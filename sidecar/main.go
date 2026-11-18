// Command ech-sidecar is the DoH transport behind the magpie plugin.
//
// It forwards requests to the configured upstreams, resolving their A and
// AAAA records exclusively through DNS over HTTPS. The upstream hostname is
// retained for HTTP Host, TLS SNI, and certificate verification.
//
// Usage:
//
//	ech-sidecar -upstreams-file upstreams.json [-listen 127.0.0.1:8790]
//	           [-doh <endpoint,...>] [-ech]
//
// The upstreams file is a JSON object of names to upstream addresses:
//
//	{"nvidia": "https://api.example.com/v1"}
//
// A request for /nvidia/chat/completions goes to the "nvidia" upstream.
// The listening address is written to stdout as one JSON line, and to
// -port-file when given.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	dialTimeout      = 15 * time.Second
	handshakeTimeout = 20 * time.Second
	healthPath       = "/_ech/health"
	upstreamWait     = 2 * time.Second
)

// The built-in resolvers use IP addresses so no system DNS lookup is needed
// to reach the resolver itself. Custom resolver hostnames use the system DNS
// only to connect to that resolver, never to resolve an upstream hostname.
const defaultDoH = "https://223.5.5.5/resolve,https://1.12.12.12/dns-query"

type upstream struct {
	name string
	url  *url.URL

	transport *http.Transport
	proxy     *httputil.ReverseProxy
	ech       *echClient
}

type sidecar struct {
	mu       sync.RWMutex
	ups      map[string]*upstream
	resolver *dohResolver
	ech      bool
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8790", "address to listen on")
	upstreams := flag.String("upstreams-file", "", "file the upstreams are read from")
	doh := flag.String("doh", defaultDoH, "comma separated DoH endpoints; JSON and RFC 8484 are supported")
	ech := flag.Bool("ech", false, "use ECH only when the upstream's HTTPS record publishes a configuration")
	portFile := flag.String("port-file", "", "file the listening port is written to")
	flag.Parse()

	if *upstreams == "" {
		fail("no upstream file given: -upstreams-file <file> is required")
	}
	endpoints, err := dohEndpoints(*doh)
	if err != nil {
		fail("%v", err)
	}
	resolver, err := newDoHResolver(endpoints)
	if err != nil {
		fail("the DoH resolver cannot be started: %v", err)
	}
	defer resolver.close()

	sc := &sidecar{ups: map[string]*upstream{}, resolver: resolver, ech: *ech}
	log.Printf("the DoH endpoints are %s", strings.Join(endpoints, ", "))
	if err := sc.read(*upstreams); err != nil {
		fail("the upstreams cannot be read: %v", err)
	}
	go sc.watch(*upstreams)

	mux := http.NewServeMux()
	mux.HandleFunc(healthPath, sc.health)
	mux.HandleFunc("/", sc.serve)
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fail("cannot listen on %s: %v", *listen, err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	status := sc.status()
	status["port"] = port
	out, err := json.Marshal(status)
	if err != nil {
		fail("cannot write the status: %v", err)
	}
	fmt.Println(string(out))
	if err := os.Stdout.Sync(); err != nil {
		_ = err // A pipe cannot be synced; the line is written either way.
	}
	if *portFile != "" {
		if err := os.WriteFile(*portFile, []byte(fmt.Sprintf("%d", port)), 0o644); err != nil {
			fail("cannot write the port file %s: %v", *portFile, err)
		}
	}

	server := &http.Server{Handler: mux, ReadHeaderTimeout: 30 * time.Second}
	stopped := make(chan struct{})
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		close(stopped)
	}()
	if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fail("the server stopped: %v", err)
	}
	<-stopped
}

func (sc *sidecar) read(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return err
	}
	seen := map[string]bool{}
	for name, value := range parsed {
		address, err := upstreamOf(value)
		if err != nil {
			log.Printf("the upstream %q is not an address: %v", name, err)
			continue
		}
		seen[name] = true
		sc.mu.RLock()
		old, had := sc.ups[name]
		sc.mu.RUnlock()
		if had && old.url.String() == address {
			continue
		}
		u, err := newUpstream(name, address, sc.resolver, sc.ech)
		if err != nil {
			log.Printf("the upstream %q is not an address: %v", name, err)
			continue
		}
		sc.mu.Lock()
		sc.ups[name] = u
		sc.mu.Unlock()
		if had {
			log.Printf("the upstream %q now points at %s", name, address)
		}
	}
	sc.mu.Lock()
	for name := range sc.ups {
		if !seen[name] {
			delete(sc.ups, name)
			log.Printf("the upstream %q is gone", name)
		}
	}
	sc.mu.Unlock()
	return nil
}

func (sc *sidecar) watch(path string) {
	last := stamp(path)
	for {
		time.Sleep(upstreamWait)
		now := stamp(path)
		if now == last {
			continue
		}
		last = now
		if err := sc.read(path); err != nil {
			log.Printf("the upstreams could not be read: %v", err)
		}
	}
}

func stamp(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d:%d", fi.Size(), fi.ModTime().UnixNano())
}

func upstreamOf(raw json.RawMessage) (string, error) {
	var address string
	if err := json.Unmarshal(raw, &address); err == nil {
		return address, nil
	}
	// Older versions allowed an ECH configuration beside the URL. Only the
	// address remains relevant; the ECH setting is deliberately ignored.
	var obj struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return "", err
	}
	if obj.URL == "" {
		return "", errors.New("it names no address")
	}
	return obj.URL, nil
}

func newUpstream(name, address string, resolver *dohResolver, useECH ...bool) (*upstream, error) {
	target, err := url.Parse(address)
	if err != nil || target.Host == "" {
		return nil, fmt.Errorf("the address %q is not a URL", address)
	}
	if target.Scheme != "https" {
		return nil, fmt.Errorf("the address %q is not https", address)
	}
	if resolver == nil {
		return nil, errors.New("no DoH resolver was configured")
	}
	target.Path = strings.TrimSuffix(target.Path, "/")
	u := &upstream{name: name, url: target}
	dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	tlsConfig := &tls.Config{
		ServerName: target.Hostname(),
		MinVersion: tls.VersionTLS12,
	}
	if len(useECH) > 0 && useECH[0] && net.ParseIP(target.Hostname()) == nil {
		u.ech = newECHClient(target.Hostname(), resolver, tlsConfig)
		u.transport = &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return u.ech.dialTLS(ctx, dialer, network, addr)
			},
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: handshakeTimeout,
		}
	} else {
		u.transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return resolver.dialContext(ctx, dialer, network, addr)
			},
			ForceAttemptHTTP2:   true,
			TLSClientConfig:     tlsConfig,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: handshakeTimeout,
		}
	}
	u.proxy = &httputil.ReverseProxy{
		Director:      u.direct,
		Transport:     u.transport,
		FlushInterval: -1, // Flush SSE responses as they arrive.
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("the request to %s failed: %v", target.Host, err)
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, `{"error":{"message":%q,"type":"doh_upstream_unreachable"}}`, err.Error())
		},
	}
	return u, nil
}

func (sc *sidecar) serve(w http.ResponseWriter, r *http.Request) {
	name, rest := split(r.URL.Path)
	sc.mu.RLock()
	u := sc.ups[name]
	sc.mu.RUnlock()
	if u == nil {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `{"error":{"message":%q,"type":"doh_no_upstream"}}`, "no upstream is called "+name)
		return
	}
	r.URL.Path = rest
	r.URL.RawPath = ""
	u.proxy.ServeHTTP(w, r)
}

func split(path string) (string, string) {
	p := strings.TrimPrefix(path, "/")
	at := strings.Index(p, "/")
	if at < 0 {
		return p, "/"
	}
	return p[:at], p[at:]
}

func (sc *sidecar) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(sc.status())
}

func (sc *sidecar) status() map[string]any {
	out := map[string]any{"ok": true, "upstreams": map[string]any{}}
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	for name, u := range sc.ups {
		out["upstreams"].(map[string]any)[name] = map[string]any{"url": u.url.String(), "doh": true, "ech": u.echEnabled()}
	}
	return out
}

func (u *upstream) direct(req *http.Request) {
	req.URL.Scheme = u.url.Scheme
	req.URL.Host = u.url.Host
	req.URL.Path = joinPath(u.url.Path, req.URL.Path)
	if req.URL.RawPath != "" {
		req.URL.RawPath = joinPath(u.url.Path, req.URL.RawPath)
	}
	req.Host = u.url.Host
}

func joinPath(prefix, path string) string {
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		return path
	}
	if path == "" {
		return prefix
	}
	return prefix + "/" + strings.TrimPrefix(path, "/")
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ech-sidecar: "+format+"\n", args...)
	os.Exit(1)
}
