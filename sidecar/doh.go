package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	dohWait    = 5 * time.Second
	maxDoHBody = 1 << 20
	minimumTTL = 30 * time.Second
)

var errJSONDoH = errors.New("the endpoint does not answer the JSON form of DoH")

type dnsAnswer struct {
	Status int `json:"Status"`
	Answer []struct {
		Type uint16 `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

type addressAnswer struct {
	ips     []net.IP
	expires time.Time
	err     error
}

type dohResolver struct {
	endpoints []string
	client    *http.Client
	transport *http.Transport

	mu       sync.Mutex
	cache    map[string]addressAnswer
	echCache map[string]echAnswer
}

func newDoHResolver(endpoints []string) (*dohResolver, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("no DoH endpoint given")
	}
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
	}
	// DoH endpoints by IP still need their public hostname in TLS SNI.
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		dialer := &net.Dialer{Timeout: dohWait, KeepAlive: 30 * time.Second}
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		config := transport.TLSClientConfig.Clone()
		if net.ParseIP(host) != nil {
			config.ServerName = resolverName(host)
		}
		tlsConn := tls.Client(conn, config)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	return &dohResolver{
		endpoints: endpoints,
		transport: transport,
		client:    &http.Client{Transport: transport, Timeout: dohWait},
		cache:     map[string]addressAnswer{},
		echCache:  map[string]echAnswer{},
	}, nil
}

func (r *dohResolver) close() {
	r.transport.CloseIdleConnections()
}

func dohEndpoints(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		value = defaultDoH
	}
	fields := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if len(fields) == 0 {
		return nil, errors.New("no DoH endpoint given")
	}
	var endpoints []string
	seen := map[string]bool{}
	for _, endpoint := range fields {
		parsed, err := url.Parse(endpoint)
		scheme := ""
		if err == nil {
			scheme = strings.ToLower(parsed.Scheme)
		}
		if err != nil || parsed.Host == "" || (scheme != "http" && scheme != "https") {
			return nil, fmt.Errorf("the DoH endpoint %q is not an HTTP URL", endpoint)
		}
		if parsed.User != nil || parsed.Fragment != "" {
			return nil, fmt.Errorf("the DoH endpoint %q has credentials or a fragment", endpoint)
		}
		parsed.Scheme = scheme
		endpoint = parsed.String()
		if !seen[endpoint] {
			seen[endpoint] = true
			endpoints = append(endpoints, endpoint)
		}
	}
	return endpoints, nil
}

// dialContext replaces only the socket address with a DoH answer. The HTTP
// transport still receives the original hostname for TLS SNI and certificates.
func (r *dohResolver) dialContext(ctx context.Context, dialer *net.Dialer, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips := []net.IP{net.ParseIP(host)}
	if ips[0] == nil {
		ips, err = r.lookupIPs(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("DoH could not resolve %s: %w", host, err)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("DoH returned no usable address for %s", host)
	}
	var last error
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

func resolverName(address string) string {
	switch address {
	case "223.5.5.5", "223.6.6.6":
		return "dns.alidns.com"
	case "1.12.12.12", "120.53.53.53":
		return "doh.pub"
	case "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001":
		return "cloudflare-dns.com"
	default:
		return address
	}
}

func (r *dohResolver) lookupIPs(ctx context.Context, host string) ([]net.IP, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	r.mu.Lock()
	cached, ok := r.cache[host]
	r.mu.Unlock()
	if ok && time.Now().Before(cached.expires) {
		return append([]net.IP(nil), cached.ips...), nil
	}

	ctx, cancel := context.WithTimeout(ctx, dohWait)
	defer cancel()
	type familyAnswer struct {
		kind uint16
		ips  []net.IP
		ttl  time.Duration
		err  error
	}
	answers := make(chan familyAnswer, 2)
	for _, kind := range []uint16{dnsA, dnsAAAA} {
		go func() {
			ips, ttl, err := r.lookupFamily(ctx, host, kind)
			answers <- familyAnswer{kind: kind, ips: ips, ttl: ttl, err: err}
		}()
	}
	var ips []net.IP
	ttl := time.Duration(0)
	var last error
	for range 2 {
		answer := <-answers
		if answer.err != nil {
			last = answer.err
			continue
		}
		ips = append(ips, answer.ips...)
		if ttl == 0 || answer.ttl < ttl {
			ttl = answer.ttl
		}
	}
	if len(ips) == 0 {
		return nil, last
	}
	if ttl <= 0 {
		ttl = minimumTTL
	}
	answer := addressAnswer{ips: append([]net.IP(nil), ips...), expires: time.Now().Add(ttl)}
	r.mu.Lock()
	r.cache[host] = answer
	r.mu.Unlock()
	return ips, nil
}

func (r *dohResolver) lookupFamily(ctx context.Context, host string, kind uint16) ([]net.IP, time.Duration, error) {
	answers := make(chan addressAnswer, len(r.endpoints))
	var wg sync.WaitGroup
	for _, endpoint := range r.endpoints {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ips, ttl, err := r.query(ctx, endpoint, host, kind)
			if err != nil {
				log.Printf("%s could not resolve type %d for %s: %v", endpoint, kind, host, err)
			}
			answers <- addressAnswer{ips: ips, expires: time.Now().Add(ttl), err: err}
		}()
	}
	go func() {
		wg.Wait()
		close(answers)
	}()
	var last error
	for answer := range answers {
		if answer.err == nil && len(answer.ips) > 0 {
			ttl := time.Until(answer.expires)
			return answer.ips, ttl, nil
		}
		last = answer.err
	}
	if last == nil {
		last = errors.New("no resolver answered")
	}
	return nil, 0, last
}

func (r *dohResolver) query(ctx context.Context, endpoint, host string, kind uint16) ([]net.IP, time.Duration, error) {
	ips, ttl, err := r.queryJSON(ctx, endpoint, host, kind)
	if err == nil {
		return ips, ttl, nil
	}
	if !errors.Is(err, errJSONDoH) {
		return nil, 0, err
	}
	ips, ttl, wireErr := r.queryWire(ctx, endpoint, host, kind)
	if wireErr != nil {
		return nil, 0, fmt.Errorf("the JSON form failed: %v; the RFC 8484 form failed: %w", err, wireErr)
	}
	return ips, ttl, nil
}

func (r *dohResolver) queryECH(ctx context.Context, endpoint, host string) ([]byte, time.Duration, error) {
	list, ttl, err := r.queryECHJSON(ctx, endpoint, host)
	if err == nil {
		return list, ttl, nil
	}
	if !errors.Is(err, errJSONDoH) {
		return nil, 0, err
	}
	list, ttl, wireErr := r.queryECHWire(ctx, endpoint, host)
	if wireErr != nil {
		return nil, 0, fmt.Errorf("the JSON form failed: %v; the RFC 8484 form failed: %w", err, wireErr)
	}
	return list, ttl, nil
}

func (r *dohResolver) queryECHJSON(ctx context.Context, endpoint, host string) ([]byte, time.Duration, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, 0, err
	}
	query := parsed.Query()
	query.Set("name", host)
	query.Set("type", strconv.Itoa(dnsHTTPS))
	parsed.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("accept", "application/dns-json")
	body, err := r.do(request)
	if err != nil {
		return nil, 0, err
	}
	var answer dnsAnswer
	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, 0, fmt.Errorf("%w: the answer is not JSON: %v", errJSONDoH, err)
	}
	if answer.Status != 0 {
		return nil, 0, fmt.Errorf("the resolver answered with DNS status %d", answer.Status)
	}
	for _, record := range answer.Answer {
		if record.Type != dnsHTTPS {
			continue
		}
		list, err := echValue(record.Data)
		if err != nil {
			return nil, 0, err
		}
		if len(list) > 0 {
			return list, time.Duration(record.TTL) * time.Second, nil
		}
	}
	return nil, 0, errors.New("the HTTPS record carries no ECH configuration")
}

func (r *dohResolver) queryECHWire(ctx context.Context, endpoint, host string) ([]byte, time.Duration, error) {
	query, id, err := dnsQuery(host, dnsHTTPS)
	if err != nil {
		return nil, 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("content-type", "application/dns-message")
	request.Header.Set("accept", "application/dns-message")
	body, err := r.do(request)
	if err != nil {
		return nil, 0, err
	}
	return echFromDNSMessage(body, id)
}

func (r *dohResolver) queryJSON(ctx context.Context, endpoint, host string, kind uint16) ([]net.IP, time.Duration, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, 0, err
	}
	query := parsed.Query()
	query.Set("name", host)
	query.Set("type", strconv.Itoa(int(kind)))
	parsed.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("accept", "application/dns-json")
	body, err := r.do(request)
	if err != nil {
		return nil, 0, err
	}
	var answer dnsAnswer
	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, 0, fmt.Errorf("%w: the answer is not JSON: %v", errJSONDoH, err)
	}
	if answer.Status != 0 {
		return nil, 0, fmt.Errorf("the resolver answered with DNS status %d", answer.Status)
	}
	var ips []net.IP
	ttl := time.Duration(0)
	for _, record := range answer.Answer {
		if record.Type != kind {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(record.Data))
		if ip == nil || (kind == dnsA && ip.To4() == nil) || (kind == dnsAAAA && ip.To4() != nil) {
			continue
		}
		ips = append(ips, ip)
		if ttl == 0 || time.Duration(record.TTL)*time.Second < ttl {
			ttl = time.Duration(record.TTL) * time.Second
		}
	}
	if len(ips) == 0 {
		return nil, 0, fmt.Errorf("the answer carries no type %d address", kind)
	}
	return ips, ttl, nil
}

func (r *dohResolver) queryWire(ctx context.Context, endpoint, host string, kind uint16) ([]net.IP, time.Duration, error) {
	query, id, err := dnsQuery(host, kind)
	if err != nil {
		return nil, 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("content-type", "application/dns-message")
	request.Header.Set("accept", "application/dns-message")
	body, err := r.do(request)
	if err != nil {
		return nil, 0, err
	}
	ips, err := ipsFromDNSMessage(body, id, kind)
	return ips, minimumTTL, err
}

func (r *dohResolver) do(request *http.Request) ([]byte, error) {
	response, err := r.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if request.Header.Get("accept") == "application/dns-json" && jsonDoHUnsupported(response.StatusCode) {
			return nil, fmt.Errorf("%w: it answered HTTP %d", errJSONDoH, response.StatusCode)
		}
		return nil, fmt.Errorf("answered HTTP %d", response.StatusCode)
	}
	value, err := io.ReadAll(io.LimitReader(response.Body, maxDoHBody+1))
	if err != nil {
		return nil, err
	}
	if len(value) > maxDoHBody {
		return nil, fmt.Errorf("the DoH answer is larger than %d bytes", maxDoHBody)
	}
	return value, nil
}

func jsonDoHUnsupported(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed,
		http.StatusNotAcceptable, http.StatusUnsupportedMediaType, http.StatusNotImplemented:
		return true
	}
	return false
}
