package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoHEndpoints(t *testing.T) {
	got, err := dohEndpoints(" https://doh.pub/dns-query,\nhttps://dns.alidns.com/dns-query ")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("the endpoints are %v", got)
	}
	builtins, err := dohEndpoints("")
	if err != nil || len(builtins) != 2 {
		t.Fatalf("the built-in endpoints are %v, %v", builtins, err)
	}
	for _, endpoint := range builtins {
		parsed, _ := url.Parse(endpoint)
		if net.ParseIP(parsed.Hostname()) == nil || parsed.Scheme != "https" {
			t.Fatalf("the built-in endpoint %q is not an HTTPS IP address", endpoint)
		}
	}
	for _, invalid := range []string{"doh.pub/dns-query", "ftp://doh.pub/dns-query"} {
		if _, err := dohEndpoints(invalid); err == nil {
			t.Fatalf("the invalid endpoint %q was accepted", invalid)
		}
	}
}

func TestResolverNames(t *testing.T) {
	if got := resolverName("223.5.5.5"); got != "dns.alidns.com" {
		t.Fatalf("the AliDNS TLS name is %q", got)
	}
	if got := resolverName("1.12.12.12"); got != "doh.pub" {
		t.Fatalf("the DNSPod TLS name is %q", got)
	}
	if got := resolverName("192.0.2.1"); got != "192.0.2.1" {
		t.Fatalf("the custom IP TLS name is %q", got)
	}
}

func TestBuiltinDoHResolvesAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	resolver, err := newDoHResolver([]string{"https://223.5.5.5/resolve", "https://1.12.12.12/dns-query"})
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.close()
	ips, err := resolver.lookupIPs(context.Background(), "cloudflare.com")
	if err != nil || len(ips) == 0 {
		t.Fatalf("the built-in DoH addresses are %v, %v", ips, err)
	}
}

func TestIPsFromDNSMessage(t *testing.T) {
	for _, test := range []struct {
		recordType uint16
		ip         string
	}{{dnsA, "127.0.0.1"}, {dnsAAAA, "2001:db8::1"}} {
		query, id, err := dnsQuery("api.example.com", test.recordType)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ipsFromDNSMessage(dnsResponseWithIP(query, test.recordType, net.ParseIP(test.ip)), id, test.recordType)
		if err != nil || len(got) != 1 || !got[0].Equal(net.ParseIP(test.ip)) {
			t.Fatalf("the addresses are %v, %v", got, err)
		}
		if _, err := ipsFromDNSMessage(dnsResponseWithIP(query, test.recordType, net.ParseIP(test.ip)), id+1, test.recordType); err == nil {
			t.Fatal("an answer with another id was accepted")
		}
	}
}

func TestLookupUsesJSONAndWireDoH(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordType := dnsA
		var query []byte
		if r.Method == http.MethodGet {
			if r.URL.Query().Get("name") != "api.example.com" {
				http.Error(w, "the host is wanted", http.StatusBadRequest)
				return
			}
			parsed, _ := strconv.Atoi(r.URL.Query().Get("type"))
			recordType = parsed
			var id uint16
			query, id, _ = dnsQuery("api.example.com", uint16(recordType))
			binary.BigEndian.PutUint16(query[0:2], id)
		} else {
			query, _ = io.ReadAll(r.Body)
			recordType = int(binary.BigEndian.Uint16(query[len(query)-4 : len(query)-2]))
		}
		if recordType == dnsAAAA {
			_ = json.NewEncoder(w).Encode(map[string]any{"Status": 0})
			return
		}
		ip := net.ParseIP("127.0.0.1")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"Status": 0, "Answer": []map[string]any{{"type": dnsA, "data": ip.String()}}})
			return
		}
		w.Header().Set("content-type", "application/dns-message")
		_, _ = w.Write(dnsResponseWithIP(query, dnsA, ip))
	}))
	defer server.Close()
	resolver, err := newDoHResolver([]string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.close()
	ips, err := resolver.lookupIPs(context.Background(), "api.example.com")
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("the addresses are %v, %v", ips, err)
	}
}

func TestLookupUsesWireDoHWhenJSONIsRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Error(w, "wire only", http.StatusMethodNotAllowed)
			return
		}
		query, _ := io.ReadAll(r.Body)
		if r.URL.Query().Get("type") == "28" {
			_ = json.NewEncoder(w).Encode(map[string]any{"Status": 0})
			return
		}
		_, _ = w.Write(dnsResponseWithIP(query, dnsA, net.ParseIP("127.0.0.1")))
	}))
	defer server.Close()
	resolver, _ := newDoHResolver([]string{server.URL})
	defer resolver.close()
	ips, err := resolver.lookupIPs(context.Background(), "api.example.com")
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("the addresses are %v, %v", ips, err)
	}
}

func TestSidecarForwardsUsingDoHAddress(t *testing.T) {
	var upstreamHost atomic.Value
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHost.Store(r.Host)
		_, _ = w.Write([]byte(r.URL.Path))
	}))
	defer backend.Close()
	port := backend.Listener.Addr().(*net.TCPAddr).Port

	doh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") == "28" {
			_ = json.NewEncoder(w).Encode(map[string]any{"Status": 0})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Status": 0, "Answer": []map[string]any{{"type": dnsA, "data": "127.0.0.1"}}})
	}))
	defer doh.Close()
	resolver, err := newDoHResolver([]string{doh.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.close()
	u, err := newUpstream("test", "https://api.example.com:"+strconv.Itoa(port)+"/v1", resolver)
	if err != nil {
		t.Fatal(err)
	}
	defer u.transport.CloseIdleConnections()
	u.url.Scheme = "http" // The local test upstream does not need a TLS certificate.

	sc := &sidecar{ups: map[string]*upstream{"test": u}, resolver: resolver}
	proxy := httptest.NewServer(http.HandlerFunc(sc.serve))
	defer proxy.Close()
	response, err := http.Get(proxy.URL + "/test/models")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(body) != "/v1/models" {
		t.Fatalf("the upstream answered %d, %q", response.StatusCode, body)
	}
	if got := upstreamHost.Load(); got != "api.example.com:"+strconv.Itoa(port) {
		t.Fatalf("the upstream Host is %q", got)
	}
}

func TestLookupCachesAndRefreshesExpiredAnswers(t *testing.T) {
	var calls atomic.Int32
	doh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		ttl := 60
		if r.URL.Query().Get("type") == "28" {
			_ = json.NewEncoder(w).Encode(map[string]any{"Status": 0})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Status": 0, "Answer": []map[string]any{{"type": dnsA, "data": "192.0.2.1", "TTL": ttl}}})
	}))
	defer doh.Close()
	resolver, _ := newDoHResolver([]string{doh.URL})
	defer resolver.close()
	if _, err := resolver.lookupIPs(context.Background(), "api.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.lookupIPs(context.Background(), "api.example.com"); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("the cached lookup made %d resolver requests", got)
	}
	resolver.mu.Lock()
	answer := resolver.cache["api.example.com"]
	answer.expires = time.Now().Add(-time.Second)
	resolver.cache["api.example.com"] = answer
	resolver.mu.Unlock()
	if _, err := resolver.lookupIPs(context.Background(), "api.example.com"); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 4 {
		t.Fatalf("the expired lookup made %d resolver requests", got)
	}
}

func dnsResponseWithIP(query []byte, recordType uint16, ip net.IP) []byte {
	if len(query) < 12 {
		return nil
	}
	rdata := ip.To4()
	if recordType == dnsAAAA {
		rdata = ip.To16()
	}
	answer := []byte{0xc0, 0x0c}
	answer = binary.BigEndian.AppendUint16(answer, recordType)
	answer = binary.BigEndian.AppendUint16(answer, 1)
	answer = binary.BigEndian.AppendUint32(answer, 60)
	answer = binary.BigEndian.AppendUint16(answer, uint16(len(rdata)))
	answer = append(answer, rdata...)
	message := make([]byte, 12, len(query)+len(answer))
	copy(message[0:2], query[0:2])
	binary.BigEndian.PutUint16(message[2:4], 0x8180)
	binary.BigEndian.PutUint16(message[4:6], 1)
	binary.BigEndian.PutUint16(message[6:8], 1)
	message = append(message, query[12:]...)
	return append(message, answer...)
}
