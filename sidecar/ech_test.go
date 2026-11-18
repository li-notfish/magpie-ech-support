package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

const testECHConfig = "AEX+DQBB0gAgACDFD85iIN6Pl/peBoQUS6kYYD6wzOeSYr/0XJMStAQwcgAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="

func TestECHValueFromPublishedRecord(t *testing.T) {
	want, _ := base64.StdEncoding.DecodeString(testECHConfig)
	for _, record := range []string{
		`1 . alpn="h3,h2" ech="` + testECHConfig + `" ipv4hint="104.18.10.118"`,
		`1 . ech=` + testECHConfig,
		`1 . alpn="h2"`,
	} {
		got, err := echValue(record)
		if err != nil {
			t.Fatal(err)
		}
		if record[len(record)-3:] == `h2"` {
			if len(got) != 0 {
				t.Fatalf("a record without ECH returned %v", got)
			}
		} else if string(got) != string(want) {
			t.Fatalf("the configuration is %v", got)
		}
	}
	if _, err := echValue(`1 . ech="not base64!"`); err == nil {
		t.Fatal("an invalid published configuration was accepted")
	}
}

func TestECHFromDNSMessage(t *testing.T) {
	query, id, err := dnsQuery("api.example.com", dnsHTTPS)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := base64.StdEncoding.DecodeString(testECHConfig)
	got, ttl, err := echFromDNSMessage(dnsResponseWithECH(query, list), id)
	if err != nil || string(got) != string(list) || ttl != time.Minute {
		t.Fatalf("the wire configuration is %v, %v, %v", got, ttl, err)
	}
	if _, _, err := echFromDNSMessage(dnsResponseWithECH(query, list), id+1); err == nil {
		t.Fatal("a response with another query id was accepted")
	}
}

func TestECHLookupJSONAndWire(t *testing.T) {
	list, _ := base64.StdEncoding.DecodeString(testECHConfig)
	for _, wire := range []bool{false, true} {
		t.Run(strconv.FormatBool(wire), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if wire && r.Method == http.MethodGet {
					http.Error(w, "wire only", http.StatusMethodNotAllowed)
					return
				}
				if wire {
					query, _ := io.ReadAll(r.Body)
					_, _ = w.Write(dnsResponseWithECH(query, list))
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"Status": 0, "Answer": []map[string]any{{
					"type": dnsHTTPS, "TTL": 300, "data": `1 . alpn="h2" ech="` + testECHConfig + `"`,
				}}})
			}))
			defer server.Close()
			resolver, _ := newDoHResolver([]string{server.URL})
			defer resolver.close()
			got, ttl, err := resolver.lookupECH(context.Background(), "api.example.com")
			if err != nil || string(got) != string(list) || ttl <= 0 {
				t.Fatalf("the configuration is %v, %v, %v", got, ttl, err)
			}
		})
	}
}

func TestECHIsNotUsedWithoutPublishedConfiguration(t *testing.T) {
	var httpsQueries atomic.Int32
	doh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") == "65" {
			httpsQueries.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"Status": 0, "Answer": []map[string]any{{"type": dnsHTTPS, "data": `1 . alpn="h2"`}}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Status": 0})
	}))
	defer doh.Close()
	resolver, _ := newDoHResolver([]string{doh.URL})
	defer resolver.close()
	if _, _, err := resolver.lookupECH(context.Background(), "api.example.com"); err == nil {
		t.Fatal("a record without ECH was accepted")
	}
	if _, _, err := resolver.lookupECH(context.Background(), "api.example.com"); err == nil {
		t.Fatal("a cached record without ECH was accepted")
	}
	if got := httpsQueries.Load(); got != 1 {
		t.Fatalf("the missing configuration was queried %d times", got)
	}
}

func TestECHWithoutConfigurationUsesOrdinaryTLS(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()
	port := backend.Listener.Addr().(*net.TCPAddr).Port
	var httpsQueries atomic.Int32
	doh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") == "65" {
			httpsQueries.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"Status": 0})
			return
		}
		if r.URL.Query().Get("type") == "1" {
			_ = json.NewEncoder(w).Encode(map[string]any{"Status": 0, "Answer": []map[string]any{{"type": dnsA, "data": "127.0.0.1"}}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Status": 0})
	}))
	defer doh.Close()
	resolver, _ := newDoHResolver([]string{doh.URL})
	defer resolver.close()
	client := newECHClient("api.example.com", resolver, &tls.Config{
		ServerName:         "api.example.com",
		InsecureSkipVerify: true, // Local test certificate.
	})
	conn, err := client.dialTLS(context.Background(), &net.Dialer{}, "tcp", "api.example.com:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	state := conn.(*tls.Conn).ConnectionState()
	conn.Close()
	if state.ECHAccepted || httpsQueries.Load() != 1 {
		t.Fatalf("ECH accepted %v, HTTPS queries %d", state.ECHAccepted, httpsQueries.Load())
	}
}

func TestPublishedECHFailureDoesNotDowngrade(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	port := backend.Listener.Addr().(*net.TCPAddr).Port
	resolver := &dohResolver{cache: map[string]addressAnswer{"api.example.com": {
		ips: []net.IP{net.ParseIP("127.0.0.1")}, expires: time.Now().Add(time.Minute),
	}}}
	client := newECHClient("api.example.com", resolver, &tls.Config{InsecureSkipVerify: true})
	client.remember([]byte{1, 2, 3, 4})
	conn, err := client.dialTLS(context.Background(), &net.Dialer{}, "tcp", "api.example.com:"+strconv.Itoa(port))
	if conn != nil {
		conn.Close()
		t.Fatal("an invalid ECH configuration was silently downgraded")
	}
	if err == nil {
		t.Fatal("an invalid ECH configuration was accepted")
	}
}

func TestECHHandshakeWithPublishedConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	resolver, err := newDoHResolver([]string{"https://223.5.5.5/resolve", "https://1.12.12.12/dns-query"})
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.close()
	client := newECHClient("cloudflare-ech.com", resolver, &tls.Config{
		ServerName: "cloudflare-ech.com",
		MinVersion: tls.VersionTLS12,
	})
	dialer := &net.Dialer{Timeout: dialTimeout}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := client.dialTLS(ctx, dialer, "tcp", "cloudflare-ech.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if !state.ECHAccepted {
		t.Fatal("the server did not accept the published ECH configuration")
	}
	if state.ServerName != "cloudflare-ech.com" {
		t.Fatalf("the inner TLS name is %q", state.ServerName)
	}
}

func dnsResponseWithECH(query, list []byte) []byte {
	rdata := []byte{0, 1, 0}
	rdata = binary.BigEndian.AppendUint16(rdata, 5)
	rdata = binary.BigEndian.AppendUint16(rdata, uint16(len(list)))
	rdata = append(rdata, list...)
	answer := []byte{0xc0, 0x0c}
	answer = binary.BigEndian.AppendUint16(answer, dnsHTTPS)
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
