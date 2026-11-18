package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

type echAnswer struct {
	list    []byte
	expires time.Time
	err     error
}

type echClient struct {
	mu       sync.Mutex
	host     string
	resolver *dohResolver
	config   *tls.Config
	list     []byte
}

var (
	echQuoted = regexp.MustCompile(`(?:^|\s)ech="([^"]+)"`)
	echBare   = regexp.MustCompile(`(?:^|\s)ech=([A-Za-z0-9+/=]+)`)
)

func newECHClient(host string, resolver *dohResolver, config *tls.Config) *echClient {
	return &echClient{host: host, resolver: resolver, config: config}
}

func (u *upstream) echEnabled() bool {
	return u.ech != nil
}

// dialTLS uses ordinary TLS until this hostname actually publishes an ECH
// configuration. A failed or missing discovery never invents a configuration.
func (c *echClient) dialTLS(ctx context.Context, dialer *net.Dialer, network, addr string) (net.Conn, error) {
	list := c.configList(ctx)
	if len(list) == 0 {
		return c.handshake(ctx, dialer, network, addr, nil)
	}
	var last error
	for range 3 {
		conn, err := c.handshake(ctx, dialer, network, addr, list)
		if err == nil {
			return conn, nil
		}
		last = err
		var rejected *tls.ECHRejectionError
		if !errors.As(err, &rejected) || len(rejected.RetryConfigList) == 0 {
			return nil, fmt.Errorf("the server rejected the published ECH configuration of %s: %w", c.host, err)
		}
		list = append([]byte(nil), rejected.RetryConfigList...)
		c.remember(list)
		log.Printf("ECH for %s uses the configuration returned by the server", c.host)
	}
	return nil, last
}

func (c *echClient) handshake(ctx context.Context, dialer *net.Dialer, network, addr string, list []byte) (net.Conn, error) {
	conn, err := c.resolver.dialContext(ctx, dialer, network, addr)
	if err != nil {
		return nil, err
	}
	config := c.config.Clone()
	if len(list) > 0 {
		config.MinVersion = tls.VersionTLS13
		config.MaxVersion = tls.VersionTLS13
		config.EncryptedClientHelloConfigList = list
	}
	tlsConn := tls.Client(conn, config)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (c *echClient) configList(ctx context.Context) []byte {
	c.mu.Lock()
	list := c.list
	c.mu.Unlock()
	if len(list) > 0 {
		return list
	}
	ctx, cancel := context.WithTimeout(ctx, dohWait)
	defer cancel()
	list, _, err := c.resolver.lookupECH(ctx, c.host)
	if err != nil {
		log.Printf("ECH is unavailable for %s; using ordinary TLS: %v", c.host, err)
	} else if len(list) > 0 {
		log.Printf("ECH for %s uses the configuration published in its HTTPS record", c.host)
	}
	c.mu.Lock()
	c.list = list
	c.mu.Unlock()
	return list
}

func (c *echClient) remember(list []byte) {
	c.mu.Lock()
	c.list = append([]byte(nil), list...)
	c.mu.Unlock()
}

func (r *dohResolver) lookupECH(ctx context.Context, host string) ([]byte, time.Duration, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if net.ParseIP(host) != nil {
		return nil, 0, errors.New("an IP address has no DNS ECH configuration")
	}
	r.mu.Lock()
	cached, ok := r.echCache[host]
	r.mu.Unlock()
	if ok && time.Now().Before(cached.expires) {
		return append([]byte(nil), cached.list...), time.Until(cached.expires), cached.err
	}
	answers := make(chan echAnswer, len(r.endpoints))
	var wg sync.WaitGroup
	for _, endpoint := range r.endpoints {
		wg.Add(1)
		go func() {
			defer wg.Done()
			list, ttl, err := r.queryECH(ctx, endpoint, host)
			if err != nil {
				log.Printf("%s could not discover ECH for %s: %v", endpoint, host, err)
			}
			answers <- echAnswer{list: list, expires: time.Now().Add(ttl), err: err}
		}()
	}
	go func() {
		wg.Wait()
		close(answers)
	}()
	var last error
	var selected echAnswer
	for answer := range answers {
		if answer.err == nil && len(answer.list) > 0 {
			selected = answer
			break
		}
		last = answer.err
	}
	if len(selected.list) == 0 {
		if last == nil {
			last = errors.New("no resolver answered")
		}
		selected = echAnswer{expires: time.Now().Add(minimumTTL), err: last}
	} else if time.Until(selected.expires) <= 0 {
		selected.expires = time.Now().Add(minimumTTL)
	}
	r.mu.Lock()
	r.echCache[host] = selected
	r.mu.Unlock()
	return selected.list, time.Until(selected.expires), selected.err
}

func echValue(data string) ([]byte, error) {
	match := echQuoted.FindStringSubmatch(data)
	if match == nil {
		match = echBare.FindStringSubmatch(data)
	}
	if match == nil {
		return nil, nil
	}
	list, err := base64.StdEncoding.DecodeString(match[1])
	if err != nil {
		list, err = base64.RawStdEncoding.DecodeString(match[1])
	}
	if err != nil {
		return nil, fmt.Errorf("the published ECH configuration is not base64: %w", err)
	}
	if len(list) == 0 {
		return nil, errors.New("the published ECH configuration is empty")
	}
	return list, nil
}

func echFromDNSMessage(message []byte, id uint16) ([]byte, time.Duration, error) {
	if len(message) < 12 {
		return nil, 0, errors.New("the DNS answer is shorter than its header")
	}
	if got := uint16(message[0])<<8 | uint16(message[1]); got != id {
		return nil, 0, errors.New("the DNS answer has another query id")
	}
	flags := uint16(message[2])<<8 | uint16(message[3])
	if flags&0x8000 == 0 || flags&0x0200 != 0 || flags&0x000f != 0 {
		return nil, 0, errors.New("the DNS answer is not a complete successful response")
	}
	questions := int(message[4])<<8 | int(message[5])
	answers := int(message[6])<<8 | int(message[7])
	offset := 12
	for range questions {
		next, err := skipDNSName(message, offset)
		if err != nil {
			return nil, 0, err
		}
		if next+4 > len(message) {
			return nil, 0, errors.New("the DNS question is cut short")
		}
		offset = next + 4
	}
	for range answers {
		next, err := skipDNSName(message, offset)
		if err != nil {
			return nil, 0, err
		}
		offset = next
		if offset+10 > len(message) {
			return nil, 0, errors.New("the DNS record is cut short")
		}
		kind := uint16(message[offset])<<8 | uint16(message[offset+1])
		class := uint16(message[offset+2])<<8 | uint16(message[offset+3])
		ttl := time.Duration(uint32(message[offset+4])<<24|uint32(message[offset+5])<<16|uint32(message[offset+6])<<8|uint32(message[offset+7])) * time.Second
		size := int(message[offset+8])<<8 | int(message[offset+9])
		offset += 10
		if offset+size > len(message) {
			return nil, 0, errors.New("the DNS record is cut short")
		}
		if kind == dnsHTTPS && class == 1 {
			list := echFromSVCBRData(message, offset, offset+size)
			if len(list) > 0 {
				return append([]byte(nil), list...), ttl, nil
			}
		}
		offset += size
	}
	return nil, 0, errors.New("the HTTPS record carries no ECH configuration")
}

func echFromSVCBRData(message []byte, start, end int) []byte {
	if start+2 > end {
		return nil
	}
	offset, err := skipDNSName(message, start+2)
	if err != nil || offset > end {
		return nil
	}
	for offset < end {
		if offset+4 > end {
			return nil
		}
		key := uint16(message[offset])<<8 | uint16(message[offset+1])
		size := int(message[offset+2])<<8 | int(message[offset+3])
		offset += 4
		if offset+size > end {
			return nil
		}
		if key == 5 && size > 0 {
			return message[offset : offset+size]
		}
		offset += size
	}
	return nil
}
