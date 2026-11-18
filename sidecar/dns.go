package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	dnsA     = 1
	dnsAAAA  = 28
	dnsHTTPS = 65
)

func dnsQuery(host string, recordType uint16) ([]byte, uint16, error) {
	name, err := dnsName(host)
	if err != nil {
		return nil, 0, err
	}
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, 0, fmt.Errorf("the DNS query id cannot be made: %w", err)
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	message := make([]byte, 12, 12+len(name)+4)
	binary.BigEndian.PutUint16(message[0:2], id)
	binary.BigEndian.PutUint16(message[2:4], 0x0100)
	binary.BigEndian.PutUint16(message[4:6], 1)
	message = append(message, name...)
	message = binary.BigEndian.AppendUint16(message, recordType)
	message = binary.BigEndian.AppendUint16(message, 1)
	return message, id, nil
}

func dnsName(host string) ([]byte, error) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" || len(host) > 253 {
		return nil, fmt.Errorf("the host %q is not a valid DNS name", host)
	}
	name := make([]byte, 0, len(host)+2)
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("the host %q is not a valid DNS name", host)
		}
		for i := 0; i < len(label); i++ {
			if label[i] == 0 || label[i] >= 0x80 {
				return nil, fmt.Errorf("the host %q is not an ASCII DNS name", host)
			}
		}
		name = append(name, byte(len(label)))
		name = append(name, label...)
	}
	return append(name, 0), nil
}

// ipsFromDNSMessage reads all A or AAAA answers, following no CNAME itself:
// recursive DoH resolvers include the address records in the same answer.
func ipsFromDNSMessage(message []byte, id uint16, recordType uint16) ([]net.IP, error) {
	if len(message) < 12 {
		return nil, errors.New("the DNS answer is shorter than its header")
	}
	if got := binary.BigEndian.Uint16(message[0:2]); got != id {
		return nil, fmt.Errorf("the DNS answer has id %d, not %d", got, id)
	}
	flags := binary.BigEndian.Uint16(message[2:4])
	if flags&0x8000 == 0 {
		return nil, errors.New("the DNS message is a query, not an answer")
	}
	if flags&0x0200 != 0 {
		return nil, errors.New("the DNS answer is truncated")
	}
	if code := flags & 0x000f; code != 0 {
		return nil, fmt.Errorf("the resolver answered with DNS status %d", code)
	}
	questions := int(binary.BigEndian.Uint16(message[4:6]))
	answers := int(binary.BigEndian.Uint16(message[6:8]))
	offset := 12
	for i := 0; i < questions; i++ {
		next, err := skipDNSName(message, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		if offset+4 > len(message) {
			return nil, errors.New("the DNS question is cut short")
		}
		offset += 4
	}
	var ips []net.IP
	for i := 0; i < answers; i++ {
		next, err := skipDNSName(message, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		if offset+10 > len(message) {
			return nil, errors.New("the DNS answer is cut short")
		}
		kind := binary.BigEndian.Uint16(message[offset : offset+2])
		class := binary.BigEndian.Uint16(message[offset+2 : offset+4])
		size := int(binary.BigEndian.Uint16(message[offset+8 : offset+10]))
		offset += 10
		if offset+size > len(message) {
			return nil, errors.New("the DNS record is cut short")
		}
		if kind == recordType && class == 1 && ((kind == dnsA && size == 4) || (kind == dnsAAAA && size == 16)) {
			ips = append(ips, append(net.IP(nil), message[offset:offset+size]...))
		}
		offset += size
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("the DNS answer carries no type %d address", recordType)
	}
	return ips, nil
}

func skipDNSName(message []byte, offset int) (int, error) {
	for {
		if offset >= len(message) {
			return 0, errors.New("the DNS name is cut short")
		}
		length := message[offset]
		switch {
		case length == 0:
			return offset + 1, nil
		case length&0xc0 == 0xc0:
			if offset+1 >= len(message) {
				return 0, errors.New("the compressed DNS name is cut short")
			}
			return offset + 2, nil
		case length&0xc0 != 0:
			return 0, errors.New("the DNS name has an unknown label type")
		}
		offset += 1 + int(length)
		if offset > len(message) {
			return 0, errors.New("the DNS name is cut short")
		}
	}
}
