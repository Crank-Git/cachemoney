package dnszone

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// errNotFound is returned when a query gets NODATA (no records for the name).
var errNotFound = &notFoundErr{}

type notFoundErr struct{}

func (*notFoundErr) Error() string { return "record not found" }

// Resolver queries an authoritative server for one zone and walks the object
// graph: it fetches a manifest, then every chunk, then reassembles and
// verifies the object. All records are fetched with plain DNS.
type Resolver struct {
	server string
	zone   Zone
	client *dns.Client
}

// NewResolver returns a resolver for server (e.g. "127.0.0.1:5300") serving
// zone. timeout overrides the default 5s per query if > 0.
func NewResolver(server string, zone Zone, timeout time.Duration) *Resolver {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &Resolver{server: server, zone: zone, client: &dns.Client{Timeout: timeout, UDPSize: 4096}}
}

// serverAddr returns the resolver's target address.
func (r *Resolver) serverAddr() string { return r.server }

// Fetch resolves the object described by m from the server, using tr for every
// record, and returns the reassembled bytes. A missing manifest or chunk
// fails loudly rather than returning truncated data.
func (r *Resolver) Fetch(m *objectstore.Manifest, tr objectstore.Transport) ([]byte, error) {
	raw, err := r.fetch(dns.Fqdn(fmt.Sprintf("%s.o.%s", m.ID(), r.zone)), tr)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest %s: %w", m.ID(), err)
	}
	// AAAA right-pads its final record with null bytes; the manifest is a
	// single payload so we trim the padding before parsing. JSON never ends
	// in a null byte, so this is safe.
	raw = bytes.TrimRight(raw, "\x00")
	check, err := objectstore.UnmarshalManifest(raw)
	if err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", m.ID(), err)
	}

	chunks := make(map[objectstore.ObjectID][]byte, len(check.ChunkIDs))
	for _, id := range check.ChunkIDs {
		name := dns.Fqdn(fmt.Sprintf("%s.c.%s", id, r.zone))
		c, err := r.fetch(name, tr)
		if err != nil {
			return nil, fmt.Errorf("fetch chunk %s: %w", id, err)
		}
		chunks[id] = c
	}
	return objectstore.Reassemble(check, chunks)
}

// exchange performs one DNS query, falling back to TCP if the UDP answer is
// truncated (which happens for large AAAA sets). UDP is preferred for latency.
func (r *Resolver) exchange(m *dns.Msg) (*dns.Msg, error) {
	resp, _, err := r.client.Exchange(m, r.server)
	if err != nil {
		// A UDP answer larger than our buffer yields dns.ErrBuf from the
		// partial unpack before the truncation bit can be inspected. Fall
		// back to TCP for the full answer, as RFC 1035 intends.
		if errors.Is(err, dns.ErrBuf) {
			return r.exchangeTCP(m)
		}
		return nil, err
	}
	if resp.Truncated {
		return r.exchangeTCP(m)
	}
	return resp, nil
}

// exchangeTCP re-issues query m over TCP. Used for answers too large for a
// single UDP datagram.
func (r *Resolver) exchangeTCP(m *dns.Msg) (*dns.Msg, error) {
	tcp := &dns.Client{Net: "tcp", Timeout: r.client.Timeout}
	resp, _, err := tcp.Exchange(m, r.server)
	if err != nil {
		return nil, fmt.Errorf("dnszone: tcp fallback failed: %w", err)
	}
	return resp, nil
}

// fetch performs one DNS exchange and decodes the answer.
func (r *Resolver) fetch(name string, tr objectstore.Transport) ([]byte, error) {
	qtype := dns.TypeTXT
	if tr == objectstore.AAAA {
		qtype = dns.TypeAAAA
	}
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = false

	resp, err := r.exchange(m)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns: rcode %s for %s", dns.RcodeToString[resp.Rcode], name)
	}
	if len(resp.Answer) == 0 {
		return nil, errNotFound
	}

	switch tr {
	case objectstore.TXT:
		var pieces []string
		for _, rr := range resp.Answer {
			t, ok := rr.(*dns.TXT)
			if !ok {
				return nil, fmt.Errorf("dnszone: expected TXT, got %T", rr)
			}
			pieces = append(pieces, t.Txt...)
		}
		return objectstore.DecodeTXT(pieces)
	case objectstore.AAAA:
		var addrs [][]byte
		for _, rr := range resp.Answer {
			a, ok := rr.(*dns.AAAA)
			if !ok {
				return nil, fmt.Errorf("dnszone: expected AAAA, got %T", rr)
			}
			addrs = append(addrs, a.AAAA)
		}
		return objectstore.DecodeAAAA(addrs)
	default:
		return nil, fmt.Errorf("dnszone: unknown transport %d", tr)
	}
}
