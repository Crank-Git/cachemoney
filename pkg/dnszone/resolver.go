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
//
// The suffix selects the label scheme the resolver answers for: "o" for the
// content-addressed manifest scheme (<id>.o.<zone>) and "g" for the git
// scheme (<sha>.g.<zone>). A resolver is dedicated to one scheme.
type Resolver struct {
	server string
	zone   Zone
	suffix string
	client *dns.Client
}

// NewResolver returns a resolver for server (e.g. "127.0.0.1:5300") serving
// zone. timeout overrides the default 5s per query if > 0.
func NewResolver(server string, zone Zone, timeout time.Duration) *Resolver {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &Resolver{server: server, zone: zone, suffix: "o", client: &dns.Client{Timeout: timeout, UDPSize: 4096}}
}

// WithObjectSuffix returns the resolver configured to answer the given label
// scheme. Pass "g" for the git scheme (<sha>.g.<zone>); the default "o" is
// the content-addressed manifest scheme. The resolver is returned for
// chaining and is otherwise unchanged.
func (r *Resolver) WithObjectSuffix(suffix string) *Resolver {
	// Return an independent copy so the original resolver's suffix is left
	// unchanged; a caller may keep both the manifest ("o") and git ("g")
	// resolvers around at once.
	c := *r
	c.suffix = suffix
	return &c
}

// Fetch resolves the object described by m from the server, using tr for every
// record, and returns the reassembled bytes. A missing manifest or chunk
// fails loudly rather than returning truncated data. The passed-in manifest is
// only used for its id: the manifest is re-fetched and re-verified from the
// server so a caller cannot pass a manifest that disagrees with the wire.
func (r *Resolver) Fetch(m *objectstore.Manifest, tr objectstore.Transport) ([]byte, error) {
	check, err := r.resolveManifest(m.ID(), tr)
	if err != nil {
		return nil, err
	}
	return r.walk(check, tr)
}

// FetchByID resolves the manifest for id from the server, then walks its chunks
// and returns the reassembled, verified object. It is the entry point when you
// have an object id but not its manifest bytes (as the CLI fetch command does).
func (r *Resolver) FetchByID(id objectstore.ObjectID, tr objectstore.Transport) ([]byte, error) {
	check, err := r.resolveManifest(id, tr)
	if err != nil {
		return nil, err
	}
	return r.walk(check, tr)
}

// resolveManifest fetches and parses the manifest for the given id from the
// server. AAAA right-pads its final record with null bytes; the manifest is a
// single payload so we trim the padding before parsing. JSON never ends in a
// null byte, so this is safe.
func (r *Resolver) resolveManifest(id objectstore.ObjectID, tr objectstore.Transport) (*objectstore.Manifest, error) {
	raw, err := r.fetch(dns.Fqdn(fmt.Sprintf("%s.%s.%s", id, r.suffix, r.zone)), tr)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest %s: %w", id, err)
	}
	raw = bytes.TrimRight(raw, "\x00")
	m, err := objectstore.UnmarshalManifest(raw)
	if err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", id, err)
	}
	return m, nil
}

// walk fetches every chunk of m, reassembles it, and verifies every hash. A
// missing or tampered chunk fails loudly rather than returning truncated data.
func (r *Resolver) walk(m *objectstore.Manifest, tr objectstore.Transport) ([]byte, error) {
	chunks := make(map[objectstore.ObjectID][]byte, len(m.ChunkIDs))
	for _, id := range m.ChunkIDs {
		name := dns.Fqdn(fmt.Sprintf("%s.c.%s", id, r.zone))
		c, err := r.fetch(name, tr)
		if err != nil {
			return nil, fmt.Errorf("fetch chunk %s: %w", id, err)
		}
		chunks[id] = c
	}
	return objectstore.Reassemble(m, chunks)
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

// FetchRaw fetches the raw bytes stored under <id>.<suffix>.<zone> without
// interpreting them as a manifest. It is used for the git scheme, whose payload
// is a raw object rather than a cachemoney manifest, so unlike resolveManifest
// the bytes are returned verbatim (no JSON parse). AAAA right-pads its final
// record with null bytes, so that padding is trimmed before returning. id is
// the bare object id (e.g. a git SHA), not a fully-qualified name.
func (r *Resolver) FetchRaw(id string, tr objectstore.Transport) ([]byte, error) {
	raw, err := r.fetch(dns.Fqdn(fmt.Sprintf("%s.%s.%s", id, r.suffix, r.zone)), tr)
	if err != nil {
		return nil, fmt.Errorf("dnszone: fetch %s: %w", id, err)
	}
	// AAAA right-pads its final record with null bytes; trim the padding back
	// off so the returned length matches the object. This mirrors resolveManifest.
	return bytes.TrimRight(raw, "\x00"), nil
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
