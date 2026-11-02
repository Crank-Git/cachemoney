package dnszone

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// defaultConcurrency is the number of chunk fetches run in parallel while
// walking an object graph. Chunks are content-addressed, so they can be
// fetched independently and reassembled in any order.
const defaultConcurrency = 16

// errNotFound is returned when a query gets NODATA (no records for the name).
var errNotFound = &notFoundErr{}

type notFoundErr struct{}

func (*notFoundErr) Error() string { return "record not found" }

// chunkFetch is one chunk's result from a parallel walk: its id, the decoded
// bytes, and any error. Results are indexed by position so the walk can run
// concurrently yet reassemble in manifest order.
type chunkFetch struct {
	id   objectstore.ObjectID
	data []byte
	err  error
}

// Resolver queries an authoritative server for one zone and walks the object
// graph: it fetches a manifest, then every chunk, then reassembles and
// verifies the object. All records are fetched with plain DNS.
//
// The suffix selects the label scheme the resolver answers for: "o" for the
// content-addressed manifest scheme (<id>.o.<zone>) and "g" for the git
// scheme (<sha>.g.<zone>). A resolver is dedicated to one scheme.
type Resolver struct {
	server       string
	zone         Zone
	suffix       string
	net          string // "udp" (default), "tcp", "tcp-tls" (DoT), "https" (DoH)
	dohURL       string // endpoint for the "https" network
	timeout      time.Duration
	client       *dns.Client
	dohClient    *http.Client
	tlsConfig    *tls.Config
	concurrency  int
	cache        *Cache
	fallback     objectstore.Transport
	withFallback bool
}

// NewResolver returns a resolver for server (e.g. "127.0.0.1:5300") serving
// zone. timeout overrides the default 5s per query if > 0.
func NewResolver(server string, zone Zone, timeout time.Duration) *Resolver {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	r := &Resolver{
		server:      server,
		zone:        zone,
		suffix:      "o",
		net:         "udp",
		timeout:     timeout,
		concurrency: defaultConcurrency,
	}
	r.client = r.newClient()
	r.dohClient = &http.Client{Timeout: timeout}
	return r
}

// newClient builds the underlying dns.Client for the resolver's configured
// network. For UDP it advertises a 4 KB EDNS0 buffer so large answers fit in a
// single datagram; for TCP and DoT the reliable connection is used directly.
func (r *Resolver) newClient() *dns.Client {
	c := &dns.Client{Timeout: r.timeout}
	switch r.net {
	case "tcp-tls":
		c.Net = "tcp-tls"
		if r.tlsConfig != nil {
			c.TLSConfig = r.tlsConfig
		} else {
			c.TLSConfig = systemRootsTLS()
		}
	case "tcp":
		c.Net = "tcp"
	default:
		c.Net = "udp"
		c.UDPSize = 4096
	}
	return c
}

// systemRootsTLS returns a *tls.Config that verifies a peer's certificate
// against the host's trusted root certificate pool.
func systemRootsTLS() *tls.Config {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	return &tls.Config{RootCAs: roots}
}

// WithConcurrency sets the maximum number of chunk fetches to run in parallel
// while walking an object graph. A value <= 0 resets to the default. The
// resolver is returned for chaining and is otherwise unchanged.
func (r *Resolver) WithConcurrency(n int) *Resolver {
	if n <= 0 {
		n = defaultConcurrency
	}
	c := *r
	c.concurrency = n
	return &c
}

// WithCache returns the resolver with an object cache enabled. Cache lookups
// short-circuit a fetch: a reassembled, verified object is returned directly
// when its id is present and unexpired. Objects are cached for the lifetime of
// the manifest record they were fetched from. The resolver is returned for
// chaining and is otherwise unchanged.
func (r *Resolver) WithCache(c *Cache) *Resolver {
	c2 := *r
	c2.cache = c
	return &c2
}

// WithNet selects the transport network for queries: "udp" (default), "tcp",
// "tcp-tls" for DNS over TLS (see WithDoT), or "https" for DNS over HTTPS (see
// WithDoH). The resolver is returned for chaining and is otherwise unchanged.
func (r *Resolver) WithNet(net string) *Resolver {
	c := *r
	c.net = net
	c.client = c.newClient()
	return &c
}

// WithDoH configures the resolver to answer queries over DNS over HTTPS at url,
// a public endpoint such as "https://cloudflare-dns.com/dns-query". The packed
// query is POSTed as application/dns-message and the packed response is
// unpacked. HTTPS is a reliable connection, so there is no truncation or TCP
// fallback. The resolver is returned for chaining and is otherwise unchanged.
func (r *Resolver) WithDoH(url string) *Resolver {
	c := *r
	c.net = "https"
	c.dohURL = url
	c.dohClient = &http.Client{Timeout: c.timeout}
	return &c
}

// WithDoT configures the resolver to answer queries over DNS over TLS from
// host (for example "1.1.1.1" or "dns.google"), which speaks TLS on port 853.
// The host's certificate is verified against the host's root pool. The resolver
// is returned for chaining and is otherwise unchanged.
func (r *Resolver) WithDoT(host string) *Resolver {
	c := *r
	c.net = "tcp-tls"
	c.server = host
	c.tlsConfig = nil
	c.client = c.newClient()
	return &c
}

// WithDoTConfig is like WithDoT but verifies the server against a custom root
// certificate pool, for a private or corporate DoT server. The resolver is
// returned for chaining and is otherwise unchanged.
func (r *Resolver) WithDoTConfig(host string, rootCAs *x509.CertPool) *Resolver {
	c := *r
	c.net = "tcp-tls"
	c.server = host
	c.tlsConfig = &tls.Config{RootCAs: rootCAs}
	c.client = c.newClient()
	return &c
}

// WithFallbackTransport configures the resolver to fall back to tr when a query
// on its preferred transport fails -- for example when a record is stored on
// AAAA but the resolver was asked for TXT. Every fetch first tries the
// preferred transport (the tr passed to Fetch/FetchByID/FetchRaw); if that
// fails and a fallback is configured, it retries once on the fallback. A hit on
// either transport is returned, since both are content-verified. The resolver
// is returned for chaining and is otherwise unchanged.
func (r *Resolver) WithFallbackTransport(tr objectstore.Transport) *Resolver {
	c2 := *r
	c2.fallback = tr
	c2.withFallback = true
	return &c2
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
	// A cache hit short-circuits the whole fetch: neither the manifest nor any
	// chunk is fetched. The manifest is re-verified by its id on store, so a hit
	// is always the correct bytes for m.ID().
	if r.cache != nil {
		if _, obj, ok := r.cache.Get(m.ID()); ok {
			return obj, nil
		}
	}
	check, ttl, err := r.resolveManifest(m.ID(), tr)
	if err != nil {
		return nil, err
	}
	obj, err := r.walk(check, tr)
	if err != nil {
		return nil, err
	}
	r.store(check, obj, ttl)
	return obj, nil
}

// FetchByID resolves the manifest for id from the server, then walks its chunks
// and returns the reassembled, verified object. It is the entry point when you
// have an object id but not its manifest bytes (as the CLI fetch command does).
func (r *Resolver) FetchByID(id objectstore.ObjectID, tr objectstore.Transport) ([]byte, error) {
	if r.cache != nil {
		if _, obj, ok := r.cache.Get(id); ok {
			return obj, nil
		}
	}
	check, ttl, err := r.resolveManifest(id, tr)
	if err != nil {
		return nil, err
	}
	obj, err := r.walk(check, tr)
	if err != nil {
		return nil, err
	}
	r.store(check, obj, ttl)
	return obj, nil
}

// resolveManifest fetches the manifest for the given id from the server and
// verifies it: the bytes must hash to id and describe a consistent object, or
// the manifest is rejected before any chunk is fetched. The framing
// (DecodeTXT/DecodeAAAA) returns the payload exactly: the AAAA length prefix
// disambiguates the right-padding of the final record from content, so
// nothing is trimmed.
func (r *Resolver) resolveManifest(id objectstore.ObjectID, tr objectstore.Transport) (*objectstore.Manifest, uint32, error) {
	raw, ttl, err := r.fetch(dns.Fqdn(fmt.Sprintf("%s.%s.%s", id, r.suffix, r.zone)), tr)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch manifest %s: %w", id, err)
	}
	m, err := objectstore.VerifyManifest(id, raw)
	if err != nil {
		return nil, 0, fmt.Errorf("verify manifest %s: %w", id, err)
	}
	return m, ttl, nil
}

// walk fetches every chunk of m, reassembles it, and verifies every hash. A
// missing or tampered chunk fails loudly rather than returning truncated data.
func (r *Resolver) walk(m *objectstore.Manifest, tr objectstore.Transport) ([]byte, error) {
	results := make([]chunkFetch, len(m.ChunkIDs))
	// Bounded concurrency: at most concurrency chunk fetches run at once. The
	// semaphore is released when each goroutine finishes, so a graph with more
	// chunks than the limit is drained in waves.
	sem := make(chan struct{}, r.concurrency)
	var wg sync.WaitGroup
	for i, id := range m.ChunkIDs {
		name := dns.Fqdn(fmt.Sprintf("%s.c.%s", id, r.zone))
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, id objectstore.ObjectID, name string) {
			defer wg.Done()
			defer func() { <-sem }()
			data, _, err := r.fetch(name, tr)
			results[i] = chunkFetch{id: id, data: data, err: err}
		}(i, id, name)
	}
	wg.Wait()

	chunks := make(map[objectstore.ObjectID][]byte, len(results))
	for _, res := range results {
		if res.err != nil {
			return nil, fmt.Errorf("fetch chunk %s: %w", res.id, res.err)
		}
		chunks[res.id] = res.data
	}
	return objectstore.Reassemble(m, chunks)
}

// exchange performs one DNS query, falling back to TCP if the UDP answer is
// truncated (which happens for large AAAA sets). UDP is preferred for latency.
func (r *Resolver) exchange(m *dns.Msg) (*dns.Msg, error) {
	// Advertise a 4 KB UDP buffer via EDNS0 so the server can return a large
	// answer in one datagram and, when it cannot, truncate and set the TC bit
	// that drives the TCP fallback below. Without EDNS0 a query falls back to
	// the 512-byte historic limit and the oversized response fragments on the
	// wire instead of arriving with the truncation bit set.
	m.SetEdns0(4096, false)
	// DNS over HTTPS is served over a reliable HTTP connection, so it needs no
	// UDP buffer or truncation handling: the packed query is POSTed and the
	// packed response is unpacked in exchangeDoH.
	if r.net == "https" {
		return r.exchangeDoH(m)
	}
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

// exchangeDoH resolves m over DNS over HTTPS: it POSTs the packed query to the
// configured endpoint and unpacks the packed response. HTTPS is a reliable
// connection, so there is no truncation or TCP fallback.
func (r *Resolver) exchangeDoH(m *dns.Msg) (*dns.Msg, error) {
	wire, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("dnszone: pack doh query: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.dohURL, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("dnszone: build doh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := r.dohClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dnszone: doh request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dnszone: doh endpoint returned %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("dnszone: read doh response: %w", err)
	}
	var out dns.Msg
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("dnszone: unpack doh response: %w", err)
	}
	return &out, nil
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
// the bytes are returned verbatim (no JSON parse). The framing returns the
// payload exactly, so content that ends in a null byte is preserved. id is the
// bare object id (e.g. a git SHA), not a fully-qualified name.
func (r *Resolver) FetchRaw(id string, tr objectstore.Transport) ([]byte, error) {
	raw, _, err := r.fetch(dns.Fqdn(fmt.Sprintf("%s.%s.%s", id, r.suffix, r.zone)), tr)
	if err != nil {
		return nil, fmt.Errorf("dnszone: fetch %s: %w", id, err)
	}
	return raw, nil
}

// store records obj in the resolver's cache, if one is configured, for the
// lifetime given by ttl (seconds). A zero ttl -- a record that says "do not
// cache" -- is left uncacheable. The manifest id is the cache key: every fetch
// of that id reassembles the same bytes.
func (r *Resolver) store(manifest *objectstore.Manifest, obj []byte, ttl uint32) {
	if r.cache == nil {
		return
	}
	r.cache.Put(manifest, obj, time.Duration(ttl)*time.Second)
}

// fetch performs one DNS exchange and decodes the answer. It also returns the
// TTL, in seconds, of the first answer record: the caller caches the object for
// that lifetime. A TTL of zero means the record must not be cached.
//
// If a fallback transport is configured, fetch first tries the preferred tr and
// only falls back to the other transport when that fails -- so a record stored
// on AAAA can still be resolved by a resolver asked for TXT, and vice versa. If
// both fail, the preferred transport's error is returned.
func (r *Resolver) fetch(name string, tr objectstore.Transport) ([]byte, uint32, error) {
	data, ttl, err := r.fetchOnce(name, tr)
	if err != nil && r.withFallback && r.fallback != tr {
		if fdata, fttl, ferr := r.fetchOnce(name, r.fallback); ferr == nil {
			return fdata, fttl, nil
		}
	}
	return data, ttl, err
}

// fetchOnce performs one DNS exchange on tr and decodes the answer. It returns
// the decoded payload and the TTL, in seconds, of the first answer record. See
// fetch for the fallback semantics.
func (r *Resolver) fetchOnce(name string, tr objectstore.Transport) ([]byte, uint32, error) {
	qtype := dns.TypeTXT
	if tr == objectstore.AAAA {
		qtype = dns.TypeAAAA
	}
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = false

	resp, err := r.exchange(m)
	if err != nil {
		return nil, 0, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, 0, fmt.Errorf("dns: rcode %s for %s", dns.RcodeToString[resp.Rcode], name)
	}
	if len(resp.Answer) == 0 {
		return nil, 0, errNotFound
	}
	ttl := resp.Answer[0].Header().Ttl

	switch tr {
	case objectstore.TXT:
		var pieces []string
		for _, rr := range resp.Answer {
			t, ok := rr.(*dns.TXT)
			if !ok {
				return nil, 0, fmt.Errorf("dnszone: expected TXT, got %T", rr)
			}
			pieces = append(pieces, t.Txt...)
		}
		data, err := objectstore.DecodeTXT(pieces)
		if err != nil {
			return nil, 0, err
		}
		return data, ttl, nil
	case objectstore.AAAA:
		var addrs [][]byte
		for _, rr := range resp.Answer {
			a, ok := rr.(*dns.AAAA)
			if !ok {
				return nil, 0, fmt.Errorf("dnszone: expected AAAA, got %T", rr)
			}
			addrs = append(addrs, a.AAAA)
		}
		data, err := objectstore.DecodeAAAA(addrs)
		if err != nil {
			return nil, 0, err
		}
		return data, ttl, nil
	default:
		return nil, 0, fmt.Errorf("dnszone: unknown transport %d", tr)
	}
}
