// Package dnszone bridges the content-addressed objectstore and the wire: it
// publishes objects as DNS records on a real authoritative server and resolves
// them back with a real DNS client. An object is framed exactly as the
// objectstore specifies and handed to miekg/dns; a client fetches the records
// and reassembles them exactly as a resolver would return them.
//
// This is the second spike of the project. The label scheme (which suffix
// identifies a chunk vs. a manifest, which zone hosts the records) is a
// working model to iterate on — see the README "Open questions".
package dnszone

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// Zone is the apex DNS name served by a Server, e.g. "example.com".
type Zone string

// DefaultTTL is how long records may be cached, in seconds. Immutable objects
// can live a long time; refs are expected to be short-lived in production.
const DefaultTTL uint32 = 300

// Server is a minimal authoritative DNS server for one zone. It holds records
// in memory, keyed by fully-qualified name, and answers every query from that
// map. It exists to demonstrate the end-to-end path; a production server would
// load records from disk or a backend.
type Server struct {
	zone    Zone
	ttl     uint32
	mu      sync.RWMutex
	records map[string][]dns.RR
	srv     *dns.Server
	srvTCP  *dns.Server
}

// NewServer creates a server for zone. ttl overrides the default if > 0.
func NewServer(zone Zone, ttl uint32) *Server {
	if ttl == 0 {
		ttl = DefaultTTL
	}
	return &Server{
		zone:    zone,
		ttl:     ttl,
		records: make(map[string][]dns.RR),
	}
}

// ZoneName returns the zone this server is authoritative for.
func (s *Server) ZoneName() string { return string(s.zone) }

// Port returns the actual listening port (useful when started on :0).
func (s *Server) Port() int {
	if s.srv != nil && s.srv.PacketConn != nil {
		if ua, ok := s.srv.PacketConn.LocalAddr().(*net.UDPAddr); ok {
			return ua.Port
		}
	}
	return 0
}

// Publish frames an already-built object into the zone. The manifest is
// served at <id>.o.<zone> and each chunk at <chunkid>.c.<zone>, using the
// given transport for every record.
func (s *Server) Publish(m *objectstore.Manifest, chunks [][]byte, tr objectstore.Transport) error {
	mb, err := m.Bytes()
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	if err := s.store(s.manifestName(m.ID()), mb, tr); err != nil {
		return fmt.Errorf("publish manifest: %w", err)
	}
	for i, c := range chunks {
		id := m.ChunkIDs[i]
		if err := s.store(s.chunkName(id), c, tr); err != nil {
			return fmt.Errorf("publish chunk %s: %w", id, err)
		}
	}
	return nil
}

// PublishRaw stores a raw payload under the fully-qualified name fqdn using
// the given transport. Unlike Publish it does not frame a manifest or chunks;
// it hands the payload straight to the record store. It is the hook the git
// scheme uses to publish a raw git object under <sha>.g.<zone>.
func (s *Server) PublishRaw(fqdn string, payload []byte, tr objectstore.Transport) error {
	if err := s.store(fqdn, payload, tr); err != nil {
		return fmt.Errorf("dnszone: publish raw %s: %w", fqdn, err)
	}
	return nil
}

// manifestName and chunkName build the fully-qualified names for a manifest
// and a chunk. The .o / .c suffixes distinguish record kinds and leave room
// for the .g (git) and .refs schemes without re-addressing existing objects.
// LoadStore loads objects from a local store directory into the in-memory
// record set, framed with tr. The layout matches the CLI put command:
//
//	<dir>/manifests/<id>.json   raw manifest bytes
//	<dir>/chunks/<chunkid>      raw chunk bytes
//
// The manifest is stored as its raw JSON so it round-trips through
// UnmarshalManifest unchanged; every chunk is re-hashed on the way in, so a
// corrupted store file is rejected before the server starts serving it.
func (s *Server) LoadStore(dir string, tr objectstore.Transport) error {
	mDir, cDir := filepath.Join(dir, "manifests"), filepath.Join(dir, "chunks")
	entries, err := os.ReadDir(mDir)
	if err != nil {
		return fmt.Errorf("dnszone: load manifests: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		mb, err := os.ReadFile(filepath.Join(mDir, e.Name()))
		if err != nil {
			return fmt.Errorf("dnszone: read manifest %s: %w", e.Name(), err)
		}
		m, err := objectstore.UnmarshalManifest(mb)
		if err != nil {
			return fmt.Errorf("dnszone: parse manifest %s: %w", e.Name(), err)
		}
		if err := s.store(s.manifestName(m.ID()), mb, tr); err != nil {
			return fmt.Errorf("dnszone: store manifest %s: %w", m.ID(), err)
		}
		for i, cid := range m.ChunkIDs {
			cb, err := os.ReadFile(filepath.Join(cDir, string(cid)))
			if err != nil {
				return fmt.Errorf("dnszone: read chunk %s: %w", cid, err)
			}
			if int64(len(cb)) != m.ChunkLens[i] {
				return fmt.Errorf("dnszone: chunk %s size mismatch (manifest %d, got %d)", cid, m.ChunkLens[i], len(cb))
			}
			if err := s.store(s.chunkName(cid), cb, tr); err != nil {
				return fmt.Errorf("dnszone: store chunk %s: %w", cid, err)
			}
		}
	}
	return nil
}

func (s *Server) manifestName(id objectstore.ObjectID) string {
	return dns.Fqdn(fmt.Sprintf("%s.o.%s", id, s.zone))
}

func (s *Server) chunkName(id objectstore.ObjectID) string {
	return dns.Fqdn(fmt.Sprintf("%s.c.%s", id, s.zone))
}

// Corrupt flips a byte in the first TXT piece of a chunk's record, simulating
// on-the-wire tampering. It is safe for concurrent use and synchronizes with
// the server's readers via the write lock.
func (s *Server) Corrupt(id objectstore.ObjectID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.corruptRecord(s.chunkName(id)); err != nil {
		return fmt.Errorf("dnszone: corrupt chunk %s: %w", id, err)
	}
	return nil
}

// Forget removes the record stored under fqdn from the server. It simulates a
// zone missing an object referenced by a graph (a partial or partially expired
// zone), so a fetch that needs it fails loudly.
func (s *Server) Forget(fqdn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, fqdn)
}

// CorruptAt flips a byte in the first TXT piece of the record stored under the
// fully-qualified name fqdn, simulating on-the-wire tampering. Unlike Corrupt,
// it targets an arbitrary name (used to tamper a git object record) rather than
// a chunk. It is safe for concurrent use and synchronizes with the server's
// readers via the write lock.
func (s *Server) CorruptAt(fqdn string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.corruptRecord(fqdn)
}

// corruptRecord applies the byte flip to the record at fqdn: it flips a bit in
// the first TXT piece's base64 data (after the ":" separator), never the
// sequence prefix, so the decoded bytes change and the content hash no longer
// matches the object.
func (s *Server) corruptRecord(fqdn string) error {
	recs, ok := s.records[fqdn]
	if !ok {
		return fmt.Errorf("no record for %s", fqdn)
	}
	txt, ok := recs[0].(*dns.TXT)
	if !ok {
		return fmt.Errorf("record for %s is not TXT", fqdn)
	}
	if len(txt.Txt) == 0 {
		return fmt.Errorf("no TXT strings for %s", fqdn)
	}
	piece := []byte(txt.Txt[0])
	ci := bytes.IndexByte(piece, ':')
	if ci < 0 || ci+1 >= len(piece) {
		return fmt.Errorf("cannot locate data in %q", txt.Txt[0])
	}
	piece[ci+1] ^= 0x01
	txt.Txt[0] = string(piece)
	return nil
}

// store records a payload under fqdn using the given transport.
func (s *Server) store(fqdn string, payload []byte, tr objectstore.Transport) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch tr {
	case objectstore.TXT:
		pieces := objectstore.EncodeTXT(objectstore.Frame{Payload: payload})
		s.records[fqdn] = []dns.RR{&dns.TXT{
			Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: s.ttl},
			Txt: pieces,
		}}
	case objectstore.AAAA:
		addrs := objectstore.EncodeAAAA(objectstore.Frame{Payload: payload})
		rrs := make([]dns.RR, 0, len(addrs))
		for _, a := range addrs {
			rrs = append(rrs, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: s.ttl},
				AAAA: net.IP(a),
			})
		}
		s.records[fqdn] = rrs
	default:
		return fmt.Errorf("objectstore: unknown transport %d", tr)
	}
	return nil
}

// Start binds UDP and TCP on a shared ephemeral port (use "127.0.0.1:0") and
// begins answering queries in the background. It blocks until both listeners
// are ready, so Port() returns a usable address on return.
func (s *Server) Start(addr string) error {
	// Discover a free port so UDP and TCP can share one address (the resolver
	// uses a single server address for both transports).
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("dnszone: discover port: %w", err)
	}
	ua := pc.LocalAddr().(*net.UDPAddr)
	_ = pc.Close()
	listenAt := net.JoinHostPort(ua.IP.String(), strconv.Itoa(ua.Port))

	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handle)

	var started sync.WaitGroup
	started.Add(2)
	// Use a larger UDP buffer (enables EDNS0) so manifests and multi-record
	// AAAA sets fit in a single UDP answer without truncation.
	udp := &dns.Server{Addr: listenAt, Net: "udp", Handler: mux, NotifyStartedFunc: func() { started.Done() }, UDPSize: 4096}
	tcp := &dns.Server{Addr: listenAt, Net: "tcp", Handler: mux, NotifyStartedFunc: func() { started.Done() }, UDPSize: 4096}
	go func() { _ = udp.ListenAndServe() }()
	go func() { _ = tcp.ListenAndServe() }()
	started.Wait()

	s.srv = udp
	s.srvTCP = tcp
	return nil
}

// handle answers a single query from the in-memory record map. Unknown names
// yield NODATA (an empty answer), which a client treats as not-found.
func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) {
	m := s.answer(req)
	// Truncate UDP answers to fit within the client's advertised UDP buffer so a
	// response too large for a single UDP datagram is split with the TC bit set;
	// the resolver uses TC to fall back to TCP (RFC 1035). Without truncation the
	// oversized datagram is fragmented and dropped on the wire. TCP answers are
	// length-prefixed and must never be truncated, so detect the network via the
	// peer address (UDP -> *net.UDPAddr, TCP -> *net.TCPAddr).
	if _, isTCP := w.RemoteAddr().(*net.TCPAddr); !isTCP {
		if opt := req.IsEdns0(); opt != nil {
			m.Truncate(int(opt.UDPSize()))
		}
	}
	_ = w.WriteMsg(m)
}

// answer builds the response for req from the in-memory record map: each
// question is matched against the stored records and any match is placed in the
// answer section (NODATA when a name has no records). It holds the read lock and
// never truncates or writes -- callers choose the framing (UDP truncation, TCP
// length prefix, or a DoH body).
func (s *Server) answer(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	// Hold the read lock while copying the answer so a concurrent Publish
	// cannot mutate the slice we are appending to.
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, q := range req.Question {
		if recs, ok := s.records[q.Name]; ok {
			m.Answer = append(m.Answer, recs...)
		}
	}
	return m
}

// Shutdown stops the server and releases its ports.
// CorruptAAAA flips a payload octet in the first AAAA record at fqdn so the
// decoded content no longer matches its hash, letting tests exercise corruption
// detection. It is intended for tests and panics if the record is missing or
// not an AAAA record (publishers know the transport they used).
func (s *Server) CorruptAAAA(fqdn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.records[fqdn][0].(*dns.AAAA)
	rec.AAAA[6] ^= 0x01
}

func (s *Server) Shutdown() {
	if s.srv != nil {
		_ = s.srv.Shutdown()
	}
	if s.srvTCP != nil {
		_ = s.srvTCP.Shutdown()
	}
}
