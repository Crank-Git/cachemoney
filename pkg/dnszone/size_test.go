package dnszone

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// TestEveryAnswerFits1232 publishes objects from empty to 2 MB, plus raw
// (git/mirror-style) objects, then queries every record the server holds over
// UDP with a 1232-byte EDNS buffer. No answer may be truncated or exceed 1232
// bytes on the wire. Before records were bounded, a single 1 KB chunk was
// 1548 bytes over TXT and large manifests or raw objects did not fit in a
// DNS message at all.
func TestEveryAnswerFits1232(t *testing.T) {
	for _, tr := range bothTransports {
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			srv, _, shutdown := newTestServer(t, tr)
			defer shutdown()
			for _, n := range []int{0, 1, 511, 512, 513, 4096, 100_000, 2 << 20} {
				m, chunks := objectstore.Build(randBytes(n))
				if err := srv.Publish(m, chunks, tr); err != nil {
					t.Fatalf("publish %d bytes: %v", n, err)
				}
			}
			for i, n := range []int{0, 600, 300_000} {
				name := dns.Fqdn(strings.Repeat(strconv.Itoa(i), 40) + ".g.example.com")
				if err := srv.PublishRaw(name, randBytes(n), tr); err != nil {
					t.Fatalf("publish raw %d bytes: %v", n, err)
				}
			}

			qtype := dns.TypeTXT
			if tr == objectstore.AAAA {
				qtype = dns.TypeAAAA
			}
			srv.mu.RLock()
			names := make([]string, 0, len(srv.records))
			for name := range srv.records {
				names = append(names, name)
			}
			srv.mu.RUnlock()
			addr := "127.0.0.1:" + strconv.Itoa(srv.Port())
			largest := 0
			for _, name := range names {
				q := new(dns.Msg)
				q.SetQuestion(name, qtype)
				q.SetEdns0(ednsUDPSize, false)
				wire := rawAnswer(t, "udp", addr, q)
				var resp dns.Msg
				if err := resp.Unpack(wire); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if resp.Truncated {
					t.Fatalf("%s: answer truncated at %d bytes", name, ednsUDPSize)
				}
				if len(wire) > ednsUDPSize {
					t.Fatalf("%s: answer is %d bytes, over %d", name, len(wire), ednsUDPSize)
				}
				if len(wire) > largest {
					largest = len(wire)
				}
			}
			t.Logf("%d records, largest answer %d bytes", len(names), largest)
		})
	}
}

// stopTCP shuts down the server's TCP listener so every query must succeed
// over UDP alone.
func stopTCP(t *testing.T, srv *Server) {
	t.Helper()
	if err := srv.srvTCP.Shutdown(); err != nil {
		t.Fatal(err)
	}
	srv.srvTCP = nil
}

// TestLargeObjectsOverUDPOnly round-trips multi-megabyte objects with the TCP
// listener shut down. Before this change a 2 MB object's manifest exceeded
// the 64 KB DNS message limit on both transports, and over AAAA anything over
// ~3.8 KB per record wrapped the sequence byte.
func TestLargeObjectsOverUDPOnly(t *testing.T) {
	for _, tr := range bothTransports {
		for _, n := range []int{100_000, 2 << 20, 5 << 20} {
			t.Run("transport="+strconv.Itoa(int(tr))+"/bytes="+strconv.Itoa(n), func(t *testing.T) {
				srv, res, shutdown := newTestServer(t, tr)
				defer shutdown()
				data := randBytes(n)
				m, chunks := objectstore.Build(data)
				if err := srv.Publish(m, chunks, tr); err != nil {
					t.Fatal(err)
				}
				stopTCP(t, srv)
				res = NewResolver("127.0.0.1:"+strconv.Itoa(srv.Port()), Zone("example.com"), 2*time.Second).WithConcurrency(32)
				got, err := res.FetchByID(m.ID(), tr)
				if err != nil {
					t.Fatalf("FetchByID: %v", err)
				}
				if !bytes.Equal(got, data) {
					t.Fatal("round-trip mismatch")
				}
			})
		}
	}
}

// TestFetchRawLargeObject round-trips raw (git/mirror-scheme) objects well
// past the old limits: over TXT a 100 KB raw record timed out, over AAAA a
// 5 KB one came back corrupted.
func TestFetchRawLargeObject(t *testing.T) {
	for _, tr := range bothTransports {
		for _, n := range []int{5_000, 100_000, 1 << 20} {
			t.Run("transport="+strconv.Itoa(int(tr))+"/bytes="+strconv.Itoa(n), func(t *testing.T) {
				srv, res, shutdown := newTestServer(t, tr)
				defer shutdown()
				data := randBytes(n)
				if err := srv.PublishRaw(dns.Fqdn("big.g.example.com"), data, tr); err != nil {
					t.Fatal(err)
				}
				got, err := res.WithObjectSuffix("g").FetchRaw("big", tr)
				if err != nil {
					t.Fatalf("FetchRaw: %v", err)
				}
				if !bytes.Equal(got, data) {
					t.Fatal("round-trip mismatch")
				}
			})
		}
	}
}

// TestStoreRejectsOversizePayload checks the server refuses a record payload
// over the limit rather than serving an answer that cannot fit.
func TestStoreRejectsOversizePayload(t *testing.T) {
	srv := NewServer(Zone("example.com"), 0)
	for _, tr := range bothTransports {
		if err := srv.store("x.c.example.com.", make([]byte, objectstore.MaxRecordPayload), tr); err != nil {
			t.Fatalf("payload at the limit rejected: %v", err)
		}
		if err := srv.store("x.c.example.com.", make([]byte, objectstore.MaxRecordPayload+1), tr); err == nil {
			t.Fatal("payload over the limit accepted")
		}
	}
}

// publishIndirectChain stores mb at name wrapped in exactly levels indirect
// manifests, regardless of size, and returns nothing; chunks go under .c.
func publishIndirectChain(t *testing.T, srv *Server, name string, mb []byte, levels int, tr objectstore.Transport) {
	t.Helper()
	for i := 0; i < levels; i++ {
		m, chunks := objectstore.Build(mb)
		m.Indirect = true
		for j, c := range chunks {
			if err := srv.store(srv.chunkName(m.ChunkIDs[j]), c, tr); err != nil {
				t.Fatal(err)
			}
		}
		var err error
		if mb, err = m.Bytes(); err != nil {
			t.Fatal(err)
		}
	}
	if err := srv.store(name, mb, tr); err != nil {
		t.Fatal(err)
	}
}

// TestIndirectionDepthLimit checks the resolver follows exactly
// MaxIndirection levels and refuses one more, so a hostile server cannot make
// a client chase an unbounded chain.
func TestIndirectionDepthLimit(t *testing.T) {
	for _, tr := range bothTransports {
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			srv, res, shutdown := newTestServer(t, tr)
			defer shutdown()
			data := []byte("deeply wrapped")
			m, chunks := objectstore.Build(data)
			for i, c := range chunks {
				if err := srv.store(srv.chunkName(m.ChunkIDs[i]), c, tr); err != nil {
					t.Fatal(err)
				}
			}
			mb, _ := m.Bytes()

			publishIndirectChain(t, srv, srv.manifestName(m.ID()), mb, objectstore.MaxIndirection, tr)
			got, err := res.FetchByID(m.ID(), tr)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("%d levels: got %q, %v", objectstore.MaxIndirection, got, err)
			}

			publishIndirectChain(t, srv, srv.manifestName(m.ID()), mb, objectstore.MaxIndirection+1, tr)
			if _, err := res.FetchByID(m.ID(), tr); err == nil || !strings.Contains(err.Error(), "levels") {
				t.Fatalf("%d levels: err=%v, want depth limit", objectstore.MaxIndirection+1, err)
			}
		})
	}
}

// TestFetchRejectsForgedIndirectManifest plants an indirect manifest under a
// real object's id whose chain leads to an attacker's (valid, published)
// object. Every chunk on the way hashes correctly, so only the final check
// against the requested id can catch it.
func TestFetchRejectsForgedIndirectManifest(t *testing.T) {
	for _, tr := range bothTransports {
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			srv, res, shutdown := newTestServer(t, tr)
			defer shutdown()
			real, realChunks := objectstore.Build(randBytes(100_000))
			if err := srv.Publish(real, realChunks, tr); err != nil {
				t.Fatal(err)
			}
			evilData := randBytes(100_000)
			evil, evilChunks := objectstore.Build(evilData)
			if err := srv.Publish(evil, evilChunks, tr); err != nil {
				t.Fatal(err)
			}
			evilBytes, _ := evil.Bytes()
			publishIndirectChain(t, srv, srv.manifestName(real.ID()), evilBytes, 2, tr)

			if got, err := res.FetchByID(real.ID(), tr); err == nil {
				t.Fatalf("FetchByID returned %d bytes for a forged chain", len(got))
			} else if !strings.Contains(err.Error(), "hash mismatch") {
				t.Fatalf("err=%v, want hash mismatch", err)
			}
			// The attacker object itself still resolves under its own id.
			got, err := res.FetchByID(evil.ID(), tr)
			if err != nil || !bytes.Equal(got, evilData) {
				t.Fatalf("FetchByID(evil): %v", err)
			}
		})
	}
}

// TestLargeManifestIsIndirect checks a large object's manifest record holds
// an indirect manifest, and a small object's does not.
func TestLargeManifestIsIndirect(t *testing.T) {
	srv, res, shutdown := newTestServer(t, objectstore.TXT)
	defer shutdown()
	for _, tc := range []struct {
		n        int
		indirect bool
	}{{100, false}, {200_000, true}} {
		m, chunks := objectstore.Build(randBytes(tc.n))
		if err := srv.Publish(m, chunks, objectstore.TXT); err != nil {
			t.Fatal(err)
		}
		raw, _, err := res.fetch(srv.manifestName(m.ID()), objectstore.TXT)
		if err != nil {
			t.Fatal(err)
		}
		outer, err := objectstore.UnmarshalManifest(raw)
		if err != nil {
			t.Fatal(err)
		}
		if outer.Indirect != tc.indirect {
			t.Fatalf("%d-byte object: record indirect=%v, want %v", tc.n, outer.Indirect, tc.indirect)
		}
	}
}

// TestPublishRawTTL checks only the named record gets the given TTL: the
// payload's chunks and inner manifests are content-addressed and keep the
// server's TTL. Has reports the record.
func TestPublishRawTTL(t *testing.T) {
	srv, _, shutdown := newTestServer(t, objectstore.TXT)
	defer shutdown()
	name := dns.Fqdn("repo.refs.example.com")
	if srv.Has(name) {
		t.Fatal("Has before publish")
	}
	if err := srv.PublishRawTTL(name, randBytes(200_000), objectstore.TXT, 60); err != nil {
		t.Fatal(err)
	}
	if !srv.Has(name) || !srv.Has(strings.ToUpper(name)) {
		t.Fatal("Has after publish")
	}
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	short := 0
	for key, rrs := range srv.records {
		ttl := rrs[0].Header().Ttl
		switch {
		case key == nameKey(name):
			if ttl != 60 {
				t.Fatalf("named record TTL %d, want 60", ttl)
			}
			short++
		case ttl != DefaultTTL:
			t.Fatalf("%s has TTL %d, want %d", key, ttl, DefaultTTL)
		}
	}
	if short != 1 || len(srv.records) < 400 {
		t.Fatalf("%d short-TTL records among %d", short, len(srv.records))
	}
}
