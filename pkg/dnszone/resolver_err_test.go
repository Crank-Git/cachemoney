package dnszone

import (
	"strconv"
	"testing"

	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// TestExchangeConnectionRefused ensures a UDP exchange that is refused (a
// resolver pointed at a closed port) fails loudly rather than hanging, so a
// misconfigured server address is reported instead of timing out silently.
func TestExchangeConnectionRefused(t *testing.T) {
	// Port 1 is never listening, so the exchange is refused immediately.
	res := NewResolver("127.0.0.1:1", Zone("example.com"), 0)
	if _, err := res.FetchByID("missing", objectstore.TXT); err == nil {
		t.Fatal("fetch succeeded against a closed port, want error")
	}
}

// TestResolveManifestRejectsTamper ensures a manifest whose bytes no longer
// parse as JSON fails at resolveManifest rather than being used, so a
// tampered manifest is caught before any chunk is fetched.
func TestResolveManifestRejectsTamper(t *testing.T) {
	for _, tr := range []objectstore.Transport{objectstore.TXT, objectstore.AAAA} {
		tr := tr
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			srv, res, shutdown := newTestServer(t, tr)
			defer shutdown()

			data := randBytes(3000)
			m, chunks := objectstore.Build(data)
			if err := srv.Publish(m, chunks, tr); err != nil {
				t.Fatalf("publish: %v", err)
			}
			// Corrupt the manifest record so its decoded bytes are no longer
			// valid JSON. TXT records are flipped via CorruptAt; AAAA records
			// need a byte flipped in the address itself.
			fqdn := dns.Fqdn(srv.manifestName(m.ID()))
			if tr == objectstore.AAAA {
				srv.mu.Lock()
				recs := srv.records[fqdn]
				addr := recs[0].(*dns.AAAA)
				// Byte 0 is the sequence number; flip a payload byte instead.
				addr.AAAA[1] ^= 0x01
				srv.mu.Unlock()
			} else {
				if err := srv.CorruptAt(fqdn); err != nil {
					t.Fatalf("corrupt manifest: %v", err)
				}
			}

			if _, err := res.FetchByID(m.ID(), tr); err == nil {
				t.Fatal("fetch succeeded despite tampered manifest, want error")
			}
		})
	}
}

// TestWalkRejectsMissingChunk ensures a chunk absent from the server (a NODATA
// answer) fails the walk loudly rather than returning a partial object.
func TestWalkRejectsMissingChunk(t *testing.T) {
	for _, tr := range []objectstore.Transport{objectstore.TXT, objectstore.AAAA} {
		tr := tr
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			srv, res, shutdown := newTestServer(t, tr)
			defer shutdown()

			data := randBytes(3000)
			m, chunks := objectstore.Build(data)
			if err := srv.Publish(m, chunks, tr); err != nil {
				t.Fatalf("publish: %v", err)
			}
			// Remove one chunk from the server so the walk cannot fetch it.
			srv.Forget(dns.Fqdn(srv.chunkName(m.ChunkIDs[0])))

			if _, err := res.FetchByID(m.ID(), tr); err == nil {
				t.Fatal("fetch succeeded despite missing chunk, want error")
			}
		})
	}
}

// TestTransportMismatch ensures fetching a record stored under one transport
// with a different transport fails: the server returns records of the wrong
// type for the resolver's expected transport.
func TestTransportMismatch(t *testing.T) {
	data := randBytes(3000)

	// Stored as AAAA, fetched as TXT: server returns AAAA, resolver expects TXT.
	srv, res, shutdown := newTestServer(t, objectstore.AAAA)
	defer shutdown()
	m, chunks := objectstore.Build(data)
	if err := srv.Publish(m, chunks, objectstore.AAAA); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := res.FetchByID(m.ID(), objectstore.TXT); err == nil {
		t.Fatal("fetch as TXT succeeded for AAAA-stored record, want error")
	}
}

// TestTransportMismatchAAAA ensures fetching a record stored under TXT with
// the AAAA transport fails: the server returns TXT records, but the resolver
// expects AAAA. This is the mirror of TestTransportMismatch.
func TestTransportMismatchAAAA(t *testing.T) {
	data := randBytes(3000)

	srv, res, shutdown := newTestServer(t, objectstore.TXT)
	defer shutdown()
	m, chunks := objectstore.Build(data)
	if err := srv.Publish(m, chunks, objectstore.TXT); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := res.FetchByID(m.ID(), objectstore.AAAA); err == nil {
		t.Fatal("fetch as AAAA succeeded for TXT-stored record, want error")
	}
}

// TestFetchByIDUnknownTransport ensures an unknown transport value is rejected
// by the transport switch in fetch.
func TestFetchByIDUnknownTransport(t *testing.T) {
	srv, res, shutdown := newTestServer(t, objectstore.TXT)
	defer shutdown()

	data := randBytes(3000)
	m, chunks := objectstore.Build(data)
	if err := srv.Publish(m, chunks, objectstore.TXT); err != nil {
		t.Fatalf("publish: %v", err)
	}

	if _, err := res.FetchByID(m.ID(), objectstore.Transport(99)); err == nil {
		t.Fatal("fetch with unknown transport accepted, want error")
	}
}
