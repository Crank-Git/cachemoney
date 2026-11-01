package dnszone

import (
	"bytes"
	"math/rand"
	"strconv"
	"testing"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// newTestServer starts an authoritative server on an ephemeral local port and
// returns a resolver pointed at it. The caller must call shutdown.
func newTestServer(t *testing.T, tr objectstore.Transport) (*Server, *Resolver, func()) {
	t.Helper()
	srv := NewServer(Zone("example.com"), DefaultTTL)
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start server: %v", err)
	}
	res := NewResolver("127.0.0.1:"+strconv.Itoa(srv.Port()), Zone("example.com"), 0)
	return srv, res, func() { srv.Shutdown() }
}

// TestEndToEndRoundTrip walks the full object graph over real DNS for both
// transports, including a multi-chunk payload that forces the AAAA TCP
// fallback path.
func TestEndToEndRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		transport objectstore.Transport
		payload   []byte
	}{
		{"txt-small", objectstore.TXT, []byte("small object over dns txt")},
		{"txt-chunky", objectstore.TXT, randBytes(5000)},
		{"aaaa-small", objectstore.AAAA, []byte("small object over dns aaaa")},
		{"aaaa-chunky", objectstore.AAAA, randBytes(5000)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, res, shutdown := newTestServer(t, tc.transport)
			defer shutdown()

			m, chunks := objectstore.Build(tc.payload)
			if err := srv.Publish(m, chunks, tc.transport); err != nil {
				t.Fatalf("publish: %v", err)
			}

			got, err := res.Fetch(m, tc.transport)
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if !bytes.Equal(got, tc.payload) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(tc.payload))
			}
		})
	}
}

// TestEndToEndMissing ensures a missing object fails loudly over DNS.
func TestEndToEndMissing(t *testing.T) {
	srv, res, shutdown := newTestServer(t, objectstore.TXT)
	defer shutdown()

	m, _ := objectstore.Build([]byte("never published"))
	// Publish a DIFFERENT object so the server is up, then fetch our id.
	other, otherChunks := objectstore.Build([]byte("something else"))
	_ = srv.Publish(other, otherChunks, objectstore.TXT)

	if _, err := res.Fetch(m, objectstore.TXT); err == nil {
		t.Fatal("expected not-found error over DNS, got nil")
	}
}

// TestEndToEndTamper ensures a corrupted chunk is detected by the resolver's
// reassembly verification.
func TestEndToEndTamper(t *testing.T) {
	srv, res, shutdown := newTestServer(t, objectstore.TXT)
	defer shutdown()

	m, chunks := objectstore.Build(randBytes(3000))
	if err := srv.Publish(m, chunks, objectstore.TXT); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// Corrupt one chunk on the wire; the resolver must detect it via the
	// content hash during reassembly.
	if err := srv.Corrupt(m.ChunkIDs[0]); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	if _, err := res.Fetch(m, objectstore.TXT); err == nil {
		t.Fatal("expected tamper detection, got nil")
	}
}

// randBytes returns n random bytes for exercising multi-chunk paths.
func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
