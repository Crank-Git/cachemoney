package dnszone

import (
	"bytes"
	"testing"

	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// TestFallbackTransportAAAAToTXT ensures a resolver asked for TXT can still
// resolve a record stored on AAAA when a fallback is configured: the TXT query
// yields the wrong type, the resolver falls back to AAAA, and the object is
// returned. This is the primary use case -- a zone served on both transports
// with the client preferring one.
func TestFallbackTransportAAAAToTXT(t *testing.T) {
	data := randBytes(3000)

	// Stored as AAAA, resolver prefers TXT with AAAA as fallback.
	srv, res, shutdown := newTestServer(t, objectstore.AAAA)
	defer shutdown()
	res = res.WithFallbackTransport(objectstore.AAAA)

	m, chunks := objectstore.Build(data)
	if err := srv.Publish(m, chunks, objectstore.AAAA); err != nil {
		t.Fatalf("publish: %v", err)
	}
	got, err := res.FetchByID(m.ID(), objectstore.TXT)
	if err != nil {
		t.Fatalf("fetch with fallback failed: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("fallback returned wrong bytes")
	}
}

// TestFallbackTransportTXTtoAAAA is the mirror of TestFallbackTransportAAAAToTXT:
// a resolver asked for AAAA resolves a TXT-stored record via the TXT fallback.
func TestFallbackTransportTXTtoAAAA(t *testing.T) {
	data := randBytes(3000)

	srv, res, shutdown := newTestServer(t, objectstore.TXT)
	defer shutdown()
	res = res.WithFallbackTransport(objectstore.TXT)

	m, chunks := objectstore.Build(data)
	if err := srv.Publish(m, chunks, objectstore.TXT); err != nil {
		t.Fatalf("publish: %v", err)
	}
	got, err := res.FetchByID(m.ID(), objectstore.AAAA)
	if err != nil {
		t.Fatalf("fetch with fallback failed: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("fallback returned wrong bytes")
	}
}

// TestFallbackStillFailsOnMissing ensures a fallback does not hide a genuinely
// missing object: when the record exists on neither transport the fetch fails
// with the preferred transport's error.
func TestFallbackStillFailsOnMissing(t *testing.T) {
	srv, res, shutdown := newTestServer(t, objectstore.AAAA)
	defer shutdown()
	res = res.WithFallbackTransport(objectstore.AAAA)

	m, chunks := objectstore.Build(randBytes(3000))
	if err := srv.Publish(m, chunks, objectstore.AAAA); err != nil {
		t.Fatalf("publish: %v", err)
	}
	// Remove the manifest so it exists on neither transport.
	srv.Forget(dns.Fqdn(srv.manifestName(m.ID())))

	if _, err := res.FetchByID(m.ID(), objectstore.TXT); err == nil {
		t.Fatal("fetch succeeded for a missing object, want error")
	}
}

// TestFallbackDisabledByDefault ensures the fallback only activates when
// explicitly configured: without it, the transport mismatch is a hard error.
func TestFallbackDisabledByDefault(t *testing.T) {
	data := randBytes(3000)

	srv, res, shutdown := newTestServer(t, objectstore.AAAA)
	defer shutdown()
	// No WithFallbackTransport call here.

	m, chunks := objectstore.Build(data)
	if err := srv.Publish(m, chunks, objectstore.AAAA); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := res.FetchByID(m.ID(), objectstore.TXT); err == nil {
		t.Fatal("fetch without fallback succeeded for a transport mismatch, want error")
	}
}
