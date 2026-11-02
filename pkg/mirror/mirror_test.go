package mirror

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/dnszone"
	"github.com/Crank-Git/cachemoney/pkg/objectstore"
	"github.com/Crank-Git/cachemoney/pkg/pkgindex"
)

// Reference sha256 values, checked against `sha256sum` on the host (see
// pkg/pkgindex for the same constants).
const (
	shaHello  = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
	shaFox    = "1153a4080f1fcb04425aa0b841c2b14606fe6df25d9076d2a1face2d5af57129"
	shaEmpty  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	helloText = "hello\n"
	foxText   = "the quick brown fox jumps over the lazy dog\n"
)

// testIndex returns a canonical index over three files plus the matching file
// bytes, keyed by path.
func testIndex() (*pkgindex.Index, map[string][]byte) {
	files := map[string][]byte{
		"/alpha": []byte(helloText),
		"/empty": []byte{},
		"/zeta":  []byte(foxText),
	}
	idx := pkgindex.NewIndex([]pkgindex.Entry{
		{Path: "/zeta", Mode: "100644", Size: len(foxText), SHA256: shaFox},
		{Path: "/alpha", Mode: "100644", Size: len(helloText), SHA256: shaHello},
		{Path: "/empty", Mode: "100644", Size: 0, SHA256: shaEmpty},
	})
	return idx, files
}

// startServer returns a server and a mirror-scheme resolver pointed at it.
func startServer(t *testing.T) (*dnszone.Server, *dnszone.Resolver, func()) {
	t.Helper()
	srv := dnszone.NewServer(dnszone.Zone("example.com"), 0)
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start server: %v", err)
	}
	rr := dnszone.NewResolver("127.0.0.1:"+strconv.Itoa(srv.Port()), dnszone.Zone("example.com"), 0).WithObjectSuffix("f")
	return srv, rr, srv.Shutdown
}

// TestRoundTrip publishes an index and its files, then fetches each file by
// path and checks the bytes come back exactly.
func TestRoundTrip(t *testing.T) {
	for _, tr := range []objectstore.Transport{objectstore.TXT, objectstore.AAAA} {
		tr := tr
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			idx, files := testIndex()
			srv, rr, shutdown := startServer(t)
			defer shutdown()

			indexLabel, err := Publish(srv, idx, files, tr)
			if err != nil {
				t.Fatalf("publish: %v", err)
			}

			for path, want := range files {
				got, err := Fetch(rr, indexLabel, path, tr)
				if err != nil {
					t.Fatalf("fetch %s: %v", path, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("fetch %s: got %q, want %q", path, got, want)
				}
			}
		})
	}
}

// TestFetchMissingIndex ensures a wrong index hash fails loudly.
func TestFetchMissingIndex(t *testing.T) {
	idx, files := testIndex()
	srv, rr, shutdown := startServer(t)
	defer shutdown()
	if _, err := Publish(srv, idx, files, objectstore.TXT); err != nil {
		t.Fatalf("publish: %v", err)
	}

	if _, err := Fetch(rr, "0000", "/alpha", objectstore.TXT); err == nil {
		t.Fatal("fetch succeeded with bogus index label, want error")
	}
}

// TestFetchUnknownPath ensures a path absent from the index fails loudly.
func TestFetchUnknownPath(t *testing.T) {
	idx, files := testIndex()
	srv, rr, shutdown := startServer(t)
	defer shutdown()
	if _, err := Publish(srv, idx, files, objectstore.TXT); err != nil {
		t.Fatalf("publish: %v", err)
	}

	if _, err := Fetch(rr, idx.Label(), "/missing", objectstore.TXT); err == nil {
		t.Fatal("fetch succeeded for unknown path, want error")
	}
}

// TestFetchDetectsTamper ensures a tampered index is caught: the index is
// content-addressed, so a flipped byte makes its hash no longer match the
// requested label. Exercised over TXT via Server.CorruptAt.
func TestFetchDetectsTamper(t *testing.T) {
	idx, files := testIndex()
	srv, rr, shutdown := startServer(t)
	defer shutdown()
	if _, err := Publish(srv, idx, files, objectstore.TXT); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := srv.CorruptAt(dns.Fqdn(idx.Label() + ".f.example.com")); err != nil {
		t.Fatalf("corrupt index: %v", err)
	}

	if _, err := Fetch(rr, idx.Label(), "/alpha", objectstore.TXT); err == nil {
		t.Fatal("fetch succeeded despite tampered index, want error")
	}
}

// TestFetchDetectsTamperedFile ensures a file whose bytes no longer hash to the
// index's recorded sha256 is rejected by Verify rather than returned, so a
// tampered file on the server is caught after the index validates but before
// the file is used. Corrupting a file (not the index) is what distinguishes it
// from TestFetchDetectsTamper, which targets the index hash check. Over AAAA a
// flipped octet changes content without breaking decoding, which is what lands
// the corruption at Verify rather than at the transport layer (TXT would fail
// base64 decoding first).
func TestFetchDetectsTamperedFile(t *testing.T) {
	// 43-byte content frames into several AAAA records (frame = 47 bytes /
	// 15 bytes per record = 4 records), so a payload octet can be flipped
	// without touching the 4-byte length prefix.
	content := []byte("the quick brown fox jumps over the lazy dog")
	sum := sha256.Sum256(content)
	files := map[string][]byte{"/big": content}
	idx := pkgindex.NewIndex([]pkgindex.Entry{
		{Path: "/big", Mode: "100644", Size: len(content), SHA256: hex.EncodeToString(sum[:])},
	})

	srv, rr, shutdown := startServer(t)
	defer shutdown()

	indexLabel, err := Publish(srv, idx, files, objectstore.AAAA)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	entry, err := idx.Lookup("/big")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	label, err := entry.Label()
	if err != nil {
		t.Fatalf("label: %v", err)
	}
	fqdn := dns.Fqdn(label + ".f.example.com")
	// Flip a payload octet on the first record: the 4-byte length prefix lives
	// at octets 1-4 and the sequence byte at 0, so octet 6 is pure payload.
	// The frame still decodes to the right length, but the content no longer
	// hashes to the index, which is what lands the failure at Verify.
	srv.CorruptAAAA(fqdn)
	if _, err := Fetch(rr, indexLabel, "/big", objectstore.AAAA); err == nil {
		t.Fatal("fetch succeeded despite tampered file, want verify error")
	}
}

// TestFetchNullTerminatedFile ensures a file whose content ends in a null byte
// round-trips over AAAA. AAAA right-pads its final record with null bytes, which
// is ambiguous with content that legitimately ends in a null byte; the framing's
// length prefix is what disambiguates it. TXT is unaffected, so AAAA is the
// transport that would silently corrupt such a file without the fix.
func TestFetchNullTerminatedFile(t *testing.T) {
	nullContent := []byte("binary\x00") // ends in a NUL byte
	sum := sha256.Sum256(nullContent)
	files := map[string][]byte{"/bin": nullContent}
	idx := pkgindex.NewIndex([]pkgindex.Entry{
		{Path: "/bin", Mode: "100755", Size: len(nullContent), SHA256: hex.EncodeToString(sum[:])},
	})

	srv, rr, shutdown := startServer(t)
	defer shutdown()

	indexLabel, err := Publish(srv, idx, files, objectstore.AAAA)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	got, err := Fetch(rr, indexLabel, "/bin", objectstore.AAAA)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(got, nullContent) {
		t.Fatalf("got %q (%d bytes), want %q (%d bytes)", got, len(got), nullContent, len(nullContent))
	}
}

// TestPublishRejectsMismatch ensures a file whose bytes do not match its index
// entry is rejected before publishing.
func TestPublishRejectsMismatch(t *testing.T) {
	idx, files := testIndex()
	files["/alpha"] = []byte("tampered") // no longer hashes to shaHello

	srv, _, shutdown := startServer(t)
	defer shutdown()

	if _, err := Publish(srv, idx, files, objectstore.TXT); err == nil {
		t.Fatal("publish succeeded with mismatched file, want error")
	}
}

// TestPublishRejectsMissingFile ensures Publish fails when an index lists a
// file that is not present in the provided files map, rather than publishing a
// partial index.
func TestPublishRejectsMissingFile(t *testing.T) {
	idx, _ := testIndex()
	// Drop every file: the index still lists /alpha, /empty, /zeta.
	srv, _, shutdown := startServer(t)
	defer shutdown()

	if _, err := Publish(srv, idx, map[string][]byte{}, objectstore.TXT); err == nil {
		t.Fatal("publish succeeded with missing files, want error")
	}
}

// TestPublishRejectsBadEntryLabel ensures Publish fails when an index entry's
// stored sha256 is not valid hex, so computing its DNS label fails.
func TestPublishRejectsBadEntryLabel(t *testing.T) {
	files := map[string][]byte{"/alpha": []byte(helloText)}
	idx := pkgindex.NewIndex([]pkgindex.Entry{
		{Path: "/alpha", Mode: "100644", Size: len(helloText), SHA256: "nothex!!"},
	})
	srv, _, shutdown := startServer(t)
	defer shutdown()

	if _, err := Publish(srv, idx, files, objectstore.TXT); err == nil {
		t.Fatal("publish succeeded with bad entry label, want error")
	}
}

// TestFetchMissingFile ensures Fetch fails when the requested file was never
// published, rather than returning unverified data. The full index is
// published, then the target record is forgotten from the server so the
// resolver returns a not-found.
func TestFetchMissingFile(t *testing.T) {
	idx, files := testIndex()
	srv, rr, shutdown := startServer(t)
	defer shutdown()

	if _, err := Publish(srv, idx, files, objectstore.TXT); err != nil {
		t.Fatalf("publish: %v", err)
	}
	// Remove the /zeta record from the server so the fetch cannot find it.
	zeta, err := idx.Lookup("/zeta")
	if err != nil {
		t.Fatalf("lookup /zeta: %v", err)
	}
	label, err := zeta.Label()
	if err != nil {
		t.Fatalf("label /zeta: %v", err)
	}
	srv.Forget(dns.Fqdn(label + ".f.example.com"))

	if _, err := Fetch(rr, idx.Label(), "/zeta", objectstore.TXT); err == nil {
		t.Fatal("fetch succeeded for unpublished file, want error")
	}
}

// TestFetchAcceptsLowercaseIndexLabel checks an index label copied in
// lowercase still verifies against the fetched index.
func TestFetchAcceptsLowercaseIndexLabel(t *testing.T) {
	idx, files := testIndex()
	srv, rr, shutdown := startServer(t)
	defer shutdown()
	label, err := Publish(srv, idx, files, objectstore.TXT)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range files {
		got, err := Fetch(rr, strings.ToLower(label), path, objectstore.TXT)
		if err != nil {
			t.Fatalf("fetch %s with lowercase label: %v", path, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("fetch %s: got %q, want %q", path, got, want)
		}
	}
}

// TestFetchWithAnyResolverSuffix fetches through resolvers configured for the
// default manifest scheme and for the git scheme. Fetch used to look the file
// up under the caller's suffix (<hash>.o.<zone>) and fail with "record not
// found" unless the caller had already selected the mirror scheme.
func TestFetchWithAnyResolverSuffix(t *testing.T) {
	for _, tr := range []objectstore.Transport{objectstore.TXT, objectstore.AAAA} {
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			idx, files := testIndex()
			srv, _, shutdown := startServer(t)
			defer shutdown()
			label, err := Publish(srv, idx, files, tr)
			if err != nil {
				t.Fatal(err)
			}
			base := dnszone.NewResolver("127.0.0.1:"+strconv.Itoa(srv.Port()), dnszone.Zone("example.com"), 0)
			for name, r := range map[string]*dnszone.Resolver{"default": base, "git": base.WithObjectSuffix("g")} {
				for path, want := range files {
					got, err := Fetch(r, label, path, tr)
					if err != nil {
						t.Fatalf("%s resolver, fetch %s: %v", name, path, err)
					}
					if !bytes.Equal(got, want) {
						t.Fatalf("%s resolver, fetch %s: got %q, want %q", name, path, got, want)
					}
				}
			}
		})
	}
}

// TestRoundTripLargeFile publishes and fetches a 300 KB package file. Files
// used to be one record each, so anything past ~47 KB (TXT) or ~3.8 KB (AAAA)
// could not be served.
func TestRoundTripLargeFile(t *testing.T) {
	for _, tr := range []objectstore.Transport{objectstore.TXT, objectstore.AAAA} {
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			data := make([]byte, 300_000)
			for i := range data {
				data[i] = byte(i % 253)
			}
			sum := sha256.Sum256(data)
			idx := pkgindex.NewIndex([]pkgindex.Entry{{Path: "/pool/big.deb", Mode: "100644", Size: len(data), SHA256: hex.EncodeToString(sum[:])}})
			srv, rr, shutdown := startServer(t)
			defer shutdown()
			label, err := Publish(srv, idx, map[string][]byte{"/pool/big.deb": data}, tr)
			if err != nil {
				t.Fatalf("publish: %v", err)
			}
			got, err := Fetch(rr, label, "/pool/big.deb", tr)
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Fatal("round-trip mismatch")
			}
		})
	}
}
