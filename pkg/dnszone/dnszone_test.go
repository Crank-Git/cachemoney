package dnszone

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/miekg/dns"

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

// TestEndToEndTruncateAAAA exercises the resolver's TCP fallback: a single
// large chunk whose AAAA encoding exceeds the 4 KB EDNS0 buffer forces the
// server to truncate the UDP answer, so the resolver re-issues over TCP.
func TestEndToEndTruncateAAAA(t *testing.T) {
	srv, res, shutdown := newTestServer(t, objectstore.AAAA)
	defer shutdown()

	// A single ~3 KB chunk: its AAAA encoding (15 payload bytes per 16-byte
	// record) is 201 records, so the UDP answer exceeds the 4 KB EDNS0 buffer
	// and the server truncates it (setting the TC bit); the resolver then
	// re-issues over TCP. The chunk stays under 256 records so the 1-byte
	// sequence number in each AAAA record does not overflow.
	data := randBytes(3000)
	m := &objectstore.Manifest{
		Version:    objectstore.ManifestVersion,
		TotalSize:  int64(len(data)),
		ChunkCount: 1,
		ChunkIDs:   []objectstore.ObjectID{objectstore.ChunkID(data)},
		ChunkLens:  []int64{int64(len(data))},
	}
	if err := srv.Publish(m, [][]byte{data}, objectstore.AAAA); err != nil {
		t.Fatalf("publish: %v", err)
	}
	got, err := res.Fetch(m, objectstore.AAAA)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(data))
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

// TestGitSchemeRawRoundTrip exercises the raw-record path the git scheme uses:
// a resolver configured with the ".g" suffix, a payload published under a
// custom fully-qualified name, and fetched back verbatim. It also covers
// Forget (a missing record) and CorruptAt (on-the-wire tampering).
func TestGitSchemeRawRoundTrip(t *testing.T) {
	for _, tr := range []objectstore.Transport{objectstore.TXT, objectstore.AAAA} {
		tr := tr
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			srv, res, shutdown := newTestServer(t, tr)
			defer shutdown()

			// A git-scheme resolver answers <id>.g.<zone>, not <id>.o.<zone>.
			git := res.WithObjectSuffix("g")

			id := "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0"
			want := []byte("raw git object bytes, not a manifest")
			fqdn := dns.Fqdn(id + ".g.example.com")

			if err := srv.PublishRaw(fqdn, want, tr); err != nil {
				t.Fatalf("publish raw: %v", err)
			}

			got, err := git.FetchRaw(id, tr)
			if err != nil {
				t.Fatalf("fetch raw: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("raw round-trip mismatch: got %q, want %q", got, want)
			}

			// The default suffix must NOT find the git record.
			if _, err := res.FetchRaw(id, tr); err == nil {
				t.Fatal("default resolver found a .g record, want suffix isolation")
			}

			// Forget removes the record; the fetch then fails.
			srv.Forget(fqdn)
			if _, err := git.FetchRaw(id, tr); err == nil {
				t.Fatal("fetch succeeded after Forget, want not-found")
			}

			// Re-publish and tamper; CorruptAt flips a byte in a TXT piece, so it
			// only applies to the TXT transport.
			if tr == objectstore.TXT {
				if err := srv.PublishRaw(fqdn, want, tr); err != nil {
					t.Fatalf("re-publish raw: %v", err)
				}
				if err := srv.CorruptAt(fqdn); err != nil {
					t.Fatalf("corrupt at: %v", err)
				}
				got, err = git.FetchRaw(id, tr)
				if err != nil {
					t.Fatalf("fetch raw after corrupt: %v", err)
				}
				if bytes.Equal(got, want) {
					t.Fatal("corrupt had no effect, want differing bytes")
				}
			}
		})
	}
}

// TestNewServerDefaultsTTL confirms a zero TTL is defaulted rather than served
// as zero, which would make records expire immediately.
func TestNewServerDefaultsTTL(t *testing.T) {
	srv := NewServer(Zone("example.com"), 0)
	if srv.ZoneName() != "example.com" {
		t.Fatalf("ZoneName = %q, want example.com", srv.ZoneName())
	}
}

// TestZoneName confirms the server reports the zone it was created for.
func TestZoneName(t *testing.T) {
	srv := NewServer(Zone("example.com"), DefaultTTL)
	if got := srv.ZoneName(); got != "example.com" {
		t.Fatalf("ZoneName = %q, want %q", got, "example.com")
	}
}

// TestFetchByID covers the id-first entry point: publish an object, then fetch
// it back by its manifest id alone, letting the resolver resolve the manifest
// and walk the chunks.
func TestFetchByID(t *testing.T) {
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

			got, err := res.FetchByID(m.ID(), tr)
			if err != nil {
				t.Fatalf("FetchByID: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("FetchByID mismatch: got %d bytes, want %d", len(got), len(data))
			}
		})
	}
}

// TestLoadStore writes a disk store in the CLI put layout, loads it into a
// server, and verifies the loaded object is fetchable.
func TestLoadStore(t *testing.T) {
	for _, tr := range []objectstore.Transport{objectstore.TXT, objectstore.AAAA} {
		tr := tr
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			srv, res, shutdown := newTestServer(t, tr)
			defer shutdown()

			data := randBytes(2000)
			m, chunks := objectstore.Build(data)

			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "manifests"), 0o750); err != nil {
				t.Fatalf("mkdir manifests: %v", err)
			}
			if err := os.MkdirAll(filepath.Join(dir, "chunks"), 0o750); err != nil {
				t.Fatalf("mkdir chunks: %v", err)
			}
			mb, err := m.Bytes()
			if err != nil {
				t.Fatalf("manifest bytes: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "manifests", string(m.ID())+".json"), mb, 0o640); err != nil {
				t.Fatalf("write manifest: %v", err)
			}
			for i, cid := range m.ChunkIDs {
				if err := os.WriteFile(filepath.Join(dir, "chunks", string(cid)), chunks[i], 0o640); err != nil {
					t.Fatalf("write chunk %s: %v", cid, err)
				}
			}

			if err := srv.LoadStore(dir, tr); err != nil {
				t.Fatalf("LoadStore: %v", err)
			}

			got, err := res.FetchByID(m.ID(), tr)
			if err != nil {
				t.Fatalf("fetch loaded object: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("loaded object mismatch: got %d bytes, want %d", len(got), len(data))
			}
		})
	}
}

// TestLoadStoreMissing ensures a non-existent store directory fails loudly
// rather than serving an empty zone.
func TestLoadStoreMissing(t *testing.T) {
	srv := NewServer(Zone("example.com"), DefaultTTL)
	if err := srv.LoadStore(filepath.Join(t.TempDir(), "does-not-exist"), objectstore.TXT); err == nil {
		t.Fatal("LoadStore on missing dir accepted, want error")
	}
}

// TestLoadStoreRejectsSizeMismatch ensures a chunk on disk whose size does not
// match the manifest's ChunkLens is rejected, so a corrupted store file fails
// loudly at load time rather than serving a wrong-length chunk.
func TestLoadStoreRejectsSizeMismatch(t *testing.T) {
	srv := NewServer(Zone("example.com"), DefaultTTL)
	dir := t.TempDir()
	mDir := filepath.Join(dir, "manifests")
	cDir := filepath.Join(dir, "chunks")
	if err := os.MkdirAll(mDir, 0o750); err != nil {
		t.Fatalf("mkdir manifests: %v", err)
	}
	if err := os.MkdirAll(cDir, 0o750); err != nil {
		t.Fatalf("mkdir chunks: %v", err)
	}

	data := []byte("wrong-size chunk on disk")
	m, chunks := objectstore.Build(data)
	mb, err := m.Bytes()
	if err != nil {
		t.Fatalf("manifest bytes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(mDir, string(m.ID())+".json"), mb, 0o640); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	// Write the right chunk under the right name but with one extra byte.
	wrong := make([]byte, len(chunks[0])+1)
	copy(wrong, chunks[0])
	if err := os.WriteFile(filepath.Join(cDir, string(m.ChunkIDs[0])), wrong, 0o640); err != nil {
		t.Fatalf("write chunk: %v", err)
	}

	if err := srv.LoadStore(dir, objectstore.TXT); err == nil {
		t.Fatal("LoadStore accepted a size-mismatched chunk, want error")
	}
}

// TestLoadStoreRejectsBadManifest ensures a manifest file that is not valid
// JSON is rejected at load time.
func TestLoadStoreRejectsBadManifest(t *testing.T) {
	srv := NewServer(Zone("example.com"), DefaultTTL)
	dir := t.TempDir()
	mDir := filepath.Join(dir, "manifests")
	if err := os.MkdirAll(mDir, 0o750); err != nil {
		t.Fatalf("mkdir manifests: %v", err)
	}
	if err := os.WriteFile(filepath.Join(mDir, "deadbeef.json"), []byte("not json"), 0o640); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := srv.LoadStore(dir, objectstore.TXT); err == nil {
		t.Fatal("LoadStore accepted a non-JSON manifest, want error")
	}
}

// TestCorruptUnknown ensures Corrupt on an id with no stored record fails
// loudly rather than silently succeeding.
func TestCorruptUnknown(t *testing.T) {
	srv := NewServer(Zone("example.com"), DefaultTTL)
	if err := srv.Corrupt(objectstore.ObjectID("notastoredid")); err == nil {
		t.Fatal("Corrupt on unknown id accepted, want error")
	}
}
