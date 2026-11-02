package dnszone

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// TestEndToEndTruncateAAAA exercises the resolver's TCP fallback. Chunk
// answers fit the 1232-byte EDNS0 buffer for ordinary zones, but under a
// zone name near the 253-character limit a full AAAA chunk answer does not,
// so the server truncates the UDP answer (setting TC) and the resolver
// re-issues over TCP.
func TestEndToEndTruncateAAAA(t *testing.T) {
	zone := Zone(strings.Repeat(strings.Repeat("z", 60)+".", 3) + "example.com")
	srv := NewServer(zone, 0)
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()
	addr := "127.0.0.1:" + strconv.Itoa(srv.Port())
	res := NewResolver(addr, zone, 0)

	data := randBytes(3 * objectstore.DefaultChunkSize)
	m, chunks := objectstore.Build(data)
	if err := srv.Publish(m, chunks, objectstore.AAAA); err != nil {
		t.Fatalf("publish: %v", err)
	}
	// Confirm a chunk answer really is truncated over UDP at 1232 bytes.
	q := new(dns.Msg)
	q.SetQuestion(srv.chunkName(m.ChunkIDs[0]), dns.TypeAAAA)
	q.SetEdns0(ednsUDPSize, false)
	udp, _, err := (&dns.Client{Net: "udp", UDPSize: ednsUDPSize}).Exchange(q, addr)
	if err != nil {
		t.Fatal(err)
	}
	if !udp.Truncated {
		t.Fatal("chunk answer under a long zone was not truncated; the TCP path is untested")
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

// TestWithConcurrency checks the option sets the parallelism and resets to the
// default for non-positive values, without disturbing the original resolver.
func TestWithConcurrency(t *testing.T) {
	res := NewResolver("127.0.0.1:5300", Zone("example.com"), 0)

	base := res.WithConcurrency(4)
	if base.concurrency != 4 {
		t.Fatalf("WithConcurrency(4): got %d, want 4", base.concurrency)
	}
	// The original resolver is unchanged by chaining.
	if res.concurrency != defaultConcurrency {
		t.Fatalf("WithConcurrency mutated the base resolver: got %d", res.concurrency)
	}

	reset := base.WithConcurrency(0)
	if reset.concurrency != defaultConcurrency {
		t.Fatalf("WithConcurrency(0): got %d, want default %d", reset.concurrency, defaultConcurrency)
	}
}

// TestParallelWalk fetches a multi-chunk object with a high concurrency limit,
// exercising the bounded concurrent walk and order-independent reassembly.
func TestParallelWalk(t *testing.T) {
	srv, res, shutdown := newTestServer(t, objectstore.TXT)
	defer shutdown()

	// ~5 chunks (5x the concurrency limit) so the semaphore drains in waves.
	data := randBytes(5*objectstore.DefaultChunkSize + 1)
	m, chunks := objectstore.Build(data)
	if err := srv.Publish(m, chunks, objectstore.TXT); err != nil {
		t.Fatalf("publish: %v", err)
	}

	res = res.WithConcurrency(1)
	got, err := res.Fetch(m, objectstore.TXT)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(data))
	}
}

// TestFetchUsesCache verifies the resolver cache short-circuits a second fetch:
// after the first fetch populates the cache, the object is returned even once
// the server is gone, and a missing object is not cached.
func TestFetchUsesCache(t *testing.T) {
	srv, res, shutdown := newTestServer(t, objectstore.TXT)

	m, chunks := objectstore.Build([]byte("cached object"))
	if err := srv.Publish(m, chunks, objectstore.TXT); err != nil {
		t.Fatalf("publish: %v", err)
	}

	cache := NewCache(0)
	res = res.WithCache(cache)

	// First fetch populates the cache from the server.
	if _, err := res.Fetch(m, objectstore.TXT); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if cache.Len() != 1 {
		t.Fatalf("cache should hold one object, got %d", cache.Len())
	}

	// Kill the server; a cache hit must still succeed.
	shutdown()
	if _, err := res.Fetch(m, objectstore.TXT); err != nil {
		t.Fatalf("fetch after server down: %v (cache should have served it)", err)
	}
}

// TestMissingObjectNotCached verifies a failed fetch does not poison the cache:
// a missing object is re-attempted on the next call rather than remembered as
// a miss.
func TestMissingObjectNotCached(t *testing.T) {
	_, res, shutdown := newTestServer(t, objectstore.TXT)
	defer shutdown()

	cache := NewCache(0)
	res = res.WithCache(cache)

	// Fetch an id that was never published; it must fail loudly.
	missing := objectstore.ChunkID([]byte("never published"))
	if _, err := res.FetchByID(missing, objectstore.TXT); err == nil {
		t.Fatal("expected a not-found error")
	}
	if cache.Len() != 0 {
		t.Fatalf("a missing object must not be cached, Len=%d", cache.Len())
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

			// Re-publish and tamper with the payload's chunk; CorruptAt flips a
			// byte in a TXT piece, so it only applies to the TXT transport. The
			// chunk no longer matches its hash, so the fetch fails.
			if tr == objectstore.TXT {
				if err := srv.PublishRaw(fqdn, want, tr); err != nil {
					t.Fatalf("re-publish raw: %v", err)
				}
				if err := srv.CorruptAt(srv.chunkName(objectstore.ChunkID(want))); err != nil {
					t.Fatalf("corrupt at: %v", err)
				}
				if got, err := git.FetchRaw(id, tr); err == nil {
					t.Fatalf("fetch raw after corrupt returned %q, want hash mismatch", got)
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

// TestLoadStoreRejectsUnreadableManifest ensures LoadStore fails when a manifest
// file exists but cannot be read, rather than silently skipping it.
func TestLoadStoreRejectsUnreadableManifest(t *testing.T) {
	srv := NewServer(Zone("example.com"), DefaultTTL)
	dir := t.TempDir()
	mDir := filepath.Join(dir, "manifests")
	if err := os.MkdirAll(mDir, 0o750); err != nil {
		t.Fatalf("mkdir manifests: %v", err)
	}
	path := filepath.Join(mDir, "deadbeef.json")
	if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	// Strip all read access: ReadDir still lists the file, but ReadFile fails.
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := srv.LoadStore(dir, objectstore.TXT); err == nil {
		t.Fatal("LoadStore accepted an unreadable manifest, want error")
	}
}

// TestLoadStoreMissingChunk ensures LoadStore fails when a manifest references a
// chunk that is not present in the store, rather than serving a manifest with
// no backing data.
func TestLoadStoreMissingChunk(t *testing.T) {
	dir := t.TempDir()
	mDir := filepath.Join(dir, "manifests")
	if err := os.MkdirAll(mDir, 0o750); err != nil {
		t.Fatalf("mkdir manifests: %v", err)
	}
	// Build a valid manifest but never write its chunk files, so LoadStore's
	// per-chunk read fails.
	m, _ := objectstore.Build([]byte("a small payload"))
	mb, err := m.Bytes()
	if err != nil {
		t.Fatalf("manifest bytes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(mDir, string(m.ID())+".json"), mb, 0o640); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	srv := NewServer(Zone("example.com"), DefaultTTL)
	if err := srv.LoadStore(dir, objectstore.TXT); err == nil {
		t.Fatal("LoadStore succeeded with a missing chunk, want error")
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

// TestCorruptAAAA ensures CorruptAAAA flips a payload octet in an AAAA record
// so the decoded chunk no longer matches its hash and the fetch fails. TXT
// records are covered by CorruptAt; AAAA is decoded without base64, so a
// flipped octet changes content rather than breaking decoding.
func TestCorruptAAAA(t *testing.T) {
	srv, res, shutdown := newTestServer(t, objectstore.AAAA)
	defer shutdown()

	const id = "AAAACORRUPT"
	fqdn := dns.Fqdn(id + ".f.example.com")
	payload := []byte("corruptable AAAA payload data")
	if err := srv.PublishRaw(fqdn, payload, objectstore.AAAA); err != nil {
		t.Fatalf("publish: %v", err)
	}
	srv.CorruptAAAA(srv.chunkName(objectstore.ChunkID(payload)))

	if got, err := res.WithObjectSuffix("f").FetchRaw(id, objectstore.AAAA); err == nil {
		t.Fatalf("fetch returned %q after CorruptAAAA, want hash mismatch", got)
	}
}

// TestPortReturnsZeroUnstarted ensures Port reports 0 when the server has not
// been started yet, so a caller can tell an unbound server from one on port 0.
func TestPortReturnsZeroUnstarted(t *testing.T) {
	srv := NewServer(Zone("example.com"), DefaultTTL)
	if p := srv.Port(); p != 0 {
		t.Fatalf("Port = %d on unstarted server, want 0", p)
	}
}

// TestStartBadAddr ensures Start fails when it cannot discover a free port, so
// a caller learns the server never bound rather than blocking forever.
func TestStartBadAddr(t *testing.T) {
	srv := NewServer(Zone("example.com"), DefaultTTL)
	if err := srv.Start("127.0.0.1:notaport"); err == nil {
		t.Fatal("Start succeeded with an unparseable port, want error")
	}
}

// TestLoadStoreSkipsNonJSON ensures LoadStore ignores entries that are not
// manifest files (subdirectories and non-.json files) rather than erroring.
func TestLoadStoreSkipsNonJSON(t *testing.T) {
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
	// A subdirectory and a non-json file in the manifests dir: both skipped.
	if err := os.MkdirAll(filepath.Join(mDir, "subdir"), 0o755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(mDir, "notes.txt"), []byte("ignore me"), 0o640); err != nil {
		t.Fatalf("write notes: %v", err)
	}
	if err := srv.LoadStore(dir, objectstore.TXT); err != nil {
		t.Fatalf("LoadStore skipped non-json entries, want no error: %v", err)
	}
}

// TestCorruptAtNonTXT ensures corruptRecord rejects a non-TXT record (e.g. an
// AAAA record) rather than flipping a byte in a wrong record type.
func TestCorruptAtNonTXT(t *testing.T) {
	srv := NewServer(Zone("example.com"), DefaultTTL)
	// Publish a payload as an AAAA record so the stored record is not TXT.
	fqdn := "aaaa.example.com."
	payload := []byte("aaaa-record-content")
	if err := srv.PublishRaw(fqdn, payload, objectstore.AAAA); err != nil {
		t.Fatalf("publish raw AAAA: %v", err)
	}
	if err := srv.CorruptAt(fqdn); err == nil {
		t.Fatal("CorruptAt on AAAA record accepted, want error")
	}
}

// TestCorruptRecordEmptyTxt ensures corruptRecord rejects a TXT record with no
// character-strings.
func TestCorruptRecordEmptyTxt(t *testing.T) {
	srv := NewServer(Zone("example.com"), DefaultTTL)
	fqdn := "emptytxt.example.com."
	srv.records[nameKey(fqdn)] = []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: srv.ttl},
		Txt: []string{},
	}}
	if err := srv.corruptRecord(fqdn); err == nil {
		t.Fatal("corruptRecord on empty TXT accepted, want error")
	}
}

// TestCorruptRecordNoColon ensures corruptRecord rejects a TXT record whose
// first character-string has no ":" data separator.
func TestCorruptRecordNoColon(t *testing.T) {
	srv := NewServer(Zone("example.com"), DefaultTTL)
	fqdn := "nocolon.example.com."
	srv.records[nameKey(fqdn)] = []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: srv.ttl},
		Txt: []string{"noseparator"},
	}}
	if err := srv.corruptRecord(fqdn); err == nil {
		t.Fatal("corruptRecord on TXT without colon accepted, want error")
	}
}

// TestStoreUnknownTransport ensures store rejects an unknown transport value.
func TestStoreUnknownTransport(t *testing.T) {
	srv := NewServer(Zone("example.com"), DefaultTTL)
	if err := srv.store("unknown.example.com.", []byte("data"), objectstore.Transport(99)); err == nil {
		t.Fatal("store with unknown transport accepted, want error")
	}
}
