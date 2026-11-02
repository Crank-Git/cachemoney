package dnszone

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

var bothTransports = []objectstore.Transport{objectstore.TXT, objectstore.AAAA}

// TestFetchRejectsForgedManifest serves an attacker's manifest (with its own
// valid chunks) under a real object's id. Before manifests were verified the
// resolver returned the attacker's bytes as the real object. Both entry
// points, both transports, and the cache must all refuse it.
func TestFetchRejectsForgedManifest(t *testing.T) {
	for _, tr := range bothTransports {
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			srv, res, shutdown := newTestServer(t, tr)
			defer shutdown()

			real, realChunks := objectstore.Build([]byte("the real content"))
			if err := srv.Publish(real, realChunks, tr); err != nil {
				t.Fatal(err)
			}
			evil, evilChunks := objectstore.Build([]byte("ATTACKER CONTENT"))
			if err := srv.Publish(evil, evilChunks, tr); err != nil {
				t.Fatal(err)
			}
			evilBytes, _ := evil.Bytes()
			if err := srv.PublishRaw(srv.manifestName(real.ID()), evilBytes, tr); err != nil {
				t.Fatal(err)
			}

			cache := NewCache(0)
			res = res.WithCache(cache)
			if got, err := res.FetchByID(real.ID(), tr); err == nil {
				t.Fatalf("FetchByID returned %q for a forged manifest", got)
			} else if !strings.Contains(err.Error(), "hash mismatch") {
				t.Fatalf("FetchByID error %q, want hash mismatch", err)
			}
			if got, err := res.Fetch(real, tr); err == nil {
				t.Fatalf("Fetch returned %q for a forged manifest", got)
			}
			if cache.Len() != 0 {
				t.Fatalf("forged object was cached (Len=%d)", cache.Len())
			}

			// The attacker's object is still fetchable under its own id.
			got, err := res.FetchByID(evil.ID(), tr)
			if err != nil || string(got) != "ATTACKER CONTENT" {
				t.Fatalf("FetchByID(evil) = %q, %v", got, err)
			}
		})
	}
}

// TestFetchRejectsMalformedManifest serves manifests whose bytes hash to the
// requested id but describe an inconsistent object. The resolver must return
// an error, not panic, before fetching chunks.
func TestFetchRejectsMalformedManifest(t *testing.T) {
	bad := [][]byte{
		[]byte(`{"version":1,"totalSize":5,"chunkCount":1,"chunkIDs":["AAAA"],"chunkLens":[]}`),
		[]byte(`{"version":1,"totalSize":-5,"chunkCount":1,"chunkIDs":["AAAA"],"chunkLens":[-5]}`),
		[]byte(`{"version":7,"totalSize":0,"chunkCount":0,"chunkIDs":[],"chunkLens":[]}`),
		[]byte(`not json at all`),
	}
	for _, tr := range bothTransports {
		for i, b := range bad {
			t.Run("transport="+strconv.Itoa(int(tr))+"/case="+strconv.Itoa(i), func(t *testing.T) {
				srv, res, shutdown := newTestServer(t, tr)
				defer shutdown()
				id := objectstore.ObjectID(objectstore.ToLabel(objectstore.HashBytes(b)))
				if err := srv.PublishRaw(srv.manifestName(id), b, tr); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("resolver panicked: %v", r)
					}
				}()
				if _, err := res.FetchByID(id, tr); err == nil {
					t.Fatal("FetchByID accepted a malformed manifest")
				}
			})
		}
	}
}

// TestLoadStoreServesManifestUnderFileHash writes a manifest whose bytes are
// valid but not the canonical marshaling (indented JSON). The server must
// address it by the hash of the bytes it serves, so a client can verify it.
func TestLoadStoreServesManifestUnderFileHash(t *testing.T) {
	dir := t.TempDir()
	data := randBytes(2500)
	m, chunks := objectstore.Build(data)
	pretty, err := jsonIndent(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "manifests"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "chunks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifests", "x.json"), pretty, 0o644); err != nil {
		t.Fatal(err)
	}
	for i, id := range m.ChunkIDs {
		if err := os.WriteFile(filepath.Join(dir, "chunks", string(id)), chunks[i], 0o644); err != nil {
			t.Fatal(err)
		}
	}

	srv := NewServer(Zone("example.com"), 0)
	if err := srv.LoadStore(dir, objectstore.TXT); err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()
	res := NewResolver("127.0.0.1:"+strconv.Itoa(srv.Port()), Zone("example.com"), 0)

	fileID := objectstore.ObjectID(objectstore.ToLabel(objectstore.HashBytes(pretty)))
	got, err := res.FetchByID(fileID, objectstore.TXT)
	if err != nil {
		t.Fatalf("FetchByID(file hash): %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("round-trip mismatch")
	}
	srv.mu.RLock()
	_, servedUnderReMarshal := srv.records[dns.Fqdn(srv.manifestName(m.ID()))]
	srv.mu.RUnlock()
	if servedUnderReMarshal && fileID != m.ID() {
		t.Fatal("manifest served under a re-marshaled id that does not hash its bytes")
	}
}

func jsonIndent(m *objectstore.Manifest) ([]byte, error) {
	b, err := m.Bytes()
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "  "); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
