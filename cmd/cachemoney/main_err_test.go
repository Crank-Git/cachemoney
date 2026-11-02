package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// TestPutRequiresFile ensures put fails when no file argument is given.
func TestPutRequiresFile(t *testing.T) {
	if err := run([]string{"put", "-store", t.TempDir()}); err == nil {
		t.Fatal("put with no file accepted, want error")
	}
}

// TestPutReadError ensures put fails when the input file cannot be read.
func TestPutReadError(t *testing.T) {
	if err := run([]string{"put", "-store", t.TempDir(), filepath.Join(t.TempDir(), "nope.bin")}); err == nil {
		t.Fatal("put on missing file accepted, want error")
	}
}

// TestPutMkdirError ensures put fails when the store path cannot be created,
// which happens when the store path is already a regular file.
func TestPutMkdirError(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	if err := os.WriteFile(store, []byte("i am a file"), 0o644); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(dir, "input.bin")
	if err := os.WriteFile(in, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"put", "-store", store, in}); err == nil {
		t.Fatal("put accepted when store path is a file, want error")
	}
}

// TestPutMkdirChunksError ensures put fails when the chunk directory cannot be
// created even though the manifest directory can, which happens when the store
// path is a directory but the chunks sub-path is a regular file.
func TestPutMkdirChunksError(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	if err := os.MkdirAll(filepath.Join(store, "manifests"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A regular file where put expects to create the chunks directory.
	if err := os.WriteFile(filepath.Join(store, "chunks"), []byte("i am a file"), 0o644); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(dir, "input.bin")
	if err := os.WriteFile(in, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"put", "-store", store, in}); err == nil {
		t.Fatal("put succeeded when the chunks path is a file, want error")
	}
}

// TestGetRequiresID ensures get fails when no object id is given.
func TestGetRequiresID(t *testing.T) {
	if err := run([]string{"get", "-store", t.TempDir()}); err == nil {
		t.Fatal("get with no id accepted, want error")
	}
}

// TestGetReadManifestError ensures get fails when the manifest file is missing.
func TestGetReadManifestError(t *testing.T) {
	if err := run([]string{"get", "-store", t.TempDir(), string(objectstore.ObjectID("deadbeef") + "0")}); err == nil {
		t.Fatal("get with missing manifest accepted, want error")
	}
}

// TestGetChunkError ensures get fails when a referenced chunk is missing from
// the store.
func TestGetChunkError(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	in := filepath.Join(dir, "input.bin")
	if err := os.WriteFile(in, []byte("a small payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"put", "-store", store, in}); err != nil {
		t.Fatalf("put: %v", err)
	}
	id := findObjectID(t, store)
	// Remove every chunk so get cannot reassemble the object.
	chunksDir := filepath.Join(store, "chunks")
	entries, err := os.ReadDir(chunksDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := os.Remove(filepath.Join(chunksDir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	if err := run([]string{"get", "-store", store, string(id)}); err == nil {
		t.Fatal("get succeeded with missing chunks, want error")
	}
}

// TestFetchRequiresID ensures fetch fails when no object id is given.
func TestFetchRequiresID(t *testing.T) {
	if err := run([]string{"fetch", "-addr", "127.0.0.1:" + strconv.Itoa(1)}); err == nil {
		t.Fatal("fetch with no id accepted, want error")
	}
}

// TestGetInvalidManifest ensures get fails when a manifest file is present but
// does not parse as a manifest, rather than returning a garbage object.
func TestGetInvalidManifest(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	mDir := filepath.Join(store, "manifests")
	if err := os.MkdirAll(mDir, 0o755); err != nil {
		t.Fatal(err)
	}
	id := objectstore.ObjectID("deadbeef" + "0")
	// A manifest file that is not valid JSON.
	if err := os.WriteFile(filepath.Join(mDir, string(id)+".json"), []byte("not a manifest"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"get", "-store", store, string(id)}); err == nil {
		t.Fatal("get succeeded with an unparseable manifest, want error")
	}
}

// TestFetchInvalidTransport ensures fetch fails when given an unknown transport
// flag, which parseTransport rejects before any fetch is attempted.
func TestFetchInvalidTransport(t *testing.T) {
	dir := t.TempDir()
	if err := run([]string{"fetch", "-addr", "127.0.0.1:1", "-tr", "bogus", "-out", filepath.Join(dir, "out"), string(objectstore.ObjectID("deadbeef") + "0")}); err == nil {
		t.Fatal("fetch succeeded with an unknown transport, want error")
	}
}

// TestFetchConnectionRefused ensures fetch fails when the server cannot be
// reached, rather than returning partial data.
func TestFetchConnectionRefused(t *testing.T) {
	dir := t.TempDir()
	// Port 1 is never listening, so the exchange fails.
	err := run([]string{"fetch", "-addr", "127.0.0.1:1", "-out", filepath.Join(dir, "out"), string(objectstore.ObjectID("deadbeef") + "0")})
	if err == nil {
		t.Fatal("fetch succeeded with unreachable server, want error")
	}
}

// TestServeBadAddr ensures serve fails when it cannot bind the listen address.
func TestServeBadAddr(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "input.bin")
	if err := os.WriteFile(in, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"put", "-store", dir, in}); err != nil {
		t.Fatalf("put: %v", err)
	}
	// Port 1 cannot be bound by a normal process, so Start fails.
	if err := run([]string{"serve", "-store", dir, "-addr", "127.0.0.1:1", "-zone", "example.com"}); err == nil {
		t.Fatal("serve succeeded with unbindable address, want error")
	}
}

// TestServeFailsOnBusyPort occupies the TCP side of a port and runs serve on
// it. serve used to block forever; it must return the bind error.
func TestServeFailsOnBusyPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "manifests"), 0o755); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- run([]string{"serve", "-store", dir, "-addr", ln.Addr().String()}) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("serve succeeded on a busy port, want error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve blocked on a busy port instead of returning an error")
	}
}
