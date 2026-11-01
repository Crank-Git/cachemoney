package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// findObjectID returns the single object id stored under the manifests dir.
func findObjectID(t *testing.T, store string) objectstore.ObjectID {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(store, "manifests"))
	if err != nil {
		t.Fatalf("read manifests: %v", err)
	}
	found := false
	var id objectstore.ObjectID
	for _, e := range entries {
		id = objectstore.ObjectID(strings.TrimSuffix(e.Name(), ".json"))
		found = true
	}
	if !found {
		t.Fatal("no object stored")
	}
	return id
}

func TestPutGetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	in := filepath.Join(dir, "input.bin")
	out := filepath.Join(dir, "output.bin")

	payload := []byte("content-addressed round-trip through the CLI")
	if err := os.WriteFile(in, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := run([]string{"put", "-store", store, in}); err != nil {
		t.Fatalf("put: %v", err)
	}
	id := findObjectID(t, store)

	if err := run([]string{"get", "-store", store, "-out", out, string(id)}); err != nil {
		t.Fatalf("get: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch: got %q", got)
	}
}

func TestGetDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	in := filepath.Join(dir, "input.bin")
	payload := []byte("do not tamper with this payload please")
	if err := os.WriteFile(in, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"put", "-store", store, in}); err != nil {
		t.Fatalf("put: %v", err)
	}
	id := findObjectID(t, store)

	// Corrupt a stored chunk; get must fail the hash check.
	chunksDir := filepath.Join(store, "chunks")
	entries, err := os.ReadDir(chunksDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := os.WriteFile(filepath.Join(chunksDir, e.Name()), []byte("corrupted"), 0o644); err != nil {
			t.Fatal(err)
		}
		break
	}
	if err := run([]string{"get", "-store", store, "-out", filepath.Join(dir, "out"), string(id)}); err == nil {
		t.Fatal("expected tamper to fail, got nil")
	}
}

func TestGetMissingObject(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	err := run([]string{"get", "-store", store, string(objectstore.ObjectID("deadbeef") + "missing")})
	if err == nil {
		t.Fatal("expected missing-object error, got nil")
	}
	_ = dir
}
