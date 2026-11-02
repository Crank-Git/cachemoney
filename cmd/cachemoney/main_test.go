package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Crank-Git/cachemoney/pkg/dnszone"
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

// TestPutWritesIDToOutFlag ensures the -out flag writes the object id and that
// the id written is the one used to retrieve the object.
func TestPutWritesIDToOutFlag(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	in := filepath.Join(dir, "input.bin")
	outID := filepath.Join(dir, "id.txt")
	payload := []byte("write the id to the out flag")
	if err := os.WriteFile(in, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"put", "-store", store, "-out", outID, in}); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := os.ReadFile(outID)
	if err != nil {
		t.Fatalf("read -out: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("empty id written to -out")
	}
	// The id written to -out must be the one that retrieves the object.
	if err := run([]string{"get", "-store", store, string(objectstore.ObjectID(got))}); err != nil {
		t.Fatalf("get by -out id: %v", err)
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

// startServingServer loads dir into an in-memory DNS server on an ephemeral
// port and returns it, ready to serve. The caller's test cleans it up.
func startServingServer(t *testing.T, dir string, tr objectstore.Transport) *dnszone.Server {
	t.Helper()
	srv := dnszone.NewServer(dnszone.Zone("example.com"), 0)
	if err := srv.LoadStore(dir, tr); err != nil {
		t.Fatalf("load store: %v", err)
	}
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() { srv.Shutdown() })
	return srv
}

// TestServeFetchOverDNS writes an object to a local store, loads that store
// into an authoritative DNS server, and resolves the object back over the wire
// for both transports. It exercises the full put -> serve -> fetch path.
func TestServeFetchOverDNS(t *testing.T) {
	cases := []struct {
		name      string
		transport objectstore.Transport
	}{
		{"txt", objectstore.TXT},
		{"aaaa", objectstore.AAAA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			store := filepath.Join(dir, "store")
			in := filepath.Join(dir, "input.bin")
			out := filepath.Join(dir, "output.bin")

			// A multi-chunk payload so the AAAA TCP fallback path runs.
			payload := bytes.Repeat([]byte("cachemoney-over-dns-"), 400) // 9600 bytes, ~10 chunks
			if err := os.WriteFile(in, payload, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := run([]string{"put", "-store", store, in}); err != nil {
				t.Fatalf("put: %v", err)
			}
			id := findObjectID(t, store)

			srv := startServingServer(t, store, tc.transport)
			addr := "127.0.0.1:" + strconv.Itoa(srv.Port())

			if err := run([]string{"fetch", "-addr", addr, "-tr", tc.name, "-out", out, string(id)}); err != nil {
				t.Fatalf("fetch: %v", err)
			}
			got, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(payload))
			}
		})
	}
}

// TestFetchOverDNSMissing ensures a fetch for an unknown id fails over DNS.
func TestFetchOverDNSMissing(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	// Populate the store with an unrelated object so the server has records.
	in := filepath.Join(dir, "input.bin")
	if err := os.WriteFile(in, []byte("something else"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"put", "-store", store, in}); err != nil {
		t.Fatalf("put: %v", err)
	}
	srv := startServingServer(t, store, objectstore.TXT)
	addr := "127.0.0.1:" + strconv.Itoa(srv.Port())

	err := run([]string{"fetch", "-addr", addr, "-out", filepath.Join(dir, "out"), "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"})
	if err == nil {
		t.Fatal("expected not-found error over DNS, got nil")
	}
}

// TestServeBadStore ensures serve fails loudly when the store cannot be loaded.
func TestServeBadStore(t *testing.T) {
	err := run([]string{"serve", "-store", filepath.Join("does", "not", "exist")})
	if err == nil {
		t.Fatal("expected serve to fail on a missing store, got nil")
	}
}

// TestServeBadTransport ensures serve rejects an unknown transport flag.
func TestServeBadTransport(t *testing.T) {
	err := run([]string{"serve", "-tr", "smtptls"})
	if err == nil {
		t.Fatal("expected serve to fail on an unknown transport, got nil")
	}
}

// TestRunDispatch covers the run-level error paths: no command, and an unknown
// command, both of which must fail before dispatching to a subcommand.
func TestRunDispatch(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("run with no args accepted, want usage error")
	}
	if err := run([]string{"bogus"}); err == nil {
		t.Fatal("run with unknown command accepted, want error")
	}
}

// TestParseTransport covers the transport flag parser directly.
func TestParseTransport(t *testing.T) {
	wantOK := map[string]objectstore.Transport{
		"txt":  objectstore.TXT,
		"":     objectstore.TXT,
		"aaaa": objectstore.AAAA,
		"AAAA": objectstore.AAAA,
	}
	for in, want := range wantOK {
		got, err := parseTransport(in)
		if err != nil {
			t.Fatalf("parseTransport(%q): unexpected error %v", in, err)
		}
		if got != want {
			t.Fatalf("parseTransport(%q): got %v, want %v", in, got, want)
		}
	}
	if _, err := parseTransport("nope"); err == nil {
		t.Fatal("expected error for unknown transport")
	}
}

// TestMain runs the compiled binary as a subprocess to cover the top-level
// main() entry point, including the error print and non-zero exit path that
// run() (invoked directly elsewhere) does not reach.
func TestMain(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "bogus-command")
	if out, _ := cmd.CombinedOutput(); cmd.ProcessState.ExitCode() == 0 {
		t.Fatalf("expected non-zero exit for unknown command, got %q", out)
	}
}

// buildBinary compiles the cachemoney binary once for subprocess tests.
func buildBinary(t *testing.T) string {
	bin := filepath.Join(t.TempDir(), "cachemoney-bin")
	args := []string{"build", "-o", bin, "."}
	cmd := exec.Command("go", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatal(err)
	}
	return bin
}
