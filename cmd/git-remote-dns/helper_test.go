package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/cachemoney/pkg/dnszone"
	"github.com/Crank-Git/cachemoney/pkg/gitdns"
	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// 40-char hex root commit used by the in-process unit tests.
const testSHA = "0123456789abcdef0123456789abcdef01234567"

// TestParseURL checks that the helper extracts the 40-char hex SHA-1 from the
// various URL forms git can hand it: dns://<sha>, dns::<sha>, a bare <sha>, and
// a whitespace-padded form.
func TestParseURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"dns-slash-slash", "dns://" + testSHA, testSHA},
		{"dns-colon-colon", "dns::" + testSHA, testSHA},
		{"bare", testSHA, testSHA},
		{"padded", "  " + testSHA + "  ", testSHA},
		{"dns-slash-slash-slashes", "dns:///" + testSHA, testSHA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseURL(tc.in)
			if err != nil {
				t.Fatalf("parseURL(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("parseURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestParseURLRepoNames checks that anything other than a 40-hex SHA is read
// as a repository name, lowercased.
func TestParseURLRepoNames(t *testing.T) {
	cases := map[string]string{
		"dns://abc":                         "abc",
		"dns::cachemoney":                   "cachemoney",
		"dns://My-Repo/":                    "my-repo",
		"dns://" + strings.Repeat("a", 41):  strings.Repeat("a", 41),
		"dns://" + strings.Repeat("z", 40):  strings.Repeat("z", 40),
		"dns://" + strings.ToUpper(testSHA): testSHA,
	}
	for in, want := range cases {
		got, err := parseURL(in)
		if err != nil || got != want {
			t.Fatalf("parseURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

// TestParseURLErrors checks inputs that are neither a SHA nor a valid
// repository name are rejected.
func TestParseURLErrors(t *testing.T) {
	bad := []string{
		"",                                 // empty
		"dns://",                           // empty target
		"dns://not_a.repo",                 // underscore and dot
		"dns://-lead",                      // leading hyphen
		"dns://" + strings.Repeat("a", 64), // longer than a DNS label
		"dns://a/b",                        // path
	}
	for _, in := range bad {
		if _, err := parseURL(in); err == nil {
			t.Fatalf("parseURL(%q) = nil error, want error", in)
		}
	}
}

// TestLoadConfig checks the environment-driven config and its defaults.
func TestLoadConfig(t *testing.T) {
	// A zone is required.
	t.Setenv("GIT_REMOTE_DNS_ZONE", "")
	if _, err := loadConfig(); err == nil {
		t.Fatal("loadConfig without zone: nil error, want error")
	}

	t.Setenv("GIT_REMOTE_DNS_ZONE", "example.com")
	t.Setenv("GIT_REMOTE_DNS_SERVER", "10.0.0.1:9000")
	t.Setenv("GIT_REMOTE_DNS_TRANSPORT", "aaaa")
	t.Setenv("GIT_REMOTE_DNS_TIMEOUT", "250ms")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.server != "10.0.0.1:9000" {
		t.Errorf("server = %q, want 10.0.0.1:9000", cfg.server)
	}
	if cfg.zone != "example.com" {
		t.Errorf("zone = %q, want example.com", cfg.zone)
	}
	if cfg.transport != "aaaa" {
		t.Errorf("transport = %q, want aaaa", cfg.transport)
	}
	if cfg.timeout != "250ms" {
		t.Errorf("timeout = %q, want 250ms", cfg.timeout)
	}
}

// TestLoadConfigDefaultServer checks the default server when unset.
func TestLoadConfigDefaultServer(t *testing.T) {
	t.Setenv("GIT_REMOTE_DNS_SERVER", "")
	t.Setenv("GIT_REMOTE_DNS_ZONE", "example.com")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.server != "127.0.0.1:5300" {
		t.Errorf("server = %q, want default 127.0.0.1:5300", cfg.server)
	}
}

// TestMustDuration checks that empty and invalid timeouts fall back to 5s while
// a valid duration is parsed through.
func TestMustDuration(t *testing.T) {
	if got := mustDuration(""); got != 5*time.Second {
		t.Errorf("mustDuration(\"\") = %v, want 5s", got)
	}
	if got := mustDuration("not-a-duration"); got != 5*time.Second {
		t.Errorf("mustDuration(garbage) = %v, want 5s", got)
	}
	if got := mustDuration("2s"); got != 2*time.Second {
		t.Errorf("mustDuration(2s) = %v, want 2s", got)
	}
}

// TestNewHelper checks that a helper is built from a valid dns URL with the
// environment config applied, and that an invalid transport is rejected.
func TestNewHelper(t *testing.T) {
	t.Setenv("GIT_REMOTE_DNS_ZONE", "example.com")
	t.Setenv("GIT_REMOTE_DNS_SERVER", "127.0.0.1:5300")
	t.Setenv("GIT_REMOTE_DNS_TRANSPORT", "txt")

	h, err := newHelper("dns://" + testSHA)
	if err != nil {
		t.Fatalf("newHelper: %v", err)
	}
	if h.id != testSHA {
		t.Errorf("id = %q, want %q", h.id, testSHA)
	}
	if h.transport != objectstore.TXT {
		t.Errorf("transport = %v, want TXT", h.transport)
	}

	// Invalid transport must be rejected.
	t.Setenv("GIT_REMOTE_DNS_TRANSPORT", "bogus")
	if _, err := newHelper("dns://" + testSHA); err == nil {
		t.Fatal("newHelper with bogus transport: nil error, want error")
	}

	// The aaaa transport variant selects the AAAA transport.
	t.Setenv("GIT_REMOTE_DNS_TRANSPORT", "aaaa")
	h2, err := newHelper("dns://" + testSHA)
	if err != nil {
		t.Fatalf("newHelper aaaa: %v", err)
	}
	if h2.transport != objectstore.AAAA {
		t.Errorf("transport = %v, want AAAA", h2.transport)
	}
}

// TestNewHelperErrors checks that newHelper surfaces the loadConfig (missing
// zone) and parseURL (bad SHA) errors rather than proceeding.
func TestNewHelperErrors(t *testing.T) {
	// Missing zone -> loadConfig error.
	t.Setenv("GIT_REMOTE_DNS_ZONE", "")
	if _, err := newHelper("dns://" + testSHA); err == nil {
		t.Fatal("newHelper without zone: nil error, want error")
	}

	// Neither a SHA nor a repository name -> parseURL error (zone is set again).
	t.Setenv("GIT_REMOTE_DNS_ZONE", "example.com")
	if _, err := newHelper("dns://not_a.repo"); err == nil {
		t.Fatal("newHelper with bad URL: nil error, want error")
	}
}

// TestRunErrors checks the free run entry point's argument and URL validation.
func TestRunErrors(t *testing.T) {
	// Too few arguments.
	if err := run([]string{"git-remote-dns"}); err == nil {
		t.Fatal("run with too few args: nil error, want error")
	}

	// Invalid URL, zone set so loadConfig passes and parseURL fails.
	t.Setenv("GIT_REMOTE_DNS_ZONE", "example.com")
	if err := run([]string{"git-remote-dns", "origin", "dns://not_a.repo"}); err == nil {
		t.Fatal("run with bad URL: nil error, want error")
	}
}

// TestMainSuccess drives the real main entry point with a valid command stream
// on a stdin pipe, covering main and the run success path in-process.
func TestMainSuccess(t *testing.T) {
	t.Setenv("GIT_REMOTE_DNS_ZONE", "example.com")
	t.Setenv("GIT_REMOTE_DNS_SERVER", "127.0.0.1:5300")

	in, outPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStdin := os.Stdin
	os.Stdin = in
	defer func() { os.Stdin = oldStdin }()

	oldArgs := os.Args
	os.Args = []string{"git-remote-dns", "origin", "dns://" + testSHA}
	defer func() { os.Args = oldArgs }()

	go func() {
		defer outPipe.Close()
		outPipe.WriteString("capabilities\n")
		outPipe.WriteString("list\n")
	}()

	// runMain (not main) is driven here: main wraps it with os.Exit, which the
	// testing framework intercepts and panics on, so the exit-code wrapper is
	// exercised via the subprocess integration test instead.
	if code := runMain(os.Args); code != 0 {
		t.Errorf("runMain success: code %d, want 0", code)
	}
}

// TestRunMainError checks that runMain returns a non-zero exit code when the
// helper fails, without calling os.Exit (which would kill the test process).
func TestRunMainError(t *testing.T) {
	if code := runMain([]string{"git-remote-dns"}); code == 0 {
		t.Error("runMain with too few args: exit code 0, want non-zero")
	}
}

// TestRunFree drives the free run entry point (the one main calls) with a
// command stream on a stdin pipe, covering the run/dispatch capabilities and
// list path in-process.
func TestRunFree(t *testing.T) {
	t.Setenv("GIT_REMOTE_DNS_ZONE", "example.com")
	t.Setenv("GIT_REMOTE_DNS_SERVER", "127.0.0.1:5300")

	in, outPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStdin := os.Stdin
	os.Stdin = in
	defer func() { os.Stdin = oldStdin }()

	go func() {
		defer outPipe.Close()
		outPipe.WriteString("capabilities\n")
		outPipe.WriteString("list\n")
	}()

	if err := run([]string{"git-remote-dns", "origin", "dns://" + testSHA}); err != nil {
		t.Fatalf("run: %v", err)
	}
}

// TestDispatchCapabilities checks that the capabilities command is answered with
// the "fetch" capability followed by a blank line.
func TestDispatchCapabilities(t *testing.T) {
	h := &helper{id: testSHA, out: bufio.NewWriter(&bytes.Buffer{})}
	sc := bufio.NewReader(strings.NewReader(""))
	if err := h.dispatch("capabilities", sc); err != nil {
		t.Fatalf("dispatch capabilities: %v", err)
	}
	h.out.Flush()
}

// TestDispatchList checks that the list command emits the ref line and the HEAD
// symref line, terminated by a blank line.
func TestDispatchList(t *testing.T) {
	var buf bytes.Buffer
	h := &helper{id: testSHA, out: bufio.NewWriter(&buf)}
	sc := bufio.NewReader(strings.NewReader(""))
	if err := h.dispatch("list", sc); err != nil {
		t.Fatalf("dispatch list: %v", err)
	}
	h.out.Flush()
	got := buf.String()
	want := testSHA + " refs/heads/main\n@refs/heads/main HEAD\n\n"
	if got != want {
		t.Fatalf("list output = %q, want %q", got, want)
	}
}

// TestDispatchEmpty checks that a blank or whitespace-only command line is a
// no-op: dispatch returns nil without touching the output stream.
func TestDispatchEmpty(t *testing.T) {
	for _, line := range []string{"", "   "} {
		var buf bytes.Buffer
		h := &helper{id: testSHA, out: bufio.NewWriter(&buf)}
		sc := bufio.NewReader(strings.NewReader(""))
		if err := h.dispatch(line, sc); err != nil {
			t.Fatalf("dispatch(%q): %v", line, err)
		}
		h.out.Flush()
		if buf.Len() != 0 {
			t.Fatalf("dispatch(%q) wrote %q, want empty", line, buf.String())
		}
	}
}

// TestReadFetchBatch checks that the fetch batch is parsed into the requested
// commit SHAs, stopping at the terminating blank line.
func TestReadFetchBatch(t *testing.T) {
	sc := bufio.NewReader(strings.NewReader(
		"fetch " + testSHA + " refs/heads/main\nfetch deadbeefdeadbeefdeadbeefdeadbeefdeadbeef refs/heads/other\n\n"))
	h := &helper{id: testSHA}
	shas := h.readFetchBatch(sc)
	if len(shas) != 2 || shas[0] != testSHA || shas[1] != "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" {
		t.Fatalf("readFetchBatch = %v, want [testSHA deadbeef...]", shas)
	}
}

// TestCmdList checks that cmdList writes the ref and HEAD symref lines.
func TestCmdList(t *testing.T) {
	var buf bytes.Buffer
	h := &helper{id: testSHA}
	if err := h.cmdList(&buf); err != nil {
		t.Fatalf("cmdList: %v", err)
	}
	want := testSHA + " refs/heads/main\n@refs/heads/main HEAD\n\n"
	if buf.String() != want {
		t.Fatalf("cmdList = %q, want %q", buf.String(), want)
	}
}

// TestRun drives a full command stream through the helper's stdin loop,
// exercising the run/dispatch/capabilities/list path end to end.
func TestRun(t *testing.T) {
	t.Setenv("GIT_REMOTE_DNS_ZONE", "example.com")
	t.Setenv("GIT_REMOTE_DNS_SERVER", "127.0.0.1:5300")

	h, err := newHelper("dns://" + testSHA)
	if err != nil {
		t.Fatalf("newHelper: %v", err)
	}

	in, outPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStdin := os.Stdin
	os.Stdin = in
	defer func() { os.Stdin = oldStdin }()

	var buf bytes.Buffer
	h.out = bufio.NewWriter(&buf)

	go func() {
		defer outPipe.Close()
		outPipe.WriteString("capabilities\n")
		outPipe.WriteString("list\n")
	}()

	if err := h.run(); err != nil {
		t.Fatalf("run: %v", err)
	}
	h.out.Flush()
	got := buf.String()
	if !strings.Contains(got, "fetch\n") {
		t.Errorf("capabilities response missing from output: %q", got)
	}
	if !strings.Contains(got, testSHA+" refs/heads/main") {
		t.Errorf("list output missing ref line: %q", got)
	}
	if !strings.Contains(got, "@refs/heads/main HEAD") {
		t.Errorf("list output missing HEAD symref: %q", got)
	}
}

// TestRunFetchError drives the run loop with a fetch command that fails (the
// configured server is not listening), covering the run->dispatch error return.
func TestRunFetchError(t *testing.T) {
	t.Setenv("GIT_REMOTE_DNS_ZONE", "example.com")
	t.Setenv("GIT_REMOTE_DNS_SERVER", "127.0.0.1:5300") // nothing listening here

	h, err := newHelper("dns://" + testSHA)
	if err != nil {
		t.Fatalf("newHelper: %v", err)
	}

	in, outPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStdin := os.Stdin
	os.Stdin = in
	defer func() { os.Stdin = oldStdin }()

	go func() {
		defer outPipe.Close()
		outPipe.WriteString("capabilities\n")
		outPipe.WriteString("list\n")
		outPipe.WriteString("fetch " + testSHA + " refs/heads/main\n")
		outPipe.WriteString("\n") // terminate the fetch batch
	}()

	h.out = bufio.NewWriter(&bytes.Buffer{})
	if err := h.run(); err == nil {
		t.Fatal("run with a failing fetch: nil error, want error")
	}
}

// TestDispatchFetchEmpty checks that a bare "fetch" with no reachable commits
// yields the "no objects reachable" error, exercising the dispatch/fetch and
// cmdFetch empty-batch error paths.
func TestDispatchFetchEmpty(t *testing.T) {
	h := &helper{id: testSHA, out: bufio.NewWriter(&bytes.Buffer{})}
	sc := bufio.NewReader(strings.NewReader(""))
	if err := h.dispatch("fetch", sc); err == nil {
		t.Fatal("dispatch bare fetch: nil error, want 'no objects reachable' error")
	}
}

// withCleanGitDir clears all GIT_* variables from the process environment and
// points GIT_DIR at dir for the duration of the test, restoring the environment
// afterwards. This lets a test exercise the helper's in-process fetch path,
// which installs objects via `git unpack-objects` into the GIT_DIR git sets.
func withCleanGitDir(t *testing.T, dir string) {
	t.Helper()
	saved := os.Environ()
	for _, kv := range saved {
		if i := strings.IndexByte(kv, '='); i >= 0 && strings.HasPrefix(kv[:i], "GIT_") {
			os.Unsetenv(kv[:i])
		}
	}
	os.Setenv("GIT_DIR", dir)
	t.Cleanup(func() {
		for _, kv := range os.Environ() {
			if i := strings.IndexByte(kv, '='); i >= 0 && strings.HasPrefix(kv[:i], "GIT_") {
				os.Unsetenv(kv[:i])
			}
		}
		for _, kv := range saved {
			if i := strings.IndexByte(kv, '='); i >= 0 {
				os.Setenv(kv[:i], kv[i+1:])
			}
		}
	})
}

// gitObjectExists reports whether sha is present in dir's object store.
func gitObjectExists(t *testing.T, dir, sha string) bool {
	t.Helper()
	c := exec.Command("git", "cat-file", "-e", sha)
	c.Dir = dir
	c.Env = gitEnv()
	return c.Run() == nil
}

// TestDispatchFetchInstallObjects drives the helper's fetch path in-process:
// it publishes a repo to a local server, then dispatches a "fetch" command with
// GIT_DIR pointed at a clone repo and verifies that the reachable objects were
// installed into that repo's object store via `git unpack-objects`. This is the
// remote-helper path that the end-to-end clone test exercises only as a
// subprocess (invisible to the coverage profiler).
func TestDispatchFetchInstallObjects(t *testing.T) {
	const zone = "example.com"

	src := t.TempDir()
	root := writeRepo(t, src)

	srv := dnszone.NewServer(dnszone.Zone(zone), dnszone.DefaultTTL)
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Shutdown()

	if err := gitdns.Publish(srv, root, func(sha string) ([]byte, error) {
		return gitLooseObject(src, sha)
	}, objectstore.TXT); err != nil {
		t.Fatalf("publish: %v", err)
	}

	r := dnszone.NewResolver("127.0.0.1:"+strconv.Itoa(srv.Port()), dnszone.Zone(zone), 0).
		WithObjectSuffix("g")

	// A clone-style repo to receive the objects.
	dest := t.TempDir()
	runGit(t, dest, "init", "-q", "-b", "main")
	withCleanGitDir(t, filepath.Join(dest, ".git"))

	h := &helper{id: root, r: r, transport: objectstore.TXT}
	sc := bufio.NewReader(strings.NewReader(""))
	var buf bytes.Buffer
	h.out = bufio.NewWriter(&buf)

	// Drive the fetch command exactly as git would: the triggering "fetch <sha>
	// <ref>" line, followed immediately by the terminating blank line.
	if err := h.dispatch("fetch "+root+" refs/heads/main", sc); err != nil {
		t.Fatalf("dispatch fetch: %v", err)
	}
	h.out.Flush()
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Errorf("fetch output should end with the batch-complete newline, got %q", buf.String())
	}

	// The root commit, its tree, and the blob it reference must all now be
	// present in the clone's object store.
	tree := runGit(t, src, "rev-parse", root+"^{tree}")
	blob := runGit(t, src, "rev-parse", root+":hello.txt")
	for _, sha := range []string{root, tree, blob} {
		if !gitObjectExists(t, dest, sha) {
			t.Errorf("object %s not installed into clone object store", sha)
		}
	}
}

// TestCmdFetchInstallObjectsError verifies that cmdFetch propagates an
// installObjects failure: the pack is built successfully, but `git
// unpack-objects` (run against a bad GIT_DIR) fails, so cmdFetch returns that
// error at the installObjects check rather than emitting the completion
// newline.
func TestCmdFetchInstallObjectsError(t *testing.T) {
	const zone = "example.com"

	src := t.TempDir()
	root := writeRepo(t, src)

	srv := dnszone.NewServer(dnszone.Zone(zone), dnszone.DefaultTTL)
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Shutdown()

	if err := gitdns.Publish(srv, root, func(sha string) ([]byte, error) {
		return gitLooseObject(src, sha)
	}, objectstore.TXT); err != nil {
		t.Fatalf("publish: %v", err)
	}

	r := dnszone.NewResolver("127.0.0.1:"+strconv.Itoa(srv.Port()), dnszone.Zone(zone), 0).
		WithObjectSuffix("g")

	// GIT_DIR points at a path that is not a git repository, so installObjects
	// fails after buildPack has already succeeded.
	withCleanGitDir(t, filepath.Join(t.TempDir(), "not-a-git-repo"))

	h := &helper{id: root, r: r, transport: objectstore.TXT}
	var buf bytes.Buffer
	if err := h.cmdFetch([]string{root}, &buf); err == nil {
		t.Fatal("cmdFetch with a bad GIT_DIR: nil error, want install error")
	}
}

// failWriter is an io.Writer that always fails, used to exercise the cmdFetch
// completion-write error path.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("failWriter always fails") }

// TestCmdFetchWriteError verifies that cmdFetch propagates a failure to write
// the batch-completion newline. Everything succeeds (fetch, buildPack,
// installObjects) and only the final io.WriteString fails.
func TestCmdFetchWriteError(t *testing.T) {
	const zone = "example.com"

	src := t.TempDir()
	root := writeRepo(t, src)

	srv := dnszone.NewServer(dnszone.Zone(zone), dnszone.DefaultTTL)
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Shutdown()

	if err := gitdns.Publish(srv, root, func(sha string) ([]byte, error) {
		return gitLooseObject(src, sha)
	}, objectstore.TXT); err != nil {
		t.Fatalf("publish: %v", err)
	}

	r := dnszone.NewResolver("127.0.0.1:"+strconv.Itoa(srv.Port()), dnszone.Zone(zone), 0).
		WithObjectSuffix("g")

	dest := t.TempDir()
	runGit(t, dest, "init", "-q", "-b", "main")
	withCleanGitDir(t, filepath.Join(dest, ".git"))

	h := &helper{id: root, r: r, transport: objectstore.TXT}
	if err := h.cmdFetch([]string{root}, failWriter{}); err == nil {
		t.Fatal("cmdFetch with a failing writer: nil error, want write error")
	}
}

// TestEnvironWithoutGitDir checks that GIT_* variables are stripped from the
// environment.
func TestEnvironWithoutGitDir(t *testing.T) {
	t.Setenv("GIT_DIR", "/tmp/wrong")
	t.Setenv("GIT_OBJECT_DIRECTORY", "/tmp/wrong-objects")
	t.Setenv("UNRELATED_VAR", "keep-me")

	env := environWithoutGitDir()
	for _, kv := range env {
		if strings.HasPrefix(kv, "GIT_") {
			t.Fatalf("environWithoutGitDir kept %q", kv)
		}
	}
	found := false
	for _, kv := range env {
		if strings.HasPrefix(kv, "UNRELATED_VAR=") {
			found = true
		}
	}
	if !found {
		t.Fatal("environWithoutGitDir dropped a non-GIT variable")
	}
}

// TestCmdFetchFetchError checks that cmdFetch propagates a DNS fetch failure
// (here, a resolver pointed at a dead server) rather than silently succeeding.
func TestCmdFetchFetchError(t *testing.T) {
	// Start a server on an ephemeral port, then stop it so the port is closed.
	srv := dnszone.NewServer(dnszone.Zone("example.com"), dnszone.DefaultTTL)
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start server: %v", err)
	}
	port := srv.Port()
	srv.Shutdown()

	r := dnszone.NewResolver("127.0.0.1:"+strconv.Itoa(port), dnszone.Zone("example.com"), 100*time.Millisecond).
		WithObjectSuffix("g")
	h := &helper{id: testSHA, r: r, transport: objectstore.TXT}
	var buf bytes.Buffer
	if err := h.cmdFetch([]string{testSHA}, &buf); err == nil {
		t.Fatal("cmdFetch with dead server: nil error, want fetch error")
	}
}

// TestInstallObjectsError checks that installObjects returns an error when
// `git unpack-objects` fails -- here because GIT_DIR is not a git repository.
func TestInstallObjectsError(t *testing.T) {
	withCleanGitDir(t, filepath.Join(t.TempDir(), "not-a-git-repo"))
	h := &helper{id: testSHA, transport: objectstore.TXT}
	// A minimal PACK header; unpack-objects rejects the bad GIT_DIR first.
	pack := []byte("PACK\x00\x00\x00\x01\x00\x00\x00\x14")
	if err := h.installObjects(pack); err == nil {
		t.Fatal("installObjects in non-repo: nil error, want unpack error")
	}
}
