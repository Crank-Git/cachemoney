package main

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Crank-Git/cachemoney/pkg/dnszone"
	"github.com/Crank-Git/cachemoney/pkg/gitdns"
	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// runGit runs a git command in dir and returns its trimmed stdout, failing the
// test on error. It pins author/committer identity and date so commits are
// reproducible.
func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// gitEnv pins identity/date env vars for reproducible commits.
func gitEnv() []string {
	return append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_AUTHOR_DATE=2020-01-01T00:00:00 +0000",
		"GIT_COMMITTER_DATE=2020-01-01T00:00:00 +0000",
	)
}

// writeRepo creates a source git repo in dir with a couple of commits and
// returns the root commit SHA-1.
func writeRepo(t *testing.T, dir string) string {
	t.Helper()
	runGit(t, dir, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello world\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "nested.txt"), []byte("nested file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "-A")
	runGit(t, dir, "commit", "-q", "-m", "initial commit")
	runGit(t, dir, "commit", "--allow-empty", "-q", "-m", "second commit")
	return runGit(t, dir, "rev-parse", "HEAD")
}

// gitLooseObject reads and zlib-decompresses a loose git object from a repo's
// object store, returning its raw canonical bytes. Fresh repositories store
// objects loose; packed repos would need git cat-file instead.
func gitLooseObject(dir, sha string) ([]byte, error) {
	p := filepath.Join(dir, ".git", "objects", sha[:2], sha[2:])
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

// buildHelper compiles the git-remote-dns binary into a private bin dir and
// returns its path.
func buildHelper(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	helper := filepath.Join(binDir, "git-remote-dns")
	build := exec.Command("go", "build", "-o", helper, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build helper: %v", err)
	}
	return helper
}

// TestGitRemoteDNSClone is an end-to-end test: it publishes a real git repo's
// objects to a local authoritative server, then runs `git clone dns:<sha>`
// against a freshly built git-remote-dns helper and verifies the clone matches
// the source.
func TestGitRemoteDNSClone(t *testing.T) {
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

	helper := buildHelper(t)
	dest := filepath.Join(t.TempDir(), "clone")
	cmd := exec.Command("git", "clone", fmt.Sprintf("dns://%s", root), dest)
	cmd.Env = append(os.Environ(),
		"GIT_REMOTE_DNS_SERVER=127.0.0.1:"+strconv.Itoa(srv.Port()),
		"GIT_REMOTE_DNS_ZONE="+zone,
		"GIT_REMOTE_DNS_TRANSPORT=txt",
		"PATH="+filepath.Dir(helper)+":"+os.Getenv("PATH"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git clone: %v\n%s", err, out)
	}

	// The clone must check out refs/heads/main (HEAD is a symref, not detached).
	if got := runGit(t, dest, "symbolic-ref", "HEAD"); got != "refs/heads/main" {
		t.Fatalf("HEAD symref = %q, want refs/heads/main", got)
	}
	if got := runGit(t, dest, "rev-parse", "HEAD"); got != root {
		t.Fatalf("clone HEAD = %s, want %s", got, root)
	}
	// The cloned tree must match the source tree.
	if a, b := runGit(t, src, "ls-tree", "-r", "HEAD"), runGit(t, dest, "ls-tree", "-r", "HEAD"); a != b {
		t.Fatalf("tree mismatch\n source: %s\n clone:  %s", a, b)
	}
}

// TestGitRemoteDNSPackValidates that the packfile the helper produces is a
// well-formed pack git accepts, by verifying it with git verify-pack.
func TestGitRemoteDNSPackValidates(t *testing.T) {
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
	objs, err := gitdns.Fetch(r, root, objectstore.TXT)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	h := &helper{id: root, r: r, transport: objectstore.TXT}
	pack, err := h.buildPack(objs)
	if err != nil {
		t.Fatalf("buildPack: %v", err)
	}
	if len(pack) < 12 || string(pack[:4]) != "PACK" {
		t.Fatalf("pack does not start with PACK magic: %v", pack[:min(12, len(pack))])
	}

	packPath := filepath.Join(t.TempDir(), "pack.pack")
	if err := os.WriteFile(packPath, pack, 0o644); err != nil {
		t.Fatal(err)
	}
	// git verify-pack needs the accompanying .idx; generate it with index-pack.
	if err := exec.Command("git", "index-pack", packPath).Run(); err != nil {
		t.Fatalf("git index-pack: %v", err)
	}
	vp := exec.Command("git", "verify-pack", "-v", packPath)
	out, err := vp.CombinedOutput()
	if err != nil {
		t.Fatalf("git verify-pack: %v\n%s", err, out)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestGitRemoteDNSCloneWithSubmodule clones, over DNS, a real repository whose
// tree records a submodule. The superproject clone must succeed and keep the
// gitlink entry; the submodule's own commit is not fetched.
func TestGitRemoteDNSCloneWithSubmodule(t *testing.T) {
	const zone = "example.com"
	src := t.TempDir()
	runGit(t, src, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(src, "app.txt"), []byte("app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".gitmodules"), []byte("[submodule \"lib\"]\n\tpath = lib\n\turl = https://example.com/lib.git\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, src, "add", "app.txt", ".gitmodules")
	const link = "4444444444444444444444444444444444444444"
	runGit(t, src, "update-index", "--add", "--cacheinfo", "160000,"+link+",lib")
	runGit(t, src, "commit", "-q", "-m", "add submodule")
	root := runGit(t, src, "rev-parse", "HEAD")

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

	helper := buildHelper(t)
	dest := filepath.Join(t.TempDir(), "clone")
	cmd := exec.Command("git", "clone", "dns://"+root, dest)
	cmd.Env = append(os.Environ(),
		"GIT_REMOTE_DNS_SERVER=127.0.0.1:"+strconv.Itoa(srv.Port()),
		"GIT_REMOTE_DNS_ZONE="+zone,
		"PATH="+filepath.Dir(helper)+":"+os.Getenv("PATH"),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git clone: %v\n%s", err, out)
	}
	if got := runGit(t, dest, "rev-parse", "HEAD"); got != root {
		t.Fatalf("clone HEAD = %s, want %s", got, root)
	}
	if got := runGit(t, dest, "ls-tree", "HEAD", "lib"); !strings.HasPrefix(got, "160000 commit "+link) {
		t.Fatalf("gitlink entry = %q, want 160000 commit %s", got, link)
	}
	if a, b := runGit(t, src, "ls-tree", "-r", "HEAD"), runGit(t, dest, "ls-tree", "-r", "HEAD"); a != b {
		t.Fatalf("tree mismatch\n source: %s\n clone:  %s", a, b)
	}
	runGit(t, dest, "fsck", "--no-dangling")
}
