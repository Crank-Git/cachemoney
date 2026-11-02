package main

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Crank-Git/cachemoney/pkg/dnszone"
	"github.com/Crank-Git/cachemoney/pkg/gitdns"
)

// startServeGitProcess runs the cachemoney binary's serve-git and returns the
// port it reports.
func startServeGitProcess(t *testing.T, cm string, args ...string) int {
	t.Helper()
	serve := exec.Command(cm, append([]string{"serve-git"}, args...)...)
	stdout, err := serve.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	serve.Stderr = &stderr
	if err := serve.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serve.Process.Kill(); _ = serve.Wait() })
	lines := bufio.NewScanner(stdout)
	if !lines.Scan() {
		t.Fatalf("serve-git printed nothing; stderr: %s", stderr.String())
	}
	m := regexp.MustCompile(`\(port (\d+)\)`).FindStringSubmatch(lines.Text())
	if m == nil {
		t.Fatalf("no port in %q", lines.Text())
	}
	go func() {
		for lines.Scan() {
		}
	}()
	port, _ := strconv.Atoi(m[1])
	return port
}

// waitForRef polls the served refs until name points at sha.
func waitForRef(t *testing.T, port int, tr, name, sha string) {
	t.Helper()
	trv, _ := parseTransport(tr)
	res := dnszone.NewResolver("127.0.0.1:"+strconv.Itoa(port), dnszone.Zone("example.com"), time.Second)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if refs, err := gitdns.FetchRefs(res, "demo", trv); err == nil {
			if got, ok := refs.Lookup(name); ok && got == sha || !ok && sha == "" {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s never reached %q", name, sha)
}

// TestCloneByNameAndPull is the refs workflow end to end with the real
// binaries: serve-git publishes a repository by name, `git clone dns://demo`
// gets every branch and tag with HEAD on main, then upstream commits,
// branches, and deletions reach the clone through the refresh and
// `git pull` / `git fetch --prune`, fetching only new objects.
func TestCloneByNameAndPull(t *testing.T) {
	bin := t.TempDir()
	cm := buildInto(t, ".", bin, "cachemoney")
	buildInto(t, "../git-remote-dns", bin, "git-remote-dns")

	for _, tr := range []string{"txt", "aaaa"} {
		t.Run(tr, func(t *testing.T) {
			src := t.TempDir()
			git(t, src, "init", "-q", "-b", "main")
			write := func(name, content string) {
				if err := os.WriteFile(filepath.Join(src, name), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			write("a.txt", "a\n")
			write("big.bin", strings.Repeat("0123456789abcdef", 20_000))
			git(t, src, "add", "-A")
			git(t, src, "commit", "-q", "-m", "one")
			git(t, src, "tag", "-a", "v1", "-m", "release v1")
			git(t, src, "tag", "light")
			git(t, src, "checkout", "-q", "-b", "dev")
			write("dev.txt", "dev\n")
			git(t, src, "add", "dev.txt")
			git(t, src, "commit", "-q", "-m", "dev work")
			git(t, src, "checkout", "-q", "main")

			port := startServeGitProcess(t, cm, "-repo", src, "-name", "demo", "-addr", "127.0.0.1:0", "-tr", tr, "-refresh", "200ms")
			env := append(os.Environ(),
				"GIT_REMOTE_DNS_ZONE=example.com",
				"GIT_REMOTE_DNS_SERVER=127.0.0.1:"+strconv.Itoa(port),
				"GIT_REMOTE_DNS_TRANSPORT="+tr,
				"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
				"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
				"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
			)
			gitIn := func(dir string, extraEnv []string, args ...string) string {
				t.Helper()
				cmd := exec.Command("git", args...)
				cmd.Dir = dir
				cmd.Env = append(append([]string{}, env...), extraEnv...)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
				}
				return strings.TrimSpace(string(out))
			}

			parent := t.TempDir()
			gitIn(parent, nil, "clone", "-q", "dns://demo", "clone")
			dest := filepath.Join(parent, "clone")

			if got := git(t, dest, "symbolic-ref", "HEAD"); got != "refs/heads/main" {
				t.Fatalf("HEAD = %s", got)
			}
			if a, b := git(t, src, "rev-parse", "main"), git(t, dest, "rev-parse", "HEAD"); a != b {
				t.Fatalf("HEAD %s, want main %s", b, a)
			}
			if a, b := git(t, src, "rev-parse", "dev"), git(t, dest, "rev-parse", "origin/dev"); a != b {
				t.Fatalf("origin/dev %s, want %s", b, a)
			}
			if got := git(t, dest, "tag"); got != "light\nv1" {
				t.Fatalf("tags %q", got)
			}
			if got := git(t, dest, "cat-file", "-t", "v1"); got != "tag" {
				t.Fatalf("v1 is a %s, want an annotated tag", got)
			}
			if a, b := git(t, src, "rev-parse", "v1"), git(t, dest, "rev-parse", "v1"); a != b {
				t.Fatalf("v1 tag object %s, want %s", b, a)
			}
			git(t, dest, "fsck", "--full", "--no-dangling")

			// Upstream moves main; after the refresh, pull fetches only the
			// new commit, its tree, and the changed blob.
			write("a.txt", "a, edited\n")
			git(t, src, "commit", "-q", "-am", "two")
			newMain := git(t, src, "rev-parse", "main")
			waitForRef(t, port, tr, "refs/heads/main", newMain)
			out := gitIn(dest, []string{"GIT_REMOTE_DNS_TRACE=1"}, "pull", "-q", "--ff-only")
			if got := git(t, dest, "rev-parse", "HEAD"); got != newMain {
				t.Fatalf("after pull HEAD %s, want %s", got, newMain)
			}
			if !strings.Contains(out, ">> fetched 3 objects") {
				t.Fatalf("pull did not fetch exactly the 3 new objects:\n%s", out)
			}

			// Nothing new: the fetch succeeds and downloads nothing.
			out = gitIn(dest, []string{"GIT_REMOTE_DNS_TRACE=1"}, "fetch", "-q")
			if strings.Contains(out, ">> fetched") && !strings.Contains(out, ">> fetched 0 objects") {
				t.Fatalf("no-op fetch downloaded objects:\n%s", out)
			}

			// A new branch appears and a deleted one is pruned. The two
			// changes are separate git commands, so a refresh can publish
			// one without the other: wait for both.
			git(t, src, "branch", "-D", "dev")
			git(t, src, "branch", "feature")
			waitForRef(t, port, tr, "refs/heads/dev", "")
			waitForRef(t, port, tr, "refs/heads/feature", git(t, src, "rev-parse", "feature"))
			gitIn(dest, nil, "fetch", "-q", "--prune")
			remotes := git(t, dest, "for-each-ref", "--format=%(refname)", "refs/remotes/origin")
			if !strings.Contains(remotes, "refs/remotes/origin/feature") || strings.Contains(remotes, "refs/remotes/origin/dev") {
				t.Fatalf("remote branches after fetch --prune:\n%s", remotes)
			}
			git(t, dest, "fsck", "--full", "--no-dangling")
		})
	}
}
