package main

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// git runs a git command in dir with a pinned identity and returns stdout.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_AUTHOR_DATE=2020-01-01T00:00:00 +0000",
		"GIT_COMMITTER_DATE=2020-01-01T00:00:00 +0000",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// buildInto compiles the package at pkgDir into dir/name.
func buildInto(t *testing.T, pkgDir, dir, name string) string {
	t.Helper()
	out := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", out, pkgDir)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkgDir, err, b)
	}
	return out
}

// sourceRepo builds a repository whose history is mostly packed (after
// `git gc`) with one loose commit on top. It holds a nested directory, an
// executable, a symlink, and a 200 KB binary file, so serving it exercises
// packed and loose objects, every tree entry mode, and multi-chunk blobs.
func sourceRepo(t *testing.T) string {
	t.Helper()
	src := t.TempDir()
	git(t, src, "init", "-q", "-b", "main")
	write := func(name string, data []byte, mode os.FileMode) {
		p := filepath.Join(src, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, mode); err != nil {
			t.Fatal(err)
		}
	}
	big := make([]byte, 200_000)
	for i := range big {
		big[i] = byte(i*17 + i/389)
	}
	write("README.md", []byte("# demo\n"), 0o644)
	write("src/lib/a.go", []byte("package lib\n"), 0o644)
	write("bin/run.sh", []byte("#!/bin/sh\necho hi\n"), 0o755)
	write("assets/blob.bin", big, 0o644)
	if err := os.Symlink("README.md", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	git(t, src, "add", "-A")
	git(t, src, "commit", "-q", "-m", "first")
	for i := 0; i < 5; i++ {
		write("src/lib/a.go", []byte("package lib\n// rev "+string(rune('a'+i))+"\n"), 0o644)
		git(t, src, "commit", "-q", "-am", "edit "+string(rune('a'+i)))
	}
	git(t, src, "gc", "-q", "--aggressive")
	write("NEW.txt", []byte("loose object after gc\n"), 0o644)
	git(t, src, "add", "NEW.txt")
	git(t, src, "commit", "-q", "-m", "loose commit")
	if packed := git(t, src, "count-objects", "-v"); !strings.Contains(packed, "in-pack: ") || strings.Contains(packed, "in-pack: 0\n") {
		t.Fatalf("source repo has no packed objects:\n%s", packed)
	}
	return src
}

// TestServeGitCloneEndToEnd runs the real binaries the way a user would:
// `cachemoney serve-git` on a repository with packed history, then
// `git clone dns://<sha>` through git-remote-dns, over both transports. The
// clone must reproduce the full history and working tree, and serve-git
// must exit cleanly on SIGINT.
func TestServeGitCloneEndToEnd(t *testing.T) {
	src := sourceRepo(t)
	bin := t.TempDir()
	cm := buildInto(t, ".", bin, "cachemoney")
	buildInto(t, "../git-remote-dns", bin, "git-remote-dns")
	head := git(t, src, "rev-parse", "HEAD")

	for _, tr := range []string{"txt", "aaaa"} {
		t.Run(tr, func(t *testing.T) {
			serve := exec.Command(cm, "serve-git", "-repo", src, "-name", "demo", "-addr", "127.0.0.1:0", "-zone", "repo.example.org", "-tr", tr)
			stdout, err := serve.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			serve.Stderr = &stderr
			if err := serve.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			defer func() {
				if serve.ProcessState == nil {
					_ = serve.Process.Kill()
				}
			}()

			// The first line names the commit and port; the next shows the
			// clone command.
			lines := bufio.NewScanner(stdout)
			var banner []string
			for len(banner) < 3 && lines.Scan() {
				banner = append(banner, lines.Text())
			}
			go func() {
				for lines.Scan() {
				}
				done <- serve.Wait()
			}()
			if len(banner) < 3 {
				t.Fatalf("serve-git output %q, stderr %s", banner, stderr.String())
			}
			m := regexp.MustCompile(`as demo \(\d+ refs, HEAD ([0-9a-f]{40})\) .*\(port (\d+)\)`).FindStringSubmatch(banner[0])
			if m == nil || m[1] != head {
				t.Fatalf("banner %q does not name HEAD %s", banner[0], head)
			}
			if !strings.Contains(banner[2], "git clone dns://demo") || !strings.Contains(banner[2], "GIT_REMOTE_DNS_SERVER=127.0.0.1:"+m[2]) {
				t.Fatalf("clone hint %q", banner[2])
			}

			dest := filepath.Join(t.TempDir(), "clone")
			clone := exec.Command("git", "clone", "-q", "dns://"+head, dest)
			clone.Env = append(os.Environ(),
				"GIT_REMOTE_DNS_ZONE=repo.example.org",
				"GIT_REMOTE_DNS_SERVER=127.0.0.1:"+m[2],
				"GIT_REMOTE_DNS_TRANSPORT="+tr,
				"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
			)
			if out, err := clone.CombinedOutput(); err != nil {
				t.Fatalf("git clone: %v\n%s", err, out)
			}

			if a, b := git(t, src, "log", "--format=%H %s"), git(t, dest, "log", "--format=%H %s"); a != b {
				t.Fatalf("history differs\nsource:\n%s\nclone:\n%s", a, b)
			}
			if a, b := git(t, src, "ls-tree", "-r", "HEAD"), git(t, dest, "ls-tree", "-r", "HEAD"); a != b {
				t.Fatalf("tree differs\nsource:\n%s\nclone:\n%s", a, b)
			}
			for _, f := range []string{"assets/blob.bin", "bin/run.sh", "NEW.txt", "src/lib/a.go"} {
				want, _ := os.ReadFile(filepath.Join(src, f))
				got, err := os.ReadFile(filepath.Join(dest, f))
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("%s differs in the clone", f)
				}
			}
			if target, err := os.Readlink(filepath.Join(dest, "link")); err != nil || target != "README.md" {
				t.Fatalf("symlink = %q, %v", target, err)
			}
			if fi, err := os.Stat(filepath.Join(dest, "bin/run.sh")); err != nil || fi.Mode()&0o111 == 0 {
				t.Fatal("executable bit lost")
			}
			git(t, dest, "fsck", "--full", "--no-dangling")

			if err := serve.Process.Signal(syscall.SIGINT); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("serve-git exited with %v after SIGINT; stderr: %s", err, stderr.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("serve-git did not exit on SIGINT")
			}
		})
	}
}

// TestServeGitErrors checks serve-git fails cleanly on bad input instead of
// serving nothing.
func TestServeGitErrors(t *testing.T) {
	src := t.TempDir()
	git(t, src, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(src, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, src, "add", "f")
	git(t, src, "commit", "-q", "-m", "one")
	empty := t.TempDir()
	git(t, empty, "init", "-q")

	const ephemeral = "127.0.0.1:0"
	cases := map[string][]string{
		"not a repository": {"-addr", ephemeral, "-repo", t.TempDir(), "-name", "x"},
		"no refs":          {"-addr", ephemeral, "-repo", empty, "-name", "x"},
		"invalid name":     {"-addr", ephemeral, "-repo", src, "-name", "Bad_Name"},
		"sha-like name":    {"-addr", ephemeral, "-repo", src, "-name", strings.Repeat("ab", 20)},
		"bad transport":    {"-addr", ephemeral, "-repo", src, "-tr", "smtp"},
		"bad address":      {"-addr", "127.0.0.1:notaport", "-repo", src},
		"unknown flag":     {"-addr", ephemeral, "-repo", src, "-bogus"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			g, err := startGitServer(args)
			if err == nil {
				g.srv.Shutdown()
				t.Fatal("startGitServer succeeded")
			}
		})
	}
}

// TestCatFileReadsPackedAndLoose reads every object of a gc'd repository
// through catFile and checks each one hashes to its id.
func TestCatFileReadsPackedAndLoose(t *testing.T) {
	src := sourceRepo(t)
	cf, err := openCatFile(src)
	if err != nil {
		t.Fatal(err)
	}
	defer cf.Close()
	ids := strings.Fields(git(t, src, "rev-list", "--objects", "--no-object-names", "--all"))
	if len(ids) < 20 {
		t.Fatalf("only %d objects", len(ids))
	}
	for _, id := range ids {
		raw, err := cf.read(id)
		if err != nil {
			t.Fatalf("read %s: %v", id, err)
		}
		hash := exec.Command("git", "hash-object", "--stdin", "-t", strings.SplitN(string(raw), " ", 2)[0])
		hash.Stdin = bytes.NewReader(raw[bytes.IndexByte(raw, 0)+1:])
		out, err := hash.Output()
		if err != nil || strings.TrimSpace(string(out)) != id {
			t.Fatalf("object %s re-hashes to %s", id, out)
		}
	}
	if _, err := cf.read(strings.Repeat("0", 40)); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing object: err=%v", err)
	}
	if _, err := cf.read("not-a-sha\nHEAD"); err == nil {
		t.Fatal("cat-file accepted a non-SHA object id")
	}
}
