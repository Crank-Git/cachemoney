package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/dnszone"
	"github.com/Crank-Git/cachemoney/pkg/gitdns"
	"github.com/Crank-Git/cachemoney/pkg/gitobj"
	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// refsRepo makes a repository with two branches, an annotated tag, and a
// lightweight tag, with HEAD on main.
func refsRepo(t *testing.T) string {
	t.Helper()
	src := t.TempDir()
	git(t, src, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(src, "f"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, src, "add", "f")
	git(t, src, "commit", "-q", "-m", "one")
	git(t, src, "tag", "-a", "v1", "-m", "release v1")
	git(t, src, "tag", "light")
	git(t, src, "branch", "dev")
	return src
}

// TestReadRefs checks branches, both kinds of tags, and a symbolic HEAD are
// read as git reports them, and a detached HEAD becomes a HEAD ref.
func TestReadRefs(t *testing.T) {
	src := refsRepo(t)
	refs, err := readRefs(src)
	if err != nil {
		t.Fatal(err)
	}
	want := git(t, src, "for-each-ref", "--format=%(objectname) %(refname)", "refs/heads", "refs/tags")
	got := strings.TrimSpace(strings.TrimPrefix(string(refs.Marshal()), "@refs/heads/main HEAD\n"))
	if got != want {
		t.Fatalf("refs\n%s\nwant\n%s", got, want)
	}
	if refs.Head != "refs/heads/main" {
		t.Fatalf("HEAD = %q", refs.Head)
	}
	tagSHA, _ := refs.Lookup("refs/tags/v1")
	if tagSHA != git(t, src, "rev-parse", "v1") || tagSHA == git(t, src, "rev-parse", "v1^{commit}") {
		t.Fatal("annotated tag must point at the tag object, not its commit")
	}

	git(t, src, "checkout", "-q", "--detach", "HEAD")
	refs, err = readRefs(src)
	if err != nil {
		t.Fatal(err)
	}
	if sha, ok := refs.Lookup("HEAD"); refs.Head != "" || !ok || sha != git(t, src, "rev-parse", "HEAD") {
		t.Fatalf("detached HEAD read as head=%q HEAD ref %q", refs.Head, sha)
	}
}

// TestDefaultRepoName checks directory names are mapped to a valid label.
func TestDefaultRepoName(t *testing.T) {
	cases := map[string]string{
		"cachemoney":            "cachemoney",
		"My_Project.git":        "my-project-git",
		"--weird  name--":       "weird-name",
		strings.Repeat("a", 80): strings.Repeat("a", 63),
	}
	for dir, want := range cases {
		p := filepath.Join(t.TempDir(), dir)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		git(t, p, "init", "-q")
		got, err := defaultRepoName(p)
		if err != nil || got != want {
			t.Fatalf("defaultRepoName(%q) = %q, %v; want %q", dir, got, err, want)
		}
		if !gitdns.ValidRepoName(got) {
			t.Fatalf("%q is not a valid repo name", got)
		}
	}
}

// TestServeGitPublishesAndRefreshesRefs starts serve-git in process, reads
// the refs over DNS, then changes the repository (new commit, new branch,
// deleted branch, new tag) and refreshes: the new refs and their objects are
// served, the deleted branch is gone, and only new objects are read.
func TestServeGitPublishesAndRefreshesRefs(t *testing.T) {
	for _, tr := range []string{"txt", "aaaa"} {
		t.Run(tr, func(t *testing.T) {
			src := refsRepo(t)
			g, err := startGitServer([]string{"-repo", src, "-name", "demo", "-addr", "127.0.0.1:0", "-refresh", "0", "-tr", tr})
			if err != nil {
				t.Fatal(err)
			}
			defer g.srv.Shutdown()
			trv, _ := parseTransport(tr)
			res := dnszone.NewResolver("127.0.0.1:"+strconv.Itoa(g.srv.Port()), dnszone.Zone("example.com"), 2*time.Second)

			refs, err := gitdns.FetchRefs(res, "demo", trv)
			if err != nil {
				t.Fatal(err)
			}
			if string(refs.Marshal()) != string(g.refs.Marshal()) || len(refs.Refs) != 4 {
				t.Fatalf("served refs:\n%s", refs.Marshal())
			}
			// Every ref's objects are served, annotated tag included.
			var roots []string
			for _, r := range refs.Refs {
				roots = append(roots, r.SHA)
			}
			objs, err := gitdns.FetchAll(res.WithObjectSuffix("g"), roots, trv, nil)
			if err != nil {
				t.Fatalf("fetch ref objects: %v", err)
			}
			if objs[mustLookup(t, refs, "refs/tags/v1")].Kind != gitobj.Tag {
				t.Fatal("v1 is not served as a tag object")
			}

			// The refs record is short-lived; the objects are not.
			q := new(dns.Msg)
			qtype := dns.TypeTXT
			if trv == objectstore.AAAA {
				qtype = dns.TypeAAAA
			}
			q.SetQuestion(gitdns.RefsName("demo", "example.com"), qtype)
			resp, _, err := (&dns.Client{Net: "tcp"}).Exchange(q, "127.0.0.1:"+strconv.Itoa(g.srv.Port()))
			if err != nil || len(resp.Answer) == 0 || resp.Answer[0].Header().Ttl != gitdns.RefTTL {
				t.Fatalf("refs record TTL: %v %v", resp, err)
			}
			q.SetQuestion(dns.Fqdn(roots[0]+".g.example.com"), qtype)
			resp, _, err = (&dns.Client{Net: "tcp"}).Exchange(q, "127.0.0.1:"+strconv.Itoa(g.srv.Port()))
			if err != nil || len(resp.Answer) == 0 || resp.Answer[0].Header().Ttl != dnszone.DefaultTTL {
				t.Fatalf("object record TTL: %v %v", resp, err)
			}

			if changed, err := g.refresh(); err != nil || changed {
				t.Fatalf("refresh with no changes: changed=%v err=%v", changed, err)
			}

			if err := os.WriteFile(filepath.Join(src, "f"), []byte("two\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			git(t, src, "commit", "-q", "-am", "two")
			git(t, src, "branch", "-D", "dev")
			git(t, src, "checkout", "-q", "-b", "feature")
			git(t, src, "tag", "-a", "v2", "-m", "release v2")
			before := objectCount(g)
			if changed, err := g.refresh(); err != nil || !changed {
				t.Fatalf("refresh after changes: changed=%v err=%v", changed, err)
			}
			// New commit, its tree, its blob, and the v2 tag object.
			if added := objectCount(g) - before; added != 4 {
				t.Fatalf("refresh published %d new git objects, want 4", added)
			}

			refs, err = gitdns.FetchRefs(res, "demo", trv)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := refs.Lookup("refs/heads/dev"); ok {
				t.Fatal("deleted branch still served")
			}
			newHead := git(t, src, "rev-parse", "HEAD")
			if sha := mustLookup(t, refs, "refs/heads/feature"); sha != newHead || refs.Head != "refs/heads/feature" {
				t.Fatalf("feature=%s head=%s, want %s", sha, refs.Head, newHead)
			}
			if _, err := gitdns.Fetch(res.WithObjectSuffix("g"), newHead, trv); err != nil {
				t.Fatalf("new commit not served: %v", err)
			}
		})
	}
}

func mustLookup(t *testing.T, refs *gitdns.RefList, name string) string {
	t.Helper()
	sha, ok := refs.Lookup(name)
	if !ok {
		t.Fatalf("ref %s missing from\n%s", name, refs.Marshal())
	}
	return sha
}

// objectCount counts git-object records (<sha>.g) the server holds.
func objectCount(g *gitServer) int {
	n := 0
	for _, sha := range strings.Fields(gitOutputMust(g.cfg.repo)) {
		if g.srv.Has(dns.Fqdn(sha + ".g.example.com")) {
			n++
		}
	}
	return n
}

// gitOutputMust lists every object id in the repository.
func gitOutputMust(repo string) string {
	out, err := gitOutput(repo, "cat-file", "--batch-all-objects", "--batch-check=%(objectname)")
	if err != nil {
		panic(err)
	}
	return out
}
