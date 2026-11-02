package gitdns

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/dnszone"
	"github.com/Crank-Git/cachemoney/pkg/gitobj"
	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// refHello is git's SHA-1 for the blob content "hello"; asserting it pins the
// test's object construction against real git.
const refHello = "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0"

// rawBytes wraps content in canonical Git object framing:
// "<kind> <size>\x00<content>".
func rawBytes(kind gitobj.Kind, content []byte) []byte {
	return append([]byte(fmt.Sprintf("%s %d\x00", kind, len(content))), content...)
}

// buildGraph constructs a small git object graph: a blob ("hello"), a tree
// referencing it as hello.txt, and a single-root commit pointing at the tree.
// It returns the objects keyed by SHA plus the individual SHAs.
func buildGraph(t *testing.T) (objects map[string][]byte, commitSHA, treeSHA, blobSHA string) {
	t.Helper()

	blobContent := []byte("hello")
	blobSHA = gitobj.ObjectSHA(gitobj.Blob, blobContent)
	if blobSHA != refHello {
		t.Fatalf("blob sha = %s, want git refHello %s", blobSHA, refHello)
	}
	blobRaw := rawBytes(gitobj.Blob, blobContent)

	entries := []gitobj.Entry{{Mode: "100644", Name: "hello.txt", SHA: blobSHA}}
	gitobj.SortEntries(entries)
	treeContent := gitobj.MarshalTree(entries)
	treeSHA = gitobj.ObjectSHA(gitobj.Tree, treeContent)
	treeRaw := rawBytes(gitobj.Tree, treeContent)

	msg := "Hello\n"
	header := "tree " + treeSHA + "\n" +
		"author Test Author <test@example.com> 1700000000 +0000\n" +
		"committer Test Author <test@example.com> 1700000000 +0000\n\n"
	commitContent := rawBytes(gitobj.Commit, []byte(header+msg))
	commitSHA = gitobj.ObjectSHA(gitobj.Commit, []byte(header+msg))

	objects = map[string][]byte{
		commitSHA: commitContent,
		treeSHA:   treeRaw,
		blobSHA:   blobRaw,
	}
	return objects, commitSHA, treeSHA, blobSHA
}

// gitServer starts a server on an ephemeral port for the test zone and returns
// it with a git-scheme resolver pointed at it.
func gitServer(t *testing.T) (*dnszone.Server, *dnszone.Resolver) {
	t.Helper()
	srv := dnszone.NewServer("example.com", 0)
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(srv.Shutdown)
	rr := dnszone.NewResolver("127.0.0.1:"+strconv.Itoa(srv.Port()), dnszone.Zone("example.com"), 0).WithObjectSuffix("g")
	return srv, rr
}

func TestPublishFetchRoundTrip(t *testing.T) {
	for _, tr := range []objectstore.Transport{objectstore.TXT, objectstore.AAAA} {
		tr := tr
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			objects, commitSHA, treeSHA, blobSHA := buildGraph(t)
			fetch := func(sha string) ([]byte, error) {
				b, ok := objects[sha]
				if !ok {
					return nil, fmt.Errorf("no object %s", sha)
				}
				return b, nil
			}

			srv, rr := gitServer(t)
			if err := Publish(srv, commitSHA, fetch, tr); err != nil {
				t.Fatalf("publish: %v", err)
			}

			got, err := Fetch(rr, commitSHA, tr)
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if len(got) != 3 {
				t.Fatalf("fetched %d objects, want 3 (%v)", len(got), got)
			}

			c := got[commitSHA]
			if c == nil {
				t.Fatal("commit not fetched")
			}
			if c.Tree != treeSHA {
				t.Errorf("commit tree = %s, want %s", c.Tree, treeSHA)
			}
			if c.Author != "Test Author <test@example.com> 1700000000 +0000" {
				t.Errorf("commit author = %q", c.Author)
			}
			if c.Message != "Hello\n" {
				t.Errorf("commit message = %q, want %q", c.Message, "Hello\n")
			}

			tree := got[treeSHA]
			if tree == nil || len(tree.Entries) != 1 || tree.Entries[0].SHA != blobSHA {
				t.Fatalf("tree object wrong: %+v", tree)
			}
			if blob := got[blobSHA]; blob == nil || blob.Size != 5 {
				t.Errorf("blob object wrong: %+v", blob)
			}
		})
	}
}

func TestFetchMissingObject(t *testing.T) {
	// The source graph is complete (so Publish succeeds); the server then lacks
	// the blob the tree references, exercising the fetch-side missing-record path.
	for _, tr := range []objectstore.Transport{objectstore.TXT, objectstore.AAAA} {
		tr := tr
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			objects, commitSHA, _, blobSHA := buildGraph(t)
			fetch := func(sha string) ([]byte, error) {
				b, ok := objects[sha]
				if !ok {
					return nil, fmt.Errorf("no object %s", sha)
				}
				return b, nil
			}

			srv, rr := gitServer(t)
			if err := Publish(srv, commitSHA, fetch, tr); err != nil {
				t.Fatalf("publish: %v", err)
			}
			srv.Forget(dns.Fqdn(blobSHA + ".g.example.com")) // the tree points at a blob the server no longer has

			if _, err := Fetch(rr, commitSHA, tr); err == nil {
				t.Fatal("fetch succeeded despite missing blob, want error")
			}
		})
	}
}

// TestPublishRejectsCorruptSource ensures Publish fails when the source graph
// is corrupt, so Walk rejects it before publishing a half-built index.
func TestPublishRejectsCorruptSource(t *testing.T) {
	objects, commitSHA, _, _ := buildGraph(t)
	fetch := func(sha string) ([]byte, error) {
		if sha == commitSHA {
			// A blob's bytes presented under the commit's name: ReadObject
			// parses it but its content address will not match the requested
			// SHA, so Walk rejects the corrupt object.
			return rawBytes(gitobj.Blob, []byte("hello")), nil
		}
		return objects[sha], nil
	}
	srv, _ := gitServer(t)
	if err := Publish(srv, commitSHA, fetch, objectstore.TXT); err == nil {
		t.Fatal("Publish succeeded with a corrupt source, want error")
	}
}

func TestFetchDetectsTampering(t *testing.T) {
	// Tampering is exercised over TXT via Server.Corrupt, which flips a byte in
	// a stored record's first piece and is only defined for TXT answers.
	objects, commitSHA, _, blobSHA := buildGraph(t)
	fetch := func(sha string) ([]byte, error) {
		b, ok := objects[sha]
		if !ok {
			return nil, fmt.Errorf("no object %s", sha)
		}
		return b, nil
	}

	srv, rr := gitServer(t)
	if err := Publish(srv, commitSHA, fetch, objectstore.TXT); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := srv.CorruptAt(dns.Fqdn(blobSHA + ".g.example.com")); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	if _, err := Fetch(rr, commitSHA, objectstore.TXT); err == nil {
		t.Fatal("fetch succeeded despite tampered blob, want SHA mismatch")
	}
}

// TestPublishFetchWithGitlink publishes and fetches a graph whose tree holds
// a submodule gitlink. Both used to fail trying to fetch the submodule's
// commit, which is not in this repository.
func TestPublishFetchWithGitlink(t *testing.T) {
	for _, tr := range []objectstore.Transport{objectstore.TXT, objectstore.AAAA} {
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			objects := map[string][]byte{}
			blob := []byte("hello")
			blobSHA := gitobj.ObjectSHA(gitobj.Blob, blob)
			objects[blobSHA] = rawBytes(gitobj.Blob, blob)
			const link = "3333333333333333333333333333333333333333"
			entries := []gitobj.Entry{{Mode: "100644", Name: "hello.txt", SHA: blobSHA}, {Mode: gitobj.GitlinkMode, Name: "sub", SHA: link}}
			gitobj.SortEntries(entries)
			tree := gitobj.MarshalTree(entries)
			treeSHA := gitobj.ObjectSHA(gitobj.Tree, tree)
			objects[treeSHA] = rawBytes(gitobj.Tree, tree)
			commit := []byte("tree " + treeSHA + "\nauthor A <a@x> 0 +0000\ncommitter A <a@x> 0 +0000\n\nwith submodule\n")
			commitSHA := gitobj.ObjectSHA(gitobj.Commit, commit)
			objects[commitSHA] = rawBytes(gitobj.Commit, commit)

			srv := dnszone.NewServer(dnszone.Zone("example.com"), 0)
			if err := srv.Start("127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			defer srv.Shutdown()
			if err := Publish(srv, commitSHA, func(sha string) ([]byte, error) {
				if raw, ok := objects[sha]; ok {
					return raw, nil
				}
				return nil, fmt.Errorf("%s not in repository", sha)
			}, tr); err != nil {
				t.Fatalf("Publish: %v", err)
			}
			r := dnszone.NewResolver("127.0.0.1:"+strconv.Itoa(srv.Port()), dnszone.Zone("example.com"), 0).WithObjectSuffix("g")
			got, err := Fetch(r, commitSHA, tr)
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if len(got) != 3 {
				t.Fatalf("fetched %d objects, want 3", len(got))
			}
		})
	}
}

// TestPublishFetchLargeBlob round-trips a commit holding a 1 MB blob. Git
// objects used to be published as one record: over TXT anything past ~47 KB
// could not fit a DNS message, and over AAAA anything past ~3.8 KB wrapped
// the sequence byte and came back as a different object.
func TestPublishFetchLargeBlob(t *testing.T) {
	for _, tr := range []objectstore.Transport{objectstore.TXT, objectstore.AAAA} {
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			blob := make([]byte, 1<<20)
			for i := range blob {
				blob[i] = byte(i*7 + i/251)
			}
			objects := map[string][]byte{}
			blobSHA := gitobj.ObjectSHA(gitobj.Blob, blob)
			objects[blobSHA] = rawBytes(gitobj.Blob, blob)
			tree := gitobj.MarshalTree([]gitobj.Entry{{Mode: "100644", Name: "big.bin", SHA: blobSHA}})
			treeSHA := gitobj.ObjectSHA(gitobj.Tree, tree)
			objects[treeSHA] = rawBytes(gitobj.Tree, tree)
			commit := []byte("tree " + treeSHA + "\nauthor A <a@x> 0 +0000\ncommitter A <a@x> 0 +0000\n\nbig\n")
			commitSHA := gitobj.ObjectSHA(gitobj.Commit, commit)
			objects[commitSHA] = rawBytes(gitobj.Commit, commit)

			srv := dnszone.NewServer(dnszone.Zone("example.com"), 0)
			if err := srv.Start("127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			defer srv.Shutdown()
			if err := Publish(srv, commitSHA, func(sha string) ([]byte, error) {
				return objects[sha], nil
			}, tr); err != nil {
				t.Fatalf("Publish: %v", err)
			}
			r := dnszone.NewResolver("127.0.0.1:"+strconv.Itoa(srv.Port()), dnszone.Zone("example.com"), 0).WithObjectSuffix("g")
			got, err := Fetch(r, commitSHA, tr)
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if o := got[blobSHA]; o == nil || string(o.Raw) != string(objects[blobSHA]) {
				t.Fatal("large blob did not round-trip")
			}
		})
	}
}
