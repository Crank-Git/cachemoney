package gitobj

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// graph is a test object store with helpers to add objects.
type graph map[string][]byte

func (g graph) put(kind Kind, content string) string {
	sha := ObjectSHA(kind, []byte(content))
	g[sha] = rawBytes(kind, []byte(content))
	return sha
}

func (g graph) blob(s string) string { return g.put(Blob, s) }

func (g graph) tree(entries ...Entry) string {
	SortEntries(entries)
	return g.put(Tree, string(MarshalTree(entries)))
}

func (g graph) commit(tree string, msg string, parents ...string) string {
	c := "tree " + tree + "\n"
	for _, p := range parents {
		c += "parent " + p + "\n"
	}
	return g.put(Commit, c+"author A <a@x> 0 +0000\ncommitter A <a@x> 0 +0000\n\n"+msg+"\n")
}

func (g graph) tag(target string, kind Kind, name string) string {
	return g.put(Tag, "object "+target+"\ntype "+string(kind)+"\ntag "+name+"\ntagger A <a@x> 0 +0000\n\n"+name+"\n")
}

// countingFetch serves g and counts fetches per SHA.
func countingFetch(g graph) (func(string) ([]byte, error), map[string]int) {
	var mu sync.Mutex
	counts := map[string]int{}
	return func(sha string) ([]byte, error) {
		mu.Lock()
		counts[sha]++
		mu.Unlock()
		raw, ok := g[sha]
		if !ok {
			return nil, fmt.Errorf("missing %s", sha)
		}
		return raw, nil
	}, counts
}

func TestParseTag(t *testing.T) {
	target := strings.Repeat("ab", 20)
	got, err := ParseTag([]byte("object " + target + "\ntype commit\ntag v1\n\nmsg\n"))
	if err != nil || got != target {
		t.Fatalf("ParseTag = %q, %v", got, err)
	}
	bad := map[string]string{
		"no object header":       "type commit\ntag v1\n\nmsg\n",
		"short sha":              "object abc\ntype commit\n\n",
		"non-hex sha":            "object " + strings.Repeat("zz", 20) + "\n\n",
		"object only in message": "type commit\ntag v1\n\nobject " + target + "\n",
	}
	for name, raw := range bad {
		if _, err := ParseTag([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestWalkAllFollowsTags walks from annotated tags pointing at a commit, at
// another tag, at a tree, and at a blob. Every target must be fetched.
func TestWalkAllFollowsTags(t *testing.T) {
	g := graph{}
	b := g.blob("x\n")
	tr := g.tree(Entry{Mode: "100644", Name: "x", SHA: b})
	c := g.commit(tr, "one")
	tagCommit := g.tag(c, Commit, "v1")
	tagTag := g.tag(tagCommit, Tag, "v1-signed")
	loneBlob := g.blob("only reachable from a tag\n")
	tagBlob := g.tag(loneBlob, Blob, "blob-tag")
	loneTree := g.tree(Entry{Mode: "100644", Name: "y", SHA: g.blob("y\n")})
	tagTree := g.tag(loneTree, Tree, "tree-tag")

	fetch, _ := countingFetch(g)
	got, err := WalkAll(fetch, []string{tagTag, tagBlob, tagTree}, 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(g) {
		t.Fatalf("walked %d objects, want all %d", len(got), len(g))
	}
	if got[tagTag].Target != tagCommit || got[tagCommit].Target != c {
		t.Fatal("tag targets not parsed")
	}
}

// TestWalkAllSharedHistoryFetchedOnce walks two branches that share history
// and a merge. Each object is fetched exactly once and the result is the
// union of walking each tip alone.
func TestWalkAllSharedHistoryFetchedOnce(t *testing.T) {
	g := graph{}
	base := g.commit(g.tree(Entry{Mode: "100644", Name: "f", SHA: g.blob("0\n")}), "base")
	prev := base
	for i := 1; i <= 5; i++ {
		prev = g.commit(g.tree(Entry{Mode: "100644", Name: "f", SHA: g.blob(fmt.Sprintf("%d\n", i))}), fmt.Sprint(i), prev)
	}
	main := prev
	feature := g.commit(g.tree(Entry{Mode: "100644", Name: "g", SHA: g.blob("feature\n")}), "feature", base)
	merge := g.commit(g.tree(Entry{Mode: "100644", Name: "f", SHA: g.blob("merged\n")}), "merge", main, feature)

	fetch, counts := countingFetch(g)
	got, err := WalkAll(fetch, []string{main, feature, merge, main}, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	union := map[string]bool{}
	for _, tip := range []string{main, feature, merge} {
		one, err := Walk(func(s string) ([]byte, error) { return g[s], nil }, tip)
		if err != nil {
			t.Fatal(err)
		}
		for sha := range one {
			union[sha] = true
		}
	}
	if len(got) != len(union) {
		t.Fatalf("WalkAll found %d objects, union of single walks is %d", len(got), len(union))
	}
	for sha, n := range counts {
		if n != 1 {
			t.Fatalf("%s fetched %d times", sha, n)
		}
	}
}

// TestWalkAllSkipsObjectsPresent simulates an incremental fetch: the client
// already has the old history. Only the new commit, its new tree and blob are
// fetched; the unchanged blob and old commits are skipped without a fetch.
func TestWalkAllSkipsObjectsPresent(t *testing.T) {
	g := graph{}
	unchanged := g.blob("unchanged\n")
	old := g.commit(g.tree(Entry{Mode: "100644", Name: "a", SHA: unchanged}, Entry{Mode: "100644", Name: "b", SHA: g.blob("old\n")}), "old")
	old2 := g.commit(g.tree(Entry{Mode: "100644", Name: "a", SHA: unchanged}, Entry{Mode: "100644", Name: "b", SHA: g.blob("old2\n")}), "old2", old)
	present, err := Walk(func(s string) ([]byte, error) { return g[s], nil }, old2)
	if err != nil {
		t.Fatal(err)
	}
	newBlob := g.blob("new\n")
	newTree := g.tree(Entry{Mode: "100644", Name: "a", SHA: unchanged}, Entry{Mode: "100644", Name: "b", SHA: newBlob})
	tip := g.commit(newTree, "new", old2)

	fetch, counts := countingFetch(g)
	var asked []string
	got, err := WalkAll(fetch, []string{tip}, 4, func(sha string) bool {
		asked = append(asked, sha)
		_, ok := present[sha]
		return ok
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{tip: true, newTree: true, newBlob: true}
	if len(got) != len(want) {
		t.Fatalf("fetched %d objects, want %d (only the new ones)", len(got), len(want))
	}
	for sha := range counts {
		if !want[sha] {
			t.Fatalf("fetched %s, which the client already has", sha)
		}
	}
	if len(asked) == 0 {
		t.Fatal("have was never consulted")
	}

	// A tip the client already has costs nothing.
	got, err = WalkAll(fetch, []string{old2}, 4, func(sha string) bool { _, ok := present[sha]; return ok })
	if err != nil || len(got) != 0 {
		t.Fatalf("walk of a present tip fetched %d objects, err %v", len(got), err)
	}
}
