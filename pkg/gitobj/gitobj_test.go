package gitobj

import (
	"fmt"
	"testing"
)

// Known-good reference values produced by `git hash-object` / `git mktree`.
const (
	refHello  = "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0"
	refWorld  = "04fea06420ca60892f73becee3614f6d023a4b7f"
	refEmpty  = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
	refTree1  = "65829399355e5929e44741d637d52c614ac21bc3"
	refTree2  = "e30b5202a91c72788d1ce94a3918edb647d2f48c"
	refEmptyT = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
)

// rawBytes wraps content in the canonical Git object framing:
// "<kind> <size>\x00<content>".
func rawBytes(kind Kind, content []byte) []byte {
	return append([]byte(fmt.Sprintf("%s %d\x00", kind, len(content))), content...)
}

func TestObjectSHAMatchesGit(t *testing.T) {
	cases := []struct {
		kind  Kind
		input string
		want  string
	}{
		{Blob, "", refEmpty},
		{Blob, "hello", refHello},
		{Blob, "world", refWorld},
	}
	for _, c := range cases {
		if got := ObjectSHA(c.kind, []byte(c.input)); got != c.want {
			t.Errorf("ObjectSHA(%q, %q) = %s, want %s", c.kind, c.input, got, c.want)
		}
	}
}

func TestMarshalTreeMatchesGit(t *testing.T) {
	one := []Entry{{Mode: "100644", Name: "a.txt", SHA: refHello}}
	SortEntries(one)
	if got := ObjectSHA(Tree, MarshalTree(one)); got != refTree1 {
		t.Errorf("single-tree sha = %s, want %s", got, refTree1)
	}

	// Two blobs, fed in reverse order to exercise SortEntries.
	two := []Entry{
		{Mode: "100644", Name: "b.txt", SHA: refWorld},
		{Mode: "100644", Name: "a.txt", SHA: refHello},
	}
	SortEntries(two)
	if got := ObjectSHA(Tree, MarshalTree(two)); got != refTree2 {
		t.Errorf("two-tree sha = %s, want %s", got, refTree2)
	}

	if got := ObjectSHA(Tree, MarshalTree(nil)); got != refEmptyT {
		t.Errorf("empty-tree sha = %s, want %s", got, refEmptyT)
	}
}

// TestSortEntriesMatchesGit pins Git's tree-entry ordering against
// `git hash-object -t tree`: entries sort by name, tree (directory) names are
// treated as if they had a trailing '/', and the comparison is case-sensitive
// (bytewise). Each case is fed in a deliberately wrong order so SortEntries is
// exercised; the resulting SHA must equal Git's canonical value.
func TestSortEntriesMatchesGit(t *testing.T) {
	emptyTree := "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
	cases := []struct {
		name string
		// fed in deliberately unsorted order;
		in   []Entry
		want string
	}{
		{
			name: "mixed-modes",
			in: []Entry{
				{Mode: "100755", Name: "ascript.sh", SHA: "01f02e32ce8a128dd7b1d16a45f2eff66ec23c2d"},
				{Mode: "100644", Name: "afile.txt", SHA: "7c4a013e52c76442ab80ee5572399a30373600a2"},
				{Mode: "40000", Name: "adir", SHA: emptyTree},
			},
			want: "6c05c27f44df725371a396d0b39f4e1a42033690",
		},
		{
			name: "case-sensitive",
			// fed scrambled; canonical order is Foo/, Zebra, apple, foo.txt
			in: []Entry{
				{Mode: "100644", Name: "apple", SHA: "2e65efe2a145dda7ee51d1741299f848e5bf752e"},
				{Mode: "100644", Name: "foo.txt", SHA: "e25f1814e51579d5f55c0f1fe0135ddb28a47f4a"},
				{Mode: "100644", Name: "Zebra", SHA: "fa7af8bf5fdd704f73beb3adc5612682a98e1af5"},
				{Mode: "40000", Name: "Foo", SHA: emptyTree},
			},
			want: "82dfe77ae2313f37a3a2036b889b3f9d3167e47c",
		},
		{
			name: "trailing-slash",
			in: []Entry{
				{Mode: "40000", Name: "foo", SHA: emptyTree},
				{Mode: "100644", Name: "foobar", SHA: "4d1ae35ba2c8ec712fa2a379db44ad639ca277bd"},
				{Mode: "100644", Name: "foo.txt", SHA: "e25f1814e51579d5f55c0f1fe0135ddb28a47f4a"},
			},
			want: "e28af8bb697971d205204b59d028a24c4607ec23",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			SortEntries(c.in)
			got := ObjectSHA(Tree, MarshalTree(c.in))
			if got != c.want {
				t.Errorf("sorted tree sha = %s, want %s", got, c.want)
			}
		})
	}
}

func TestParseTreeRoundTrip(t *testing.T) {
	raw := MarshalTree([]Entry{
		{Mode: "100644", Name: "a.txt", SHA: refHello},
		{Mode: "100644", Name: "b.txt", SHA: refWorld},
	})
	got, err := ParseTree(raw)
	if err != nil {
		t.Fatalf("ParseTree: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	if got[0].Name != "a.txt" || got[1].Name != "b.txt" {
		t.Errorf("order not canonical: %q, %q", got[0].Name, got[1].Name)
	}
	for i, want := range []string{refHello, refWorld} {
		if got[i].SHA != want {
			t.Errorf("entry %d sha = %q, want %q", i, got[i].SHA, want)
		}
	}
}

func TestReadObjectCommit(t *testing.T) {
	content := []byte("tree " + refTree2 + "\nauthor Test <test@example.com> 1700000000 +0000\ncommitter Test <test@example.com> 1700000000 +0000\n\nFirst commit\n")
	raw := rawBytes(Commit, content)

	o, err := ReadObject(raw)
	if err != nil {
		t.Fatalf("ReadObject: %v", err)
	}
	if o.Kind != Commit {
		t.Errorf("kind = %q, want commit", o.Kind)
	}
	if o.SHA != ObjectSHA(Commit, content) {
		t.Errorf("sha mismatch")
	}
	if o.Tree != refTree2 {
		t.Errorf("tree = %q, want %q", o.Tree, refTree2)
	}
	if o.Author != "Test <test@example.com> 1700000000 +0000" {
		t.Errorf("author = %q", o.Author)
	}
	if o.Message != "First commit\n" {
		t.Errorf("message = %q", o.Message)
	}
}

func TestReadObjectRejectsBadSize(t *testing.T) {
	if _, err := ReadObject(rawBytes(Blob, []byte("hello"))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Corrupt the recorded size so it no longer matches the content length.
	bad := append([]byte("blob 999\x00"), []byte("hello")...)
	if _, err := ReadObject(bad); err == nil {
		t.Fatal("expected size mismatch error")
	}
}

func TestWalk(t *testing.T) {
	tree := MarshalTree([]Entry{
		{Mode: "100644", Name: "a.txt", SHA: refHello},
		{Mode: "100644", Name: "b.txt", SHA: refWorld},
	})
	commit := []byte("tree " + refTree2 + "\nauthor A <a@example.com> 1700000000 +0000\ncommitter A <a@example.com> 1700000000 +0000\n\nroot\n")
	commitSHA := ObjectSHA(Commit, commit)

	store := map[string][]byte{
		commitSHA: rawBytes(Commit, commit),
		refTree2:  rawBytes(Tree, tree),
		refHello:  rawBytes(Blob, []byte("hello")),
		refWorld:  rawBytes(Blob, []byte("world")),
	}

	fetch := func(sha string) ([]byte, error) {
		raw, ok := store[sha]
		if !ok {
			return nil, fmt.Errorf("object %s not found", sha)
		}
		return raw, nil
	}

	objects, err := Walk(fetch, commitSHA)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(objects) != 4 {
		t.Fatalf("walked %d objects, want 4 (commit, tree, 2 blobs)", len(objects))
	}
	for sha := range store {
		if _, ok := objects[sha]; !ok {
			t.Errorf("object %s not reached by walk", sha)
		}
	}
}

func TestWalkDetectsTampering(t *testing.T) {
	commit := []byte("tree " + refTree1 + "\nauthor A <a@example.com> 1700000000 +0000\ncommitter A <a@example.com> 1700000000 +0000\n\nroot\n")
	commitSHA := ObjectSHA(Commit, commit)

	store := map[string][]byte{
		commitSHA: rawBytes(Commit, commit),
		refTree1:  rawBytes(Tree, MarshalTree([]Entry{{Mode: "100644", Name: "a.txt", SHA: refHello}})),
		refHello:  rawBytes(Blob, []byte("HELLO")), // content no longer matches refHello
		refWorld:  rawBytes(Blob, []byte("world")),
	}

	_, err := Walk(func(sha string) ([]byte, error) {
		return store[sha], nil
	}, commitSHA)
	if err == nil {
		t.Fatal("expected tampering error")
	}
}

func TestWalkFollowsParents(t *testing.T) {
	// Two commits sharing one tree: commit2 -> commit1 (parent) -> tree -> blob.
	tree := MarshalTree([]Entry{{Mode: "100644", Name: "a.txt", SHA: refHello}})
	commit1 := []byte("tree " + refTree1 + "\nauthor A <a@example.com> 1700000000 +0000\ncommitter A <a@example.com> 1700000000 +0000\n\nfirst\n")
	commit1SHA := ObjectSHA(Commit, commit1)
	commit2 := []byte("tree " + refTree1 + "\nparent " + commit1SHA + "\nauthor A <a@example.com> 1700000001 +0000\ncommitter A <a@example.com> 1700000001 +0000\n\nsecond\n")
	commit2SHA := ObjectSHA(Commit, commit2)

	store := map[string][]byte{
		commit2SHA: rawBytes(Commit, commit2),
		commit1SHA: rawBytes(Commit, commit1),
		refTree1:   rawBytes(Tree, tree),
		refHello:   rawBytes(Blob, []byte("hello")),
	}

	objects, err := Walk(func(sha string) ([]byte, error) {
		return store[sha], nil
	}, commit2SHA)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(objects) != 4 {
		t.Fatalf("walked %d objects, want 4 (2 commits, 1 tree, 1 blob)", len(objects))
	}
	if _, ok := objects[commit1SHA]; !ok {
		t.Error("parent commit not reached")
	}
}

func TestWalkDetectsMissingParent(t *testing.T) {
	commit1 := []byte("tree " + refTree1 + "\nauthor A <a@example.com> 1700000000 +0000\ncommitter A <a@example.com> 1700000000 +0000\n\nfirst\n")
	commit1SHA := ObjectSHA(Commit, commit1)
	commit2 := []byte("tree " + refTree1 + "\nparent " + commit1SHA + "\nauthor A <a@example.com> 1700000001 +0000\ncommitter A <a@example.com> 1700000001 +0000\n\nsecond\n")
	commit2SHA := ObjectSHA(Commit, commit2)

	// commit1 is absent from the store.
	store := map[string][]byte{
		commit2SHA: rawBytes(Commit, commit2),
		refTree1:   rawBytes(Tree, MarshalTree([]Entry{{Mode: "100644", Name: "a.txt", SHA: refHello}})),
		refHello:   rawBytes(Blob, []byte("hello")),
	}

	_, err := Walk(func(sha string) ([]byte, error) {
		return store[sha], nil
	}, commit2SHA)
	if err == nil {
		t.Fatal("expected error for missing parent")
	}
}

// TestParseTreeMalformed ensures ParseTree rejects structurally broken tree
// bytes: a missing mode separator, a missing name terminator, and a truncated
// SHA. Each malformed input is a distinct branch that a well-formed tree never
// exercises.
func TestParseTreeMalformed(t *testing.T) {
	// No space separating mode from name.
	if _, err := ParseTree([]byte("100644a.txt" + refHello)); err == nil {
		t.Fatal("expected no-mode-separator error")
	}
	// Space present, but no NUL terminating the name.
	if _, err := ParseTree([]byte("100644 a.txt" + refHello)); err == nil {
		t.Fatal("expected no-name-terminator error")
	}
	// Valid mode and name, but fewer than 20 bytes of SHA.
	if _, err := ParseTree([]byte("100644 a.txt" + refHello[:10])); err == nil {
		t.Fatal("expected truncated-SHA error")
	}
}

// TestParseCommitNoSeparator covers the branch where a commit has no blank
// line separating header from message: the whole body is treated as the
// header and the message is empty, so field parsing still runs.
func TestParseCommitNoSeparator(t *testing.T) {
	content := []byte("tree " + refTree2 + "\nauthor A <a@example.com> 1700000000 +0000")
	raw := rawBytes(Commit, content)
	o, err := ReadObject(raw)
	if err != nil {
		t.Fatalf("ReadObject: %v", err)
	}
	if o.Message != "" {
		t.Errorf("message = %q, want empty", o.Message)
	}
	if o.Tree != refTree2 {
		t.Errorf("tree = %q, want %q", o.Tree, refTree2)
	}
}

// TestParseCommitMalformedHeader ensures a header line without a key/value
// separator is rejected.
func TestParseCommitMalformedHeader(t *testing.T) {
	content := []byte("this-line-has-no-separator\n")
	raw := rawBytes(Commit, content)
	if _, err := ReadObject(raw); err == nil {
		t.Fatal("expected malformed commit header error")
	}
}

// TestReadObjectRejectsMalformedHeader covers the malformed-header and
// bad-size branches of ReadObject.
func TestReadObjectRejectsMalformedHeader(t *testing.T) {
	// Header with no space: kind/size cannot be split.
	badNoSpace := append([]byte("garbage"), 0, 'h', 'i')
	if _, err := ReadObject(badNoSpace); err == nil {
		t.Fatal("expected malformed header error")
	}
	// Header with a non-numeric size.
	badSize := append([]byte("blob notanumber"), 0, 'h', 'i')
	if _, err := ReadObject(badSize); err == nil {
		t.Fatal("expected bad size error")
	}
}

// TestReadObjectRejectsMalformedContent covers the branches where ReadObject
// parses a tree or commit whose content is itself malformed.
func TestReadObjectRejectsMalformedContent(t *testing.T) {
	// A tree object whose content has no mode separator.
	malformedTree := rawBytes(Tree, []byte("no-separator-here"))
	if _, err := ReadObject(malformedTree); err == nil {
		t.Fatal("expected malformed tree content error")
	}
	// A commit object whose header line has no separator.
	malformedCommit := rawBytes(Commit, []byte("brokenline"))
	if _, err := ReadObject(malformedCommit); err == nil {
		t.Fatal("expected malformed commit content error")
	}
}

// TestWalkFetchError covers the branch where the fetch function returns an
// error for a referenced object.
func TestWalkFetchError(t *testing.T) {
	commit := []byte("tree " + refTree2 + "\nauthor A <a@example.com> 1700000000 +0000\ncommitter A <a@example.com> 1700000000 +0000\n\nroot\n")
	commitSHA := ObjectSHA(Commit, commit)

	fetch := func(sha string) ([]byte, error) {
		if sha == refTree2 {
			return nil, fmt.Errorf("boom")
		}
		return rawBytes(Commit, commit), nil
	}

	if _, err := Walk(fetch, commitSHA); err == nil {
		t.Fatal("expected fetch error")
	}
}

// TestParseTreeTruncatedSHA ensures a tree entry with fewer than 20 bytes of
// SHA is rejected, so a truncated tree fails loudly rather than reading
// past its own data.
func TestParseTreeTruncatedSHA(t *testing.T) {
	raw := []byte("100644 a.txt")[:0]
	raw = append(raw, []byte("100644 a.txt")...)
	raw = append(raw, 0)
	raw = append(raw, 0x01, 0x02, 0x03) // only 3 of the 20 SHA bytes
	if _, err := ParseTree(raw); err == nil {
		t.Fatal("truncated SHA accepted, want error")
	}
}

// TestWalkSkipsGitlinks walks a commit whose root tree and a subtree both hold
// gitlink (submodule) entries. The gitlinked commits are not in this
// repository, so fetching them must never be attempted.
func TestWalkSkipsGitlinks(t *testing.T) {
	objs := map[string][]byte{}
	put := func(kind Kind, content []byte) string {
		sha := ObjectSHA(kind, content)
		objs[sha] = rawBytes(kind, content)
		return sha
	}
	const linkRoot = "1111111111111111111111111111111111111111"
	const linkSub = "2222222222222222222222222222222222222222"

	blob := put(Blob, []byte("file\n"))
	subEntries := []Entry{{Mode: "100644", Name: "a.txt", SHA: blob}, {Mode: GitlinkMode, Name: "vendored", SHA: linkSub}}
	SortEntries(subEntries)
	sub := put(Tree, MarshalTree(subEntries))
	rootEntries := []Entry{{Mode: GitlinkMode, Name: "lib", SHA: linkRoot}, {Mode: "40000", Name: "src", SHA: sub}, {Mode: "100644", Name: "README", SHA: blob}}
	SortEntries(rootEntries)
	root := put(Tree, MarshalTree(rootEntries))
	commit := put(Commit, []byte("tree "+root+"\nauthor A <a@x> 0 +0000\ncommitter A <a@x> 0 +0000\n\nmsg\n"))

	var requested []string
	got, err := Walk(func(sha string) ([]byte, error) {
		requested = append(requested, sha)
		if raw, ok := objs[sha]; ok {
			return raw, nil
		}
		return nil, fmt.Errorf("object %s not in repository", sha)
	}, commit)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	for _, sha := range requested {
		if sha == linkRoot || sha == linkSub {
			t.Fatalf("Walk fetched gitlinked commit %s", sha)
		}
	}
	if len(got) != len(objs) {
		t.Fatalf("Walk returned %d objects, want %d", len(got), len(objs))
	}
	for sha := range objs {
		if _, ok := got[sha]; !ok {
			t.Fatalf("Walk missed %s", sha)
		}
	}
	// The gitlink entries themselves are preserved in the parsed trees.
	links := 0
	for _, e := range got[root].Entries {
		if e.Mode == GitlinkMode {
			links++
		}
	}
	if links != 1 {
		t.Fatalf("root tree has %d gitlink entries, want 1", links)
	}
}
