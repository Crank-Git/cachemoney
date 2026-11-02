package gitdns

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/Crank-Git/cachemoney/pkg/dnszone"
	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

var (
	shaA = strings.Repeat("a1", 20)
	shaB = strings.Repeat("b2", 20)
)

func TestRefListRoundTrip(t *testing.T) {
	l := &RefList{Head: "refs/heads/main", Refs: []Ref{
		{Name: "refs/tags/v1", SHA: shaB},
		{Name: "refs/heads/main", SHA: shaA},
		{Name: "refs/heads/feature/x-1.2", SHA: shaB},
	}}
	if err := l.Validate(); err != nil {
		t.Fatal(err)
	}
	raw := l.Marshal()
	want := "@refs/heads/main HEAD\n" + shaB + " refs/heads/feature/x-1.2\n" + shaA + " refs/heads/main\n" + shaB + " refs/tags/v1\n"
	if string(raw) != want {
		t.Fatalf("Marshal:\n%s\nwant\n%s", raw, want)
	}
	back, err := ParseRefList(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(back.Marshal()) != want || back.Head != l.Head {
		t.Fatal("round trip changed the list")
	}
	if sha, ok := back.Lookup("refs/tags/v1"); !ok || sha != shaB {
		t.Fatal("Lookup")
	}
	detached := "" + shaA + " HEAD\n" + shaA + " refs/heads/main\n"
	if _, err := ParseRefList([]byte(detached)); err != nil {
		t.Fatalf("detached HEAD rejected: %v", err)
	}
	if l, err := ParseRefList(nil); err != nil || len(l.Refs) != 0 {
		t.Fatalf("empty list: %v", err)
	}
}

func TestParseRefListRejects(t *testing.T) {
	line := func(sha, name string) string { return sha + " " + name + "\n" }
	cases := map[string]string{
		"unsorted":            line(shaA, "refs/heads/b") + line(shaA, "refs/heads/a"),
		"duplicate":           line(shaA, "refs/heads/a") + line(shaB, "refs/heads/a"),
		"no final newline":    strings.TrimSuffix(line(shaA, "refs/heads/a"), "\n"),
		"uppercase sha":       line(strings.ToUpper(shaA), "refs/heads/a"),
		"short sha":           line(shaA[:39], "refs/heads/a"),
		"symref not first":    line(shaA, "refs/heads/a") + "@refs/heads/a HEAD\n",
		"symref to missing":   "@refs/heads/main HEAD\n" + line(shaA, "refs/heads/a"),
		"symref and detached": "@refs/heads/a HEAD\n" + line(shaA, "HEAD") + line(shaA, "refs/heads/a"),
		"symref not HEAD":     "@refs/heads/a FOO\n" + line(shaA, "refs/heads/a"),
		"empty symref target": "@ HEAD\n",
		"not under refs/":     line(shaA, "heads/a"),
		"bare refs/":          line(shaA, "refs/"),
		"double dot":          line(shaA, "refs/heads/a..b"),
		"at-brace":            line(shaA, "refs/heads/a@{1}"),
		"lock suffix":         line(shaA, "refs/heads/a.lock"),
		"dot component":       line(shaA, "refs/heads/.hidden"),
		"trailing slash":      line(shaA, "refs/heads/a/"),
		"trailing dot":        line(shaA, "refs/heads/a."),
		"double slash":        line(shaA, "refs/heads//a"),
		"colon":               line(shaA, "refs/heads/a:b"),
		"space in name":       shaA + " refs/heads/a b\n",
		"control char":        line(shaA, "refs/heads/a\x01"),
		"blank line":          line(shaA, "refs/heads/a") + "\n",
		"missing separator":   shaA + "\n",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRefList([]byte(raw)); err == nil {
				t.Fatalf("accepted %q", raw)
			}
		})
	}
}

// FuzzParseRefListCanonical checks anything ParseRefList accepts marshals
// back to the same bytes, so a ref list has exactly one encoding.
func FuzzParseRefListCanonical(f *testing.F) {
	f.Add([]byte("@refs/heads/main HEAD\n" + shaA + " refs/heads/main\n"))
	f.Add([]byte(shaA + " HEAD\n" + shaB + " refs/tags/v1\n"))
	f.Add([]byte(shaA + " refs/heads/b\n" + shaA + " refs/heads/a\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		l, err := ParseRefList(raw)
		if err != nil {
			return
		}
		if got := l.Marshal(); string(got) != string(raw) {
			t.Fatalf("non-canonical input accepted\n in:  %q\n out: %q", raw, got)
		}
	})
}

func TestValidRepoName(t *testing.T) {
	for _, ok := range []string{"a", "cachemoney", "my-repo-2", strings.Repeat("x", 63)} {
		if !ValidRepoName(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "-a", "a-", "My", "a_b", "a.b", "a b", strings.Repeat("x", 64), shaA} {
		if ValidRepoName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestPublishFetchRefs round-trips ref lists over DNS, including one large
// enough to need an indirect manifest, replaces a list by publishing again,
// and rejects a refs record that is not a valid list.
func TestPublishFetchRefs(t *testing.T) {
	for _, tr := range []objectstore.Transport{objectstore.TXT, objectstore.AAAA} {
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			srv := dnszone.NewServer(dnszone.Zone("example.com"), 0)
			if err := srv.Start("127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			defer srv.Shutdown()
			r := dnszone.NewResolver("127.0.0.1:"+strconv.Itoa(srv.Port()), dnszone.Zone("example.com"), 0)

			big := &RefList{Head: "refs/heads/branch-000"}
			for i := 0; i < 300; i++ {
				big.Refs = append(big.Refs, Ref{Name: fmt.Sprintf("refs/heads/branch-%03d", i), SHA: shaA})
			}
			if err := PublishRefs(srv, "big", big, tr); err != nil {
				t.Fatal(err)
			}
			got, err := FetchRefs(r.WithObjectSuffix("g"), "big", tr)
			if err != nil {
				t.Fatal(err)
			}
			if string(got.Marshal()) != string(big.Marshal()) {
				t.Fatal("300-ref list did not round-trip")
			}

			small := &RefList{Head: "refs/heads/main", Refs: []Ref{{Name: "refs/heads/main", SHA: shaA}}}
			if err := PublishRefs(srv, "repo", small, tr); err != nil {
				t.Fatal(err)
			}
			moved := &RefList{Head: "refs/heads/main", Refs: []Ref{{Name: "refs/heads/main", SHA: shaB}}}
			if err := PublishRefs(srv, "repo", moved, tr); err != nil {
				t.Fatal(err)
			}
			got, err = FetchRefs(r, "repo", tr)
			if err != nil {
				t.Fatal(err)
			}
			if sha, _ := got.Lookup("refs/heads/main"); sha != shaB {
				t.Fatalf("after republish main=%s, want %s", sha, shaB)
			}

			if _, err := FetchRefs(r, "missing", tr); err == nil {
				t.Fatal("refs for an unpublished repo resolved")
			}
			if err := srv.PublishRawTTL(RefsName("junk", "example.com"), []byte("not a ref list"), tr, RefTTL); err != nil {
				t.Fatal(err)
			}
			if _, err := FetchRefs(r, "junk", tr); err == nil {
				t.Fatal("garbage refs record accepted")
			}
			if err := PublishRefs(srv, "Bad_Name", small, tr); err == nil {
				t.Fatal("invalid repo name published")
			}
			if err := PublishRefs(srv, "repo", &RefList{Head: "refs/heads/nope"}, tr); err == nil {
				t.Fatal("invalid ref list published")
			}
			if _, err := FetchRefs(r, "Bad_Name", tr); err == nil {
				t.Fatal("invalid repo name fetched")
			}
		})
	}
}
