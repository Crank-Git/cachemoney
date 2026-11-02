package pkgindex

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Reference sha256 values, checked against `sha256sum` on the host:
//
//	printf 'hello\n'            | sha256sum -> 5891b5b5...6f6be03
//	printf 'the quick brown fox jumps over the lazy dog\n' | sha256sum -> 1153a408...af57129
//	printf ''                  | sha256sum -> e3b0c442...b855
const (
	shaHello     = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
	shaFox       = "1153a4080f1fcb04425aa0b841c2b14606fe6df25d9076d2a1face2d5af57129"
	shaEmpty     = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	helloContent = "hello\n"
	foxContent   = "the quick brown fox jumps over the lazy dog\n"
	emptyContent = ""
)

// TestCanonicalRoundTrip pins the canonical byte format: a scrambled input must
// marshal to the same bytes as the sorted input, and parse back exactly.
func TestCanonicalRoundTrip(t *testing.T) {
	scrambled := []Entry{
		{Path: "/zeta", Mode: "100644", Size: len(foxContent), SHA256: shaFox},
		{Path: "/alpha", Mode: "100644", Size: len(helloContent), SHA256: shaHello},
		{Path: "/empty", Mode: "100644", Size: 0, SHA256: shaEmpty},
	}
	idx := NewIndex(scrambled)

	got := idx.Marshal()
	want := []byte(
		"100644 6 " + shaHello + "\n/alpha\x00" +
			"100644 0 " + shaEmpty + "\n/empty\x00" +
			"100644 44 " + shaFox + "\n/zeta\x00",
	)
	if !bytes.Equal(got, want) {
		t.Fatalf("Marshal = %q, want %q", got, want)
	}

	parsed, err := ParseIndex(got)
	if err != nil {
		t.Fatalf("ParseIndex: %v", err)
	}
	if !bytes.Equal(parsed.Marshal(), want) {
		t.Fatalf("round-trip mismatch")
	}
	if len(parsed.Entries) != 3 {
		t.Fatalf("parsed %d entries, want 3", len(parsed.Entries))
	}
}

// TestVerify passes for matching content and fails for tampered, wrong-size,
// and unknown-path content.
func TestVerify(t *testing.T) {
	idx := NewIndex([]Entry{
		{Path: "/alpha", Mode: "100644", Size: len(helloContent), SHA256: shaHello},
		{Path: "/empty", Mode: "100644", Size: 0, SHA256: shaEmpty},
	})

	if _, err := idx.Verify("/alpha", []byte(helloContent)); err != nil {
		t.Errorf("matching content rejected: %v", err)
	}
	if _, err := idx.Verify("/empty", []byte(emptyContent)); err != nil {
		t.Errorf("empty content rejected: %v", err)
	}

	if _, err := idx.Verify("/alpha", []byte("tampered")); err == nil {
		t.Error("tampered content accepted, want hash mismatch")
	}
	if _, err := idx.Verify("/alpha", []byte("toolong")); err == nil {
		t.Error("wrong-size content accepted, want size mismatch")
	}
	if _, err := idx.Verify("/missing", []byte("x")); err == nil {
		t.Error("unknown path accepted, want not-found")
	}
}

// TestHashStable ensures the index's own hash is deterministic and content
// sensitive.
func TestHashStable(t *testing.T) {
	a := NewIndex([]Entry{{Path: "/a", Mode: "100644", Size: 3, SHA256: shaHello}})
	b := NewIndex([]Entry{{Path: "/a", Mode: "100644", Size: 4, SHA256: shaFox}})
	if a.Hash() == "" {
		t.Fatal("empty hash")
	}
	if a.Hash() == b.Hash() {
		t.Fatal("different indexes share a hash")
	}
}

// TestDuplicatesCollapsed ensures duplicate paths are collapsed to one entry.
func TestDuplicatesCollapsed(t *testing.T) {
	idx := NewIndex([]Entry{
		{Path: "/a", Mode: "100644", Size: 3, SHA256: shaHello},
		{Path: "/a", Mode: "100600", Size: 99, SHA256: shaFox},
	})
	if len(idx.Entries) != 1 {
		t.Fatalf("duplicate paths not collapsed: %d entries", len(idx.Entries))
	}
}

// TestIndexLabel pins the base32 DNS label for an index's content hash. A raw
// sha256 hex is 64 chars, over the 63-char DNS label limit; base32 encodes it
// down to ~52. The value is cross-checked against sha256sum on the host.
func TestIndexLabel(t *testing.T) {
	idx := NewIndex([]Entry{
		{Path: "/alpha", Mode: "100644", Size: len(helloContent), SHA256: shaHello},
	})
	label := idx.Label()
	want := "XP6DX2QFQUITVFTCVJYSFJFOBVSKUBR5XHKT3CAJAYEABV4C7MOA"
	if label != want {
		t.Fatalf("Label = %q, want %q", label, want)
	}
	if len(label) > 63 {
		t.Fatalf("label %q is %d chars, exceeds the 63-char DNS limit", label, len(label))
	}
	if len(idx.Hash()) != 64 {
		t.Fatalf("Hash = %q, want 64 hex chars", idx.Hash())
	}
}

// TestEntryLabel pins the base32 DNS label for a single file's content hash and
// confirms the bad-sha error path.
func TestEntryLabel(t *testing.T) {
	e := Entry{Mode: "100644", Size: 6, SHA256: shaHello}
	label, err := e.Label()
	want := "LCI3LNJC2XPQQ3IP6CYRB66Z2IN3J7DRMOXTJUECQ2ROQRXWXYBQ"
	if err != nil {
		t.Fatalf("Label: %v", err)
	}
	if label != want {
		t.Fatalf("Label = %q, want %q", label, want)
	}
	empty := Entry{}
	if _, err := empty.Label(); err == nil {
		t.Fatal("empty sha256 accepted, want error")
	}
}

// TestLookup ensures a known path returns its entry and an unknown path errors.
func TestLookup(t *testing.T) {
	idx := NewIndex([]Entry{
		{Path: "/alpha", Mode: "100644", Size: len(helloContent), SHA256: shaHello},
	})
	e, err := idx.Lookup("/alpha")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if e.Path != "/alpha" || e.SHA256 != shaHello {
		t.Fatalf("Lookup returned %+v, want /alpha/%s", e, shaHello)
	}
	if _, err := idx.Lookup("/missing"); err == nil {
		t.Fatal("unknown path accepted, want not-found")
	}
}

// TestMalformed ensures ParseIndex rejects malformed input.
func TestMalformed(t *testing.T) {
	bad := [][]byte{
		[]byte("100644 6 " + shaHello + "\n/no-nul-terminator"),
		[]byte("garbage-header\n/path\x00"),
		[]byte("100644 notanumber " + shaHello + "\n/path\x00"),
		[]byte("100644 6 short\n/path\x00"),
	}
	for i, raw := range bad {
		if _, err := ParseIndex(raw); err == nil {
			t.Errorf("case %d: malformed input accepted, want error", i)
		}
	}
}

// TestEntryLabelBadHex covers the branch where an entry's stored sha256 is not
// valid hex, so decoding it in Label fails.
func TestEntryLabelBadHex(t *testing.T) {
	e := Entry{Mode: "100644", Size: 6, SHA256: "nothex!!"}
	if _, err := e.Label(); err == nil {
		t.Fatal("non-hex sha256 accepted, want error")
	}
}

// TestParseIndexTruncatedHeader covers the branch where a header spans the
// whole input with no trailing newline, so no entry terminator is found.
func TestParseIndexTruncatedHeader(t *testing.T) {
	raw := []byte("100644 6 " + shaHello) // no newline, no path
	if _, err := ParseIndex(raw); err == nil {
		t.Fatal("truncated header accepted, want error")
	}
}

// TestSplitHeaderNoSpace ensures splitHeader fails when a header has no space
// separator, so a malformed header index entry is rejected.
func TestSplitHeaderNoSpace(t *testing.T) {
	if _, _, _, ok := splitHeader([]byte("nospace")); ok {
		t.Fatal("splitHeader with no space accepted, want failure")
	}
}

// TestSplitHeaderNoSecondSpace ensures splitHeader rejects a header that has a
// mode and a single space but no size/sha — the second failure path (after a
// header with no space at all).
func TestSplitHeaderNoSecondSpace(t *testing.T) {
	if _, _, _, ok := splitHeader([]byte("100644 onlyone")); ok {
		t.Fatal("splitHeader with a single space accepted, want failure")
	}
}

// TestVerifySizeMismatch ensures Verify rejects content whose hash matches the
// entry but whose length does not match the recorded size.
func TestVerifySizeMismatch(t *testing.T) {
	content := []byte("hello world")
	sum := sha256.Sum256(content)
	idx := NewIndex([]Entry{{
		Path:   "/alpha",
		Size:   len(content) + 1, // correct hash, wrong size
		SHA256: hex.EncodeToString(sum[:]),
	}})
	if _, err := idx.Verify("/alpha", content); err == nil {
		t.Fatal("Verify succeeded with a size mismatch, want error")
	}
}
