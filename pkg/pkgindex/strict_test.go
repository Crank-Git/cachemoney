package pkgindex

import (
	"bytes"
	"strings"
	"testing"
)

const (
	shaA = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
	shaB = "1153a4080f1fcb04425aa0b841c2b14606fe6df25d9076d2a1face2d5af57129"
)

func entryBytes(mode, size, sha, path string) string {
	return mode + " " + size + " " + sha + "\n" + path + "\x00"
}

// TestParseIndexRejectsNonCanonical covers inputs that used to parse even
// though Marshal would never produce them.
func TestParseIndexRejectsNonCanonical(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"duplicate path", entryBytes("100644", "6", shaA, "/a") + entryBytes("100644", "6", shaB, "/a"), "duplicate"},
		{"out of order", entryBytes("100644", "6", shaA, "/b") + entryBytes("100644", "6", shaB, "/a"), "out of order"},
		{"uppercase sha", entryBytes("100644", "6", strings.ToUpper(shaA), "/a"), "sha256"},
		{"non-hex sha", entryBytes("100644", "6", strings.Repeat("g", 64), "/a"), "sha256"},
		{"short sha", entryBytes("100644", "6", shaA[:63], "/a"), "sha256"},
		{"plus-signed size", entryBytes("100644", "+6", shaA, "/a"), "non-canonical"},
		{"zero-padded size", entryBytes("100644", "06", shaA, "/a"), "non-canonical"},
		{"negative size", entryBytes("100644", "-1", shaA, "/a"), "non-canonical"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseIndex([]byte(tc.raw))
			if err == nil {
				t.Fatal("ParseIndex accepted non-canonical input")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestParseIndexAcceptsMarshal checks every canonical index still parses,
// including an empty one and paths that sort by byte value.
func TestParseIndexAcceptsMarshal(t *testing.T) {
	idx := NewIndex([]Entry{
		{Path: "/b", Mode: "100644", Size: 6, SHA256: shaA},
		{Path: "/B", Mode: "100755", Size: 0, SHA256: shaB},
		{Path: "/a/x", Mode: "100644", Size: 12, SHA256: shaB},
		{Path: "/a", Mode: "100644", Size: 6, SHA256: shaA},
	})
	for _, raw := range [][]byte{idx.Marshal(), NewIndex(nil).Marshal()} {
		got, err := ParseIndex(raw)
		if err != nil {
			t.Fatalf("ParseIndex(Marshal()): %v", err)
		}
		if !bytes.Equal(got.Marshal(), raw) {
			t.Fatal("re-marshaled index differs from input")
		}
	}
}

// FuzzParseIndexCanonical checks that any input ParseIndex accepts marshals
// back to exactly the same bytes, so an index hash identifies one byte string.
func FuzzParseIndexCanonical(f *testing.F) {
	f.Add([]byte(entryBytes("100644", "6", shaA, "/a") + entryBytes("100644", "45", shaB, "/b")))
	f.Add([]byte(entryBytes("100644", "6", shaA, "/a") + entryBytes("100644", "6", shaB, "/a")))
	f.Add([]byte(entryBytes("100644", "06", shaA, "/a")))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		idx, err := ParseIndex(raw)
		if err != nil {
			return
		}
		if got := idx.Marshal(); !bytes.Equal(got, raw) {
			t.Fatalf("ParseIndex accepted non-canonical bytes\n in:  %q\n out: %q", raw, got)
		}
	})
}
