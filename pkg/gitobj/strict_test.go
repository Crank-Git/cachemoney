package gitobj

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"testing"
)

// TestReadObjectRejectsUnknownKind checks only git's four object kinds are
// accepted.
func TestReadObjectRejectsUnknownKind(t *testing.T) {
	for _, kind := range []string{"blobby", "BLOB", "", "commit2", "ofs-delta"} {
		raw := []byte(kind + " 5\x00hello")
		if _, err := ReadObject(raw); err == nil || !strings.Contains(err.Error(), "kind") {
			t.Fatalf("ReadObject(%q kind) err=%v, want unknown kind", kind, err)
		}
	}
}

// TestReadObjectAcceptsTag reads a real annotated tag object (bytes from
// `git cat-file tag`) and checks its SHA matches git's.
func TestReadObjectAcceptsTag(t *testing.T) {
	content := []byte("object b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0\ntype blob\ntag v1\ntagger A <a@x> 0 +0000\n\nrelease\n")
	raw := rawBytes(Tag, content)
	o, err := ReadObject(raw)
	if err != nil {
		t.Fatalf("ReadObject(tag): %v", err)
	}
	sum := sha1.Sum(raw)
	if o.Kind != Tag || o.SHA != hex.EncodeToString(sum[:]) {
		t.Fatalf("tag read as kind %q sha %s, want tag %x", o.Kind, o.SHA, sum)
	}
}

// TestReadObjectRejectsNonCanonicalSize covers size spellings Atoi accepts
// but git never writes. The SHA is computed over the canonical header, so
// accepting these would report a SHA the raw bytes do not hash to.
func TestReadObjectRejectsNonCanonicalSize(t *testing.T) {
	for _, size := range []string{"05", "+5", "-5", "0005", " 5"} {
		raw := []byte("blob " + size + "\x00hello")
		if _, err := ReadObject(raw); err == nil {
			t.Fatalf("ReadObject accepted size %q", size)
		}
	}
}

// FuzzReadObjectHashesRawBytes checks that whatever ReadObject accepts, the
// SHA it reports is the SHA-1 of the exact bytes it was given, the property
// Walk relies on to verify fetched objects.
func FuzzReadObjectHashesRawBytes(f *testing.F) {
	f.Add([]byte("blob 5\x00hello"))
	f.Add([]byte("blob 05\x00hello"))
	f.Add([]byte("tree 0\x00"))
	f.Add([]byte("commit 3\x00a b"))
	f.Add([]byte("tag 0\x00"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		o, err := ReadObject(raw)
		if err != nil {
			return
		}
		sum := sha1.Sum(raw)
		if o.SHA != hex.EncodeToString(sum[:]) {
			t.Fatalf("ReadObject(%q) reported SHA %s, raw bytes hash to %x", raw, o.SHA, sum)
		}
	})
}
