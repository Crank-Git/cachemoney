// Package pkgindex models a package file index: a canonical, path-sorted list
// of file entries (path, mode, size, sha256) with a method to verify a file
// against it. This is the pure, DNS-agnostic core of the apt/Nix mirror spike.
//
// The DNS transport that stores and serves the index and the files it lists
// lives elsewhere; this package only cares about the index's canonical bytes
// and hash verification.
//
// Unlike objectstore (which addresses objects by content hash) and gitobj
// (which addresses tree entries by the SHA of their mode+name+target), a
// package index addresses files by their in-repo path: a client requests a
// path, receives the file, and checks its sha256 against the index.
package pkgindex

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// Entry is one file listed in the index: its path within the package, its
// octal file mode (e.g. "100644"), its content length, and the hex sha256 of
// its content.
type Entry struct {
	Path   string
	Mode   string
	Size   int
	SHA256 string
}

// Index is a set of file entries. It is canonical: entries are sorted by path,
// so two identical indexes marshal to identical bytes.
type Index struct {
	Entries []Entry
}

// NewIndex returns an Index with its entries sorted by path and duplicates
// removed (later entries win). It is the constructor callers should use so an
// Index is always in canonical form.
func NewIndex(entries []Entry) *Index {
	byPath := make(map[string]Entry, len(entries))
	order := make([]string, 0, len(entries))
	for _, e := range entries {
		if _, ok := byPath[e.Path]; !ok {
			order = append(order, e.Path)
		}
		byPath[e.Path] = e
	}
	sorted := make([]Entry, 0, len(order))
	for _, p := range order {
		sorted = append(sorted, byPath[p])
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	return &Index{Entries: sorted}
}

// Hash returns the hex sha256 of the index's canonical bytes. It lets the
// index itself be content-addressed and served like any other object.
func (i *Index) Hash() string {
	sum := sha256.Sum256(i.Marshal())
	return hex.EncodeToString(sum[:])
}

// Label returns the base32 DNS label for the index's content hash. A SHA-256
// hash is 64 hex chars, which exceeds the 63-char label limit; base32 encodes
// it to ~51. This is what the DNS transport uses to address the index.
func (i *Index) Label() string {
	return objectstore.ToLabel(sha256.Sum256(i.Marshal()))
}

// Marshal serializes the index into canonical bytes: entries sorted by path,
// each as a text header ("mode SP size SP sha256\n") followed by the raw path
// bytes terminated by a NUL. The NUL terminator is safe because POSIX paths
// may contain any byte except NUL and '/'.
func (i *Index) Marshal() []byte {
	var b bytes.Buffer
	for _, e := range i.Entries {
		fmt.Fprintf(&b, "%s %d %s\n", e.Mode, e.Size, e.SHA256)
		b.WriteString(e.Path)
		b.WriteByte(0)
	}
	return b.Bytes()
}

// ParseIndex parses canonical bytes produced by Marshal. It rejects malformed
// headers, truncated paths, and duplicate paths.
func ParseIndex(raw []byte) (*Index, error) {
	var entries []Entry
	i := 0
	for i < len(raw) {
		headerEnd := bytes.IndexByte(raw[i:], '\n')
		if headerEnd < 0 {
			return nil, fmt.Errorf("pkgindex: truncated entry header at %d", i)
		}
		header := raw[i : i+headerEnd]
		pathStart := i + headerEnd + 1
		pathEnd := bytes.IndexByte(raw[pathStart:], 0)
		if pathEnd < 0 {
			return nil, fmt.Errorf("pkgindex: truncated path at %d", pathStart)
		}
		path := string(raw[pathStart : pathStart+pathEnd])

		mode, sizeStr, sha, ok := splitHeader(header)
		if !ok {
			return nil, fmt.Errorf("pkgindex: malformed header %q", string(header))
		}
		size, err := strconv.Atoi(sizeStr)
		if err != nil {
			return nil, fmt.Errorf("pkgindex: bad size %q: %w", sizeStr, err)
		}
		if len(sha) != 64 {
			return nil, fmt.Errorf("pkgindex: bad sha256 %q", sha)
		}
		entries = append(entries, Entry{Path: path, Mode: mode, Size: size, SHA256: sha})
		i = pathStart + pathEnd + 1
	}
	return &Index{Entries: entries}, nil
}

// splitHeader parses a "mode SP size SP sha256" header into its three fields.
func splitHeader(header []byte) (mode, size, sha string, ok bool) {
	first := bytes.IndexByte(header, ' ')
	if first < 0 {
		return "", "", "", false
	}
	mode = string(header[:first])
	rest := header[first+1:]
	second := bytes.IndexByte(rest, ' ')
	if second < 0 {
		return "", "", "", false
	}
	size = string(rest[:second])
	sha = string(rest[second+1:])
	return mode, size, sha, true
}

// Lookup returns the entry for path, or an error if the path is unknown. It is
// the pre-fetch lookup a mirror uses to learn a file's expected hash before it
// fetches the file.
func (i *Index) Lookup(path string) (*Entry, error) {
	for _, e := range i.Entries {
		if e.Path == path {
			return &e, nil
		}
	}
	return nil, fmt.Errorf("pkgindex: no entry for %s", path)
}

// Label returns the base32 DNS label for this entry's content hash, decoding
// the stored hex sha256. It is what the DNS transport uses to address the
// file; the hex form stored in SHA256 stays human- and tool-checkable.
func (e *Entry) Label() (string, error) {
	raw, err := hex.DecodeString(e.SHA256)
	if err != nil {
		return "", fmt.Errorf("pkgindex: bad sha256 %q: %w", e.SHA256, err)
	}
	if len(raw) != sha256.Size {
		return "", fmt.Errorf("pkgindex: sha256 %q is not %d bytes", e.SHA256, sha256.Size)
	}
	var sum [sha256.Size]byte
	copy(sum[:], raw)
	return objectstore.ToLabel(sum), nil
}

// Verify looks up path in the index and checks that content matches the listed
// size and sha256. It returns the matching entry, or an error if the path is
// unknown or the content does not match.
func (i *Index) Verify(path string, content []byte) (*Entry, error) {
	for _, e := range i.Entries {
		if e.Path != path {
			continue
		}
		sum := sha256.Sum256(content)
		got := hex.EncodeToString(sum[:])
		if got != e.SHA256 {
			return nil, fmt.Errorf("pkgindex: %s content hash mismatch: got %s, want %s", path, got, e.SHA256)
		}
		if len(content) != e.Size {
			return nil, fmt.Errorf("pkgindex: %s size mismatch: got %d, want %d", path, len(content), e.Size)
		}
		return &e, nil
	}
	return nil, fmt.Errorf("pkgindex: no entry for %s", path)
}
