// Package gitobj models Git objects (blobs, trees, commits) as
// content-addressed records. Git already addresses objects by the SHA-1 of
// their canonical bytes; this package computes those SHAs, parses trees and
// commits, and walks a repository from a commit down to its blobs, verifying
// every object on the way.
//
// The object model follows the Git wire format exactly so SHAs match
// `git hash-object` and `git mktree`; the DNS transport that stores and
// fetches these objects lives in pkg/gitdns.
package gitobj

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Kind is a Git object type.
type Kind string

const (
	// Blob is file content.
	Blob Kind = "blob"
	// Tree is a directory listing of entries.
	Tree Kind = "tree"
	// Commit references a tree, parents, and metadata.
	Commit Kind = "commit"
	// Tag is an annotated tag. Walk does not follow tags; they are accepted
	// so a tag object can be read and verified.
	Tag Kind = "tag"
)

// GitlinkMode is the tree-entry mode of a gitlink: a submodule pointer whose
// SHA names a commit in another repository.
const GitlinkMode = "160000"

// Entry is one tree entry: a mode, a name, and the SHA of the object it
// references.
type Entry struct {
	Mode string
	Name string
	SHA  string
}

// Object is a parsed Git object. Exactly the fields relevant to Kind are
// populated: Entries for trees, and the commit fields for commits.
type Object struct {
	Kind Kind
	SHA  string
	Raw  []byte // canonical (uncompressed) bytes
	Size int    // content length, as Git records it

	// Tree fields.
	Entries []Entry

	// Commit fields.
	Tree      string
	Parents   []string
	Author    string
	Committer string
	Message   string

	// Tag fields: the object an annotated tag points at.
	Target string
}

// ObjectSHA returns the hex SHA-1 of the canonical Git object bytes for the
// given kind and content: "<kind> <size>\x00<content>". The result matches
// `git hash-object`.
func ObjectSHA(kind Kind, content []byte) string {
	header := fmt.Sprintf("%s %d\x00", kind, len(content))
	h := sha1.New()
	h.Write([]byte(header))
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// MarshalTree serializes entries into canonical Git tree bytes. Entries must
// be sorted first with SortEntries (Git sorts by name, treating tree names as
// if they had a trailing slash, case-sensitively).
func MarshalTree(entries []Entry) []byte {
	var b bytes.Buffer
	for _, e := range entries {
		b.WriteString(e.Mode)
		b.WriteByte(' ')
		b.WriteString(e.Name)
		b.WriteByte(0)
		b.Write(hexDec(e.SHA))
	}
	return b.Bytes()
}

// ParseTree parses canonical Git tree bytes into entries.
func ParseTree(raw []byte) ([]Entry, error) {
	var entries []Entry
	i := 0
	for i < len(raw) {
		space := bytes.IndexByte(raw[i:], ' ')
		if space < 0 {
			return nil, fmt.Errorf("gitobj: malformed tree entry (no mode separator) at %d", i)
		}
		mode := string(raw[i : i+space])
		nameStart := i + space + 1
		nul := bytes.IndexByte(raw[nameStart:], 0)
		if nul < 0 {
			return nil, fmt.Errorf("gitobj: malformed tree entry (no name terminator) at %d", i)
		}
		name := string(raw[nameStart : nameStart+nul])
		shaStart := nameStart + nul + 1
		if shaStart+20 > len(raw) {
			return nil, fmt.Errorf("gitobj: truncated SHA at %d", shaStart)
		}
		sum := raw[shaStart : shaStart+20]
		entries = append(entries, Entry{Mode: mode, Name: name, SHA: hex.EncodeToString(sum)})
		i = shaStart + 20
	}
	return entries, nil
}

// SortEntries sorts entries into the canonical order Git uses to hash trees:
// by name, treating tree (directory) names as if they had a trailing slash,
// compared case-sensitively (bytewise).
func SortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		return entryLess(entries[i], entries[j])
	})
}

// entryLess reports whether entry a sorts before entry b in a Git tree.
// Directories (mode 40000) are compared as if their name had a trailing '/';
// the comparison itself is case-sensitive, matching Git's bytewise ordering.
func entryLess(a, b Entry) bool {
	an, bn := a.Name, b.Name
	if a.Mode == "40000" {
		an += "/"
	}
	if b.Mode == "40000" {
		bn += "/"
	}
	return an < bn
}

// ParseCommit parses canonical Git commit bytes into a Commit object's fields.
// The message is everything after the blank line following the header lines.
func ParseCommit(raw []byte) (*Object, error) {
	o := &Object{Kind: Commit}
	header := string(raw)
	// The header block ends at the first blank line ("\n\n"); everything after
	// it is the commit message.
	idx := strings.Index(header, "\n\n")
	var headerPart, msgPart string
	if idx < 0 {
		// No blank line separator: treat the whole thing as header with an
		// empty message, so field parsing still runs.
		headerPart = header
		msgPart = ""
	} else {
		headerPart = header[:idx]
		msgPart = header[idx+2:]
	}
	for _, line := range strings.Split(headerPart, "\n") {
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("gitobj: malformed commit header %q", line)
		}
		switch key {
		case "tree":
			o.Tree = value
		case "parent":
			o.Parents = append(o.Parents, value)
		case "author":
			o.Author = value
		case "committer":
			o.Committer = value
		}
	}
	o.Message = msgPart
	return o, nil
}

// ParseTag parses canonical Git tag bytes and returns the SHA of the object
// the tag points at (its "object" header).
func ParseTag(raw []byte) (string, error) {
	header := string(raw)
	if i := strings.Index(header, "\n\n"); i >= 0 {
		header = header[:i]
	}
	for _, line := range strings.Split(header, "\n") {
		if target, ok := strings.CutPrefix(line, "object "); ok {
			if len(target) != 40 || len(hexDec(target)) != 20 {
				return "", fmt.Errorf("gitobj: tag object %q is not a SHA-1", target)
			}
			return target, nil
		}
	}
	return "", fmt.Errorf("gitobj: tag has no object header")
}

// ReadObject inspects the raw bytes of a Git object, verifies its content
// length, computes and returns its SHA-1, and parses the kind-specific fields.
// The header must be canonical ("<kind> <decimal size>\x00" with a known kind
// and no sign or leading zeros): the SHA-1 is computed over that canonical
// form, so any other spelling would yield bytes that do not hash to SHA.
func ReadObject(raw []byte) (*Object, error) {
	nul := bytes.IndexByte(raw, 0)
	if nul < 0 {
		return nil, fmt.Errorf("gitobj: missing header terminator")
	}
	header := string(raw[:nul])
	kind, sizeStr, ok := strings.Cut(header, " ")
	if !ok {
		return nil, fmt.Errorf("gitobj: malformed header %q", header)
	}
	switch Kind(kind) {
	case Blob, Tree, Commit, Tag:
	default:
		return nil, fmt.Errorf("gitobj: unknown object kind %q", kind)
	}
	size, err := strconv.Atoi(sizeStr)
	if err != nil {
		return nil, fmt.Errorf("gitobj: bad size %q: %w", sizeStr, err)
	}
	if size < 0 || strconv.Itoa(size) != sizeStr {
		return nil, fmt.Errorf("gitobj: non-canonical size %q", sizeStr)
	}
	content := raw[nul+1:]
	if len(content) != size {
		return nil, fmt.Errorf("gitobj: size mismatch (recorded %d, got %d)", size, len(content))
	}
	o := &Object{Kind: Kind(kind), SHA: ObjectSHA(Kind(kind), content), Raw: raw, Size: size}
	switch Kind(kind) {
	case Tree:
		o.Entries, err = ParseTree(content)
		if err != nil {
			return nil, err
		}
	case Commit:
		var c *Object
		c, err = ParseCommit(content)
		if err != nil {
			return nil, err
		}
		o.Tree, o.Parents, o.Author, o.Committer, o.Message = c.Tree, c.Parents, c.Author, c.Committer, c.Message
	case Tag:
		if o.Target, err = ParseTag(content); err != nil {
			return nil, err
		}
	}
	return o, nil
}

// Walk fetches the commit at commitSHA and every object it references,
// verifying each object's SHA-1 as it is fetched. Gitlink (submodule) entries
// are not followed: their commits live in another repository. fetch retrieves
// the raw (uncompressed) bytes of a Git object by its hex SHA-1 and is called
// one object at a time. It returns every object encountered, keyed by SHA.
func Walk(fetch func(sha string) ([]byte, error), commitSHA string) (map[string]*Object, error) {
	return WalkConcurrent(fetch, commitSHA, 1)
}

// WalkConcurrent is Walk with up to workers fetches in flight at once, for a
// fetch whose latency dominates (one network round trip per object). fetch
// must be safe for concurrent use when workers > 1. On the first error no new
// fetches start, in-flight ones are drained, and that error is returned.
func WalkConcurrent(fetch func(sha string) ([]byte, error), commitSHA string, workers int) (map[string]*Object, error) {
	return WalkAll(fetch, []string{commitSHA}, workers, nil)
}

// WalkAll walks from every root in one pass (a ref's commit or annotated
// tag), fetching each reachable object once with up to workers in flight.
// Annotated tags are followed to the object they point at.
//
// When have is non-nil it is asked about each object before it is fetched;
// an object it reports present is skipped along with everything below it, on
// git's guarantee that a repository holding an object holds its closure. It
// is called from one goroutine at a time. The result holds only the objects
// fetched.
func WalkAll(fetch func(sha string) ([]byte, error), roots []string, workers int, have func(sha string) bool) (map[string]*Object, error) {
	if workers < 1 {
		workers = 1
	}
	type result struct {
		sha string
		obj *Object
		err error
	}
	results := make(chan result)
	load := func(sha string) {
		raw, err := fetch(sha)
		if err != nil {
			results <- result{sha: sha, err: fmt.Errorf("gitobj: fetch %s: %w", sha, err)}
			return
		}
		o, err := ReadObject(raw)
		if err == nil && o.SHA != sha {
			err = fmt.Errorf("gitobj: %s resolved to object %s", sha, o.SHA)
		}
		results <- result{sha: sha, obj: o, err: err}
	}

	objects := make(map[string]*Object)
	queued := map[string]bool{}
	var pending []string
	enqueue := func(sha string) {
		if queued[sha] {
			return
		}
		queued[sha] = true
		if have != nil && have(sha) {
			return
		}
		pending = append(pending, sha)
	}
	for i := len(roots) - 1; i >= 0; i-- {
		enqueue(roots[i])
	}
	inflight := 0
	var firstErr error
	for {
		for firstErr == nil && inflight < workers && len(pending) > 0 {
			sha := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			inflight++
			go load(sha)
		}
		if inflight == 0 {
			break
		}
		res := <-results
		inflight--
		if res.err != nil {
			if firstErr == nil {
				firstErr = res.err
			}
			continue
		}
		o := res.obj
		objects[res.sha] = o
		switch o.Kind {
		case Tree:
			for _, e := range o.Entries {
				// A gitlink names a commit in another repository (a
				// submodule); it is not part of this graph.
				if e.Mode != GitlinkMode {
					enqueue(e.SHA)
				}
			}
		case Commit:
			if o.Tree != "" {
				enqueue(o.Tree)
			}
			for _, p := range o.Parents {
				enqueue(p)
			}
		case Tag:
			enqueue(o.Target)
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return objects, nil
}

// hexDec decodes a hex SHA string into its raw bytes, validating the length.
func hexDec(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}
