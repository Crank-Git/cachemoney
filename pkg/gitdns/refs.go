package gitdns

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/dnszone"
	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// RefTTL is the TTL, in seconds, of a repository's refs record. Refs are the
// only records that change, so resolvers may only cache them briefly.
const RefTTL uint32 = 60

// refsLabel is the scheme label for refs records: <repo>.refs.<zone>.
const refsLabel = "refs"

// Ref is one named reference and the object it points at (a commit, or an
// annotated tag object).
type Ref struct {
	Name string // "refs/heads/main", "refs/tags/v1", or "HEAD" when detached
	SHA  string
}

// RefList is a repository's references as published at <repo>.refs.<zone>.
// Its bytes are git's remote-helper `list` output: an optional
// "@<target> HEAD" line naming the ref HEAD points at, then "<sha> <name>"
// lines sorted by name, each newline-terminated.
//
// Unlike every other record, a ref list is not content-addressed: it is only
// as trustworthy as the DNS path that delivered it. Everything it points at
// is still verified by SHA.
type RefList struct {
	Head string // symbolic HEAD target, e.g. "refs/heads/main"; "" if none
	Refs []Ref
}

// Validate checks every name and SHA, that names are unique, and that a
// symbolic HEAD names a listed ref.
func (l *RefList) Validate() error {
	seen := make(map[string]bool, len(l.Refs))
	for _, r := range l.Refs {
		if !validRefName(r.Name) {
			return fmt.Errorf("gitdns: invalid ref name %q", r.Name)
		}
		if !isSHA1(r.SHA) {
			return fmt.Errorf("gitdns: ref %s has invalid SHA %q", r.Name, r.SHA)
		}
		if seen[r.Name] {
			return fmt.Errorf("gitdns: duplicate ref %s", r.Name)
		}
		seen[r.Name] = true
	}
	if l.Head != "" {
		if l.Head == "HEAD" || !validRefName(l.Head) {
			return fmt.Errorf("gitdns: invalid HEAD target %q", l.Head)
		}
		if !seen[l.Head] {
			return fmt.Errorf("gitdns: HEAD points at %s, which is not listed", l.Head)
		}
		if seen["HEAD"] {
			return fmt.Errorf("gitdns: HEAD is both symbolic and detached")
		}
	}
	return nil
}

// Marshal returns the canonical bytes of the list (refs sorted by name).
func (l *RefList) Marshal() []byte {
	refs := append([]Ref(nil), l.Refs...)
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	var b bytes.Buffer
	if l.Head != "" {
		fmt.Fprintf(&b, "@%s HEAD\n", l.Head)
	}
	for _, r := range refs {
		fmt.Fprintf(&b, "%s %s\n", r.SHA, r.Name)
	}
	return b.Bytes()
}

// Lookup returns the SHA a ref points at.
func (l *RefList) Lookup(name string) (string, bool) {
	for _, r := range l.Refs {
		if r.Name == name {
			return r.SHA, true
		}
	}
	return "", false
}

// ParseRefList parses and validates canonical ref-list bytes. Anything
// Marshal would not produce (unsorted or duplicate refs, a symref line that
// is not first, missing final newline) is rejected.
func ParseRefList(raw []byte) (*RefList, error) {
	l := &RefList{}
	text := string(raw)
	if text != "" && !strings.HasSuffix(text, "\n") {
		return nil, fmt.Errorf("gitdns: ref list not newline-terminated")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if text == "" {
		lines = nil
	}
	for i, line := range lines {
		value, name, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("gitdns: malformed ref line %q", line)
		}
		if target, sym := strings.CutPrefix(value, "@"); sym {
			if i != 0 || name != "HEAD" || target == "" {
				return nil, fmt.Errorf("gitdns: symref line %q must be the first line and name HEAD and a target", line)
			}
			l.Head = target
			continue
		}
		if n := len(l.Refs); n > 0 && name <= l.Refs[n-1].Name {
			return nil, fmt.Errorf("gitdns: ref %s out of order or duplicated", name)
		}
		l.Refs = append(l.Refs, Ref{Name: name, SHA: value})
	}
	if err := l.Validate(); err != nil {
		return nil, err
	}
	return l, nil
}

// ValidRepoName reports whether name can address a repository's refs: one
// lowercase DNS label of letters, digits, and inner hyphens, not a 40-hex
// string (which git-remote-dns reads as a commit SHA).
func ValidRepoName(name string) bool {
	if len(name) == 0 || len(name) > 63 || name[0] == '-' || name[len(name)-1] == '-' || isSHA1(name) {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// RefsName is the fully-qualified name of repo's refs record in zone.
func RefsName(repo string, zone dnszone.Zone) string {
	return dns.Fqdn(repo + "." + refsLabel + "." + string(zone))
}

// PublishRefs publishes refs as repo's refs record with RefTTL, replacing any
// previous list. Publish the objects the refs point at first, so a client
// never sees a ref whose objects are missing.
func PublishRefs(s *dnszone.Server, repo string, refs *RefList, tr objectstore.Transport) error {
	if !ValidRepoName(repo) {
		return fmt.Errorf("gitdns: invalid repository name %q", repo)
	}
	if err := refs.Validate(); err != nil {
		return err
	}
	return s.PublishRawTTL(RefsName(repo, dnszone.Zone(s.ZoneName())), refs.Marshal(), tr, RefTTL)
}

// FetchRefs fetches and validates repo's ref list. r may be any resolver for
// the zone; its object suffix is ignored.
func FetchRefs(r *dnszone.Resolver, repo string, tr objectstore.Transport) (*RefList, error) {
	if !ValidRepoName(repo) {
		return nil, fmt.Errorf("gitdns: invalid repository name %q", repo)
	}
	raw, err := r.WithObjectSuffix(refsLabel).FetchRaw(repo, tr)
	if err != nil {
		return nil, fmt.Errorf("gitdns: fetch refs for %s: %w", repo, err)
	}
	l, err := ParseRefList(raw)
	if err != nil {
		return nil, fmt.Errorf("gitdns: refs for %s: %w", repo, err)
	}
	return l, nil
}

// isSHA1 reports whether s is 40 lowercase hex digits.
func isSHA1(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// validRefName applies git's check-ref-format rules to a full ref name
// ("HEAD" or "refs/..."): no control characters, space, ~ ^ : ? * [ \, no
// "..", "@{", or "//"; no component starting with "." or ending in ".lock";
// not ending in "/" or ".".
func validRefName(name string) bool {
	if name == "HEAD" {
		return true
	}
	if !strings.HasPrefix(name, "refs/") || len(name) <= len("refs/") {
		return false
	}
	if strings.Contains(name, "..") || strings.Contains(name, "@{") || strings.Contains(name, "//") ||
		strings.HasSuffix(name, "/") || strings.HasSuffix(name, ".") {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c < 0x20 || c == 0x7f || strings.IndexByte(" ~^:?*[\\", c) >= 0 {
			return false
		}
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}
