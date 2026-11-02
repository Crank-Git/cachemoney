// Package mirror publishes and fetches package-file indices and the files they
// list over DNS, the transport half of the apt/Nix mirror spike.
//
// Each file is stored as a raw record under <sha256>.f.<zone> and the index
// listing its files is stored under <indexhash>.f.<zone>, using the "f" label
// scheme so it never collides with the manifest ("o") or git ("g") schemes. A
// client fetches the index by hash, then a file by path (looking up the path's
// sha256 in the index and fetching that record), verifying the file's size and
// sha256 against the index.
//
// The pure index model lives in pkg/pkgindex; the DNS server and resolver live
// in pkg/dnszone.
package mirror

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/dnszone"
	"github.com/Crank-Git/cachemoney/pkg/objectstore"
	"github.com/Crank-Git/cachemoney/pkg/pkgindex"
)

// suffix is the DNS label the mirror scheme stores under: <hash>.f.<zone>.
const suffix = "f"

// resolverSuffix returns a resolver configured for the mirror's "f" scheme.
func resolverSuffix(r *dnszone.Resolver) *dnszone.Resolver { return r.WithObjectSuffix(suffix) }

// Publish stores each file listed in idx over DNS under <sha256>.f.<zone> and
// the index itself under <indexhash>.f.<zone>, using tr. It verifies every
// file's sha256 and size against the index first, so a corrupt source file is
// rejected before anything is published. It returns the index's hash so the
// caller and clients know where to find the index.
func Publish(s *dnszone.Server, idx *pkgindex.Index, files map[string][]byte, tr objectstore.Transport) (string, error) {
	zone := dnszone.Zone(s.ZoneName())

	// Verify every file against the index before publishing anything, so a
	// corrupt source is rejected up front rather than half-published.
	for _, e := range idx.Entries {
		data, ok := files[e.Path]
		if !ok {
			return "", fmt.Errorf("mirror: index lists file %q that is not in files", e.Path)
		}
		if _, err := idx.Verify(e.Path, data); err != nil {
			return "", err
		}
	}

	for _, e := range idx.Entries {
		label, err := e.Label()
		if err != nil {
			return "", err
		}
		fqdn := dns.Fqdn(fmt.Sprintf("%s.%s.%s", label, suffix, zone))
		if err := s.PublishRaw(fqdn, files[e.Path], tr); err != nil {
			return "", fmt.Errorf("mirror: publish %s: %w", e.Path, err)
		}
	}

	indexLabel := idx.Label()
	fqdn := dns.Fqdn(fmt.Sprintf("%s.%s.%s", indexLabel, suffix, zone))
	if err := s.PublishRaw(fqdn, idx.Marshal(), tr); err != nil {
		return "", fmt.Errorf("mirror: publish index: %w", err)
	}
	// Return the base32 label: it is the DNS id the client passes back to
	// Fetch to locate the index again.
	return indexLabel, nil
}

// Fetch retrieves the index identified by indexHash, looks up path in it,
// fetches the matching file record, and verifies the file's size and sha256
// against the index. It returns the file's bytes. A missing index, unknown
// path, or tampered file fails loudly rather than returning unverified data.
//
// Both records live under the mirror's "f" scheme, so r may be any resolver for
// the zone; its own object suffix is ignored.
func Fetch(r *dnszone.Resolver, indexHash, path string, tr objectstore.Transport) ([]byte, error) {
	r = resolverSuffix(r)
	idxRaw, err := r.FetchRaw(indexHash, tr)
	if err != nil {
		return nil, fmt.Errorf("mirror: fetch index %s: %w", indexHash, err)
	}
	// The index is content-addressed by indexHash: verify the fetched bytes
	// actually hash to it. Without this a tampered index that did not touch the
	// requested file would be used as-is.
	if got := objectstore.ToLabel(sha256.Sum256(idxRaw)); !strings.EqualFold(got, indexHash) {
		return nil, fmt.Errorf("mirror: index %s content mismatch: got %s", indexHash, got)
	}
	idx, err := pkgindex.ParseIndex(idxRaw)
	if err != nil {
		return nil, fmt.Errorf("mirror: parse index %s: %w", indexHash, err)
	}

	entry, err := idx.Lookup(path)
	if err != nil {
		return nil, fmt.Errorf("mirror: %w", err)
	}
	label, err := entry.Label()
	if err != nil {
		return nil, fmt.Errorf("mirror: %w", err)
	}

	data, err := r.FetchRaw(label, tr)
	if err != nil {
		return nil, fmt.Errorf("mirror: fetch file %s: %w", path, err)
	}
	if _, err := idx.Verify(path, data); err != nil {
		return nil, err
	}
	return data, nil
}
