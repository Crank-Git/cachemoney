// Package gitdns publishes and fetches Git object graphs over DNS using the
// cachemoney objectstore framing. Each Git object's raw (uncompressed) bytes
// are published with dnszone.Server.PublishRaw: chunked under <chunkid>.c,
// with the object's manifest at its git SHA-1 under the ".g" label,
// <sha>.g.<zone>. Fetch verifies every object's SHA-1 as it arrives, so the
// git SHA is the trust anchor.
//
// The pure object model lives in pkg/gitobj; the DNS server and resolver live
// in pkg/dnszone.
package gitdns

import (
	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/dnszone"
	"github.com/Crank-Git/cachemoney/pkg/gitobj"
	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// Publish walks the object graph rooted at commitSHA and stores every object's
// raw bytes on the server under <sha>.g.<zone>. fetch returns the raw
// (uncompressed) bytes of a git object by its hex SHA-1, e.g. from a local
// .git/objects store. The graph is walked and SHA-1 verified with gitobj.Walk,
// so a corrupt source object is rejected before it is published.
func Publish(s *dnszone.Server, commitSHA string, fetch func(sha string) ([]byte, error), tr objectstore.Transport) error {
	objects, err := gitobj.Walk(fetch, commitSHA)
	if err != nil {
		return err
	}
	zone := dnszone.Zone(s.ZoneName())
	for sha, o := range objects {
		fqdn := dns.Fqdn(sha + ".g." + string(zone))
		if err := s.PublishRaw(fqdn, o.Raw, tr); err != nil {
			return err
		}
	}
	return nil
}

// Fetch walks the object graph rooted at commitSHA over DNS, fetching each
// object's raw bytes from the server and verifying its SHA-1 as it is
// retrieved. Up to the resolver's concurrency (dnszone.Resolver.WithConcurrency)
// objects are fetched at once, so a large history is not one round trip after
// another. It returns every object encountered, keyed by SHA. The resolver
// must be configured for the git scheme (see dnszone.Resolver.WithObjectSuffix).
func Fetch(r *dnszone.Resolver, commitSHA string, tr objectstore.Transport) (map[string]*gitobj.Object, error) {
	return gitobj.WalkConcurrent(func(sha string) ([]byte, error) {
		return r.FetchRaw(sha, tr)
	}, commitSHA, r.Concurrency())
}
