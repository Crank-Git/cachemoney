package dnszone

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// query sends one question to srv over TCP (no truncation) and returns the
// response. mutate may adjust the message before it is sent.
func query(t *testing.T, srv *Server, name string, qtype uint16, mutate func(*dns.Msg)) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	if mutate != nil {
		mutate(q)
	}
	c := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}
	resp, _, err := c.Exchange(q, "127.0.0.1:"+strconv.Itoa(srv.Port()))
	if err != nil {
		t.Fatalf("query %s %s: %v", name, dns.TypeToString[qtype], err)
	}
	return resp
}

// requireSOAAuthority checks a negative answer carries the zone SOA in the
// authority section with the negative-caching TTL (RFC 2308).
func requireSOAAuthority(t *testing.T, resp *dns.Msg) {
	t.Helper()
	if len(resp.Answer) != 0 {
		t.Fatalf("negative answer has %d answer records", len(resp.Answer))
	}
	if len(resp.Ns) != 1 {
		t.Fatalf("authority section has %d records, want the SOA", len(resp.Ns))
	}
	soa, ok := resp.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("authority record is %T, want SOA", resp.Ns[0])
	}
	if soa.Hdr.Name != "example.com." || soa.Minttl != NegativeTTL || soa.Hdr.Ttl != NegativeTTL {
		t.Fatalf("SOA %s minttl=%d ttl=%d, want example.com. with %d", soa.Hdr.Name, soa.Minttl, soa.Hdr.Ttl, NegativeTTL)
	}
}

// TestAuthoritativeResponses covers each class of answer the server gives.
func TestAuthoritativeResponses(t *testing.T) {
	srv, _, shutdown := newTestServer(t, objectstore.TXT)
	defer shutdown()
	m, chunks := objectstore.Build(randBytes(2000))
	if err := srv.Publish(m, chunks, objectstore.TXT); err != nil {
		t.Fatal(err)
	}
	manifest := srv.manifestName(m.ID())
	chunk := srv.chunkName(m.ChunkIDs[0])

	t.Run("apex SOA", func(t *testing.T) {
		resp := query(t, srv, "example.com.", dns.TypeSOA, nil)
		if resp.Rcode != dns.RcodeSuccess || !resp.Authoritative || len(resp.Answer) != 1 {
			t.Fatalf("rcode=%s aa=%v answers=%d", dns.RcodeToString[resp.Rcode], resp.Authoritative, len(resp.Answer))
		}
		soa := resp.Answer[0].(*dns.SOA)
		if soa.Ns != "ns.example.com." || soa.Mbox != "hostmaster.example.com." {
			t.Fatalf("SOA ns=%s mbox=%s", soa.Ns, soa.Mbox)
		}
	})
	t.Run("apex NS", func(t *testing.T) {
		resp := query(t, srv, "EXAMPLE.com.", dns.TypeNS, nil)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
		}
		ns := resp.Answer[0].(*dns.NS)
		if ns.Ns != "ns.example.com." || ns.Hdr.Name != "EXAMPLE.com." {
			t.Fatalf("NS %s owner %s", ns.Ns, ns.Hdr.Name)
		}
	})
	t.Run("apex other type is NODATA", func(t *testing.T) {
		resp := query(t, srv, "example.com.", dns.TypeA, nil)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
		}
		requireSOAAuthority(t, resp)
	})
	t.Run("record", func(t *testing.T) {
		resp := query(t, srv, manifest, dns.TypeTXT, nil)
		if resp.Rcode != dns.RcodeSuccess || !resp.Authoritative || len(resp.Answer) != 1 {
			t.Fatalf("rcode=%s aa=%v answers=%d", dns.RcodeToString[resp.Rcode], resp.Authoritative, len(resp.Answer))
		}
		if ttl := resp.Answer[0].Header().Ttl; ttl != DefaultTTL {
			t.Fatalf("record TTL %d, want %d", ttl, DefaultTTL)
		}
	})
	t.Run("wrong type is NODATA", func(t *testing.T) {
		resp := query(t, srv, chunk, dns.TypeAAAA, nil)
		if resp.Rcode != dns.RcodeSuccess || !resp.Authoritative {
			t.Fatalf("rcode=%s aa=%v, want authoritative NOERROR", dns.RcodeToString[resp.Rcode], resp.Authoritative)
		}
		requireSOAAuthority(t, resp)
	})
	t.Run("ANY returns the records", func(t *testing.T) {
		resp := query(t, srv, chunk, dns.TypeANY, nil)
		if len(resp.Answer) != 1 {
			t.Fatalf("ANY returned %d answers", len(resp.Answer))
		}
	})
	for _, ent := range []string{"c.example.com.", "o.example.com.", "C.Example.com."} {
		t.Run("empty non-terminal "+ent, func(t *testing.T) {
			resp := query(t, srv, ent, dns.TypeTXT, nil)
			if resp.Rcode != dns.RcodeSuccess {
				t.Fatalf("rcode=%s, want NOERROR: NXDOMAIN here would hide every name below it", dns.RcodeToString[resp.Rcode])
			}
			requireSOAAuthority(t, resp)
		})
	}
	for _, missing := range []string{"nope.o.example.com.", "x.example.com.", "deep.er.nope.c.example.com.", strings.Replace(chunk, ".c.", ".g.", 1)} {
		t.Run("NXDOMAIN "+missing, func(t *testing.T) {
			resp := query(t, srv, missing, dns.TypeTXT, nil)
			if resp.Rcode != dns.RcodeNameError || !resp.Authoritative {
				t.Fatalf("rcode=%s aa=%v, want authoritative NXDOMAIN", dns.RcodeToString[resp.Rcode], resp.Authoritative)
			}
			requireSOAAuthority(t, resp)
		})
	}
	for _, outside := range []string{"google.com.", "com.", ".", "notexample.com.", "example.com.evil.", "example.org."} {
		t.Run("REFUSED "+outside, func(t *testing.T) {
			resp := query(t, srv, outside, dns.TypeA, nil)
			if resp.Rcode != dns.RcodeRefused || resp.Authoritative || len(resp.Answer)+len(resp.Ns) != 0 {
				t.Fatalf("rcode=%s aa=%v, want non-authoritative empty REFUSED", dns.RcodeToString[resp.Rcode], resp.Authoritative)
			}
		})
	}
	t.Run("NOTIMP for non-QUERY opcodes", func(t *testing.T) {
		for _, op := range []int{dns.OpcodeNotify, dns.OpcodeUpdate, dns.OpcodeStatus} {
			resp := query(t, srv, manifest, dns.TypeTXT, func(q *dns.Msg) { q.Opcode = op })
			if resp.Rcode != dns.RcodeNotImplemented {
				t.Fatalf("opcode %s: rcode=%s, want NOTIMP", dns.OpcodeToString[op], dns.RcodeToString[resp.Rcode])
			}
		}
	})
	t.Run("FORMERR for zero or two questions", func(t *testing.T) {
		for _, n := range []int{0, 2} {
			resp := query(t, srv, manifest, dns.TypeTXT, func(q *dns.Msg) {
				q.Question = q.Question[:0]
				for i := 0; i < n; i++ {
					q.Question = append(q.Question, dns.Question{Name: manifest, Qtype: dns.TypeTXT, Qclass: dns.ClassINET})
				}
			})
			if resp.Rcode != dns.RcodeFormatError {
				t.Fatalf("%d questions: rcode=%s, want FORMERR", n, dns.RcodeToString[resp.Rcode])
			}
		}
	})
}

// TestForgetReleasesEmptyNonTerminal checks a parent name turns into NXDOMAIN
// once the last record below it is removed, and stays NODATA while any
// remain.
func TestForgetReleasesEmptyNonTerminal(t *testing.T) {
	srv, _, shutdown := newTestServer(t, objectstore.TXT)
	defer shutdown()
	for _, n := range []string{"a.b.g.example.com.", "c.b.g.example.com."} {
		if err := srv.store(n, []byte("x"), objectstore.TXT); err != nil {
			t.Fatal(err)
		}
	}
	rcode := func(name string) int { return query(t, srv, name, dns.TypeTXT, nil).Rcode }
	if rc := rcode("b.g.example.com."); rc != dns.RcodeSuccess {
		t.Fatalf("ENT with two children: %s", dns.RcodeToString[rc])
	}
	srv.Forget("a.b.g.example.com.")
	if rc := rcode("b.g.example.com."); rc != dns.RcodeSuccess {
		t.Fatalf("ENT with one child: %s", dns.RcodeToString[rc])
	}
	srv.Forget("C.B.g.example.com.")
	for _, n := range []string{"b.g.example.com.", "g.example.com."} {
		if rc := rcode(n); rc != dns.RcodeNameError {
			t.Fatalf("%s with no children: %s, want NXDOMAIN", n, dns.RcodeToString[rc])
		}
	}
}

// TestSetNameserver checks the configured nameserver appears in NS and SOA.
func TestSetNameserver(t *testing.T) {
	srv, _, shutdown := newTestServer(t, objectstore.TXT)
	defer shutdown()
	srv.SetNameserver("dns1.provider.net")
	if ns := query(t, srv, "example.com.", dns.TypeNS, nil).Answer[0].(*dns.NS).Ns; ns != "dns1.provider.net." {
		t.Fatalf("NS = %s", ns)
	}
	if ns := query(t, srv, "example.com.", dns.TypeSOA, nil).Answer[0].(*dns.SOA).Ns; ns != "dns1.provider.net." {
		t.Fatalf("SOA mname = %s", ns)
	}
}

// TestEDNSHandling checks the OPT record is echoed only when the query used
// EDNS0, and an unsupported EDNS version gets BADVERS.
func TestEDNSHandling(t *testing.T) {
	srv, _, shutdown := newTestServer(t, objectstore.TXT)
	defer shutdown()
	if resp := query(t, srv, "example.com.", dns.TypeSOA, nil); resp.IsEdns0() != nil {
		t.Fatal("OPT in response to a query without EDNS0")
	}
	resp := query(t, srv, "example.com.", dns.TypeSOA, func(q *dns.Msg) { q.SetEdns0(1232, false) })
	opt := resp.IsEdns0()
	if opt == nil || opt.UDPSize() != serverUDPSize || opt.Version() != 0 {
		t.Fatalf("EDNS0 response OPT = %v", opt)
	}
	resp = query(t, srv, "example.com.", dns.TypeSOA, func(q *dns.Msg) {
		q.SetEdns0(1232, false)
		q.IsEdns0().SetVersion(1)
	})
	if resp.Rcode != dns.RcodeBadVers || resp.IsEdns0() == nil {
		t.Fatalf("EDNS version 1: rcode=%s opt=%v, want BADVERS with OPT", dns.RcodeToString[resp.Rcode], resp.IsEdns0())
	}
}

// TestNonEDNSUDPTruncatedTo512 checks a UDP client without EDNS0 never gets
// a datagram over 512 bytes; a larger answer is truncated with TC set.
func TestNonEDNSUDPTruncatedTo512(t *testing.T) {
	srv, _, shutdown := newTestServer(t, objectstore.AAAA)
	defer shutdown()
	m, chunks := objectstore.Build(randBytes(objectstore.DefaultChunkSize))
	if err := srv.Publish(m, chunks, objectstore.AAAA); err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	q.SetQuestion(srv.chunkName(m.ChunkIDs[0]), dns.TypeAAAA)
	wire := rawAnswer(t, "udp", "127.0.0.1:"+strconv.Itoa(srv.Port()), q)
	if len(wire) > dns.MinMsgSize {
		t.Fatalf("non-EDNS UDP answer is %d bytes, over 512", len(wire))
	}
	var resp dns.Msg
	if err := resp.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	if !resp.Truncated {
		t.Fatal("answer over 512 bytes not marked truncated")
	}
}

// TestResolverTreatsNXDOMAINAsNotFound checks a missing object surfaces as the
// resolver's not-found error, and transport fallback still works now that a
// record queried with the wrong type gets NODATA.
func TestResolverTreatsNXDOMAINAsNotFound(t *testing.T) {
	srv, res, shutdown := newTestServer(t, objectstore.AAAA)
	defer shutdown()
	if _, _, err := res.fetch("missing.o.example.com.", objectstore.TXT); !errors.Is(err, errNotFound) {
		t.Fatalf("NXDOMAIN fetch err=%v, want errNotFound", err)
	}
	data := randBytes(1500)
	m, chunks := objectstore.Build(data)
	if err := srv.Publish(m, chunks, objectstore.AAAA); err != nil {
		t.Fatal(err)
	}
	if _, err := res.FetchByID(m.ID(), objectstore.TXT); err == nil {
		t.Fatal("TXT fetch of AAAA-only object succeeded without fallback")
	}
	got, err := res.WithFallbackTransport(objectstore.AAAA).FetchByID(m.ID(), objectstore.TXT)
	if err != nil || string(got) != string(data) {
		t.Fatalf("fallback fetch: %v", err)
	}
}
