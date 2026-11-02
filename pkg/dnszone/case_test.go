package dnszone

import (
	"bytes"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// randomCase flips the case of each letter in name at random, the way a
// resolver applying DNS 0x20 encodes entropy into a query.
func randomCase(rng *rand.Rand, name string) string {
	b := []byte(name)
	for i, c := range b {
		if ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') {
			if rng.Intn(2) == 0 {
				b[i] = c ^ 0x20
			}
		}
	}
	return string(b)
}

// TestServerAnswersAnyCase queries the same record lowercased, uppercased,
// and with randomized case. Each must be answered, with the owner name
// spelled exactly as asked.
func TestServerAnswersAnyCase(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, tr := range bothTransports {
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			srv, _, shutdown := newTestServer(t, tr)
			defer shutdown()
			m, chunks := objectstore.Build([]byte("case-insensitive object"))
			if err := srv.Publish(m, chunks, tr); err != nil {
				t.Fatal(err)
			}
			qtype := dns.TypeTXT
			if tr == objectstore.AAAA {
				qtype = dns.TypeAAAA
			}
			stored := srv.manifestName(m.ID())
			names := []string{stored, strings.ToLower(stored), strings.ToUpper(stored)}
			for i := 0; i < 5; i++ {
				names = append(names, randomCase(rng, stored))
			}
			addr := "127.0.0.1:" + strconv.Itoa(srv.Port())
			for _, name := range names {
				q := new(dns.Msg)
				q.SetQuestion(name, qtype)
				c := &dns.Client{Net: "tcp"}
				resp, _, err := c.Exchange(q, addr)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if len(resp.Answer) == 0 {
					t.Fatalf("%s: no answer", name)
				}
				for _, rr := range resp.Answer {
					if rr.Header().Name != name {
						t.Fatalf("owner name %q, want the question's spelling %q", rr.Header().Name, name)
					}
				}
			}
			// Answering must not rewrite the stored records.
			srv.mu.RLock()
			got := srv.records[nameKey(stored)][0].Header().Name
			srv.mu.RUnlock()
			if got != stored {
				t.Fatalf("stored owner name changed to %q", got)
			}
		})
	}
}

// startCaseRandomizingProxy runs a forwarder in front of upstream that
// behaves like a recursive resolver using DNS 0x20: it re-sends each query
// with randomized case and rejects any answer whose names do not match that
// exact spelling. It returns the proxy address and a count of forwarded
// queries.
func startCaseRandomizingProxy(t *testing.T, upstream string) (string, *atomic.Int64) {
	t.Helper()
	var count atomic.Int64
	var seed atomic.Int64
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		rng := rand.New(rand.NewSource(seed.Add(1)))
		orig := req.Question[0].Name
		fwd := req.Copy()
		fwd.Question[0].Name = randomCase(rng, orig)
		up := &dns.Client{Net: "tcp"}
		resp, _, err := up.Exchange(fwd, upstream)
		if err != nil {
			fail := new(dns.Msg)
			fail.SetRcode(req, dns.RcodeServerFailure)
			_ = w.WriteMsg(fail)
			return
		}
		count.Add(1)
		ok := resp.Question[0].Name == fwd.Question[0].Name
		for _, rr := range resp.Answer {
			ok = ok && rr.Header().Name == fwd.Question[0].Name
		}
		if !ok {
			fail := new(dns.Msg)
			fail.SetRcode(req, dns.RcodeServerFailure)
			_ = w.WriteMsg(fail)
			return
		}
		resp.Id = req.Id
		resp.Question[0].Name = orig
		for _, rr := range resp.Answer {
			rr.Header().Name = orig
		}
		if _, isTCP := w.RemoteAddr().(*net.TCPAddr); !isTCP {
			size := dns.MinMsgSize
			if opt := req.IsEdns0(); opt != nil {
				size = int(opt.UDPSize())
			}
			resp.Truncate(size)
		}
		_ = w.WriteMsg(resp)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	udp := &dns.Server{PacketConn: pc, Handler: handler}
	tcp := &dns.Server{Listener: ln, Handler: handler}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()
	t.Cleanup(func() { _ = udp.Shutdown(); _ = tcp.Shutdown() })
	return "127.0.0.1:" + strconv.Itoa(port), &count
}

// TestFetchThroughCaseRandomizingResolver fetches objects through a
// 0x20-style forwarder, as a client behind a public resolver would. Before
// lookups were case-insensitive every query missed.
func TestFetchThroughCaseRandomizingResolver(t *testing.T) {
	for _, tr := range bothTransports {
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			srv, _, shutdown := newTestServer(t, tr)
			defer shutdown()
			proxy, count := startCaseRandomizingProxy(t, "127.0.0.1:"+strconv.Itoa(srv.Port()))
			res := NewResolver(proxy, Zone("example.com"), 0)

			data := randBytes(5000)
			m, chunks := objectstore.Build(data)
			if err := srv.Publish(m, chunks, tr); err != nil {
				t.Fatal(err)
			}
			got, err := res.FetchByID(m.ID(), tr)
			if err != nil {
				t.Fatalf("FetchByID via 0x20 resolver: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Fatal("round-trip mismatch")
			}
			if want := int64(1 + m.ChunkCount); count.Load() < want {
				t.Fatalf("proxy forwarded %d queries, want at least %d", count.Load(), want)
			}

			// Git-scheme names are lowercase hex; they must resolve too.
			sha := strings.Repeat("ab", 20)
			if err := srv.PublishRaw(dns.Fqdn(sha+".g.example.com"), []byte("blob"), tr); err != nil {
				t.Fatal(err)
			}
			raw, err := res.WithObjectSuffix("g").FetchRaw(sha, tr)
			if err != nil || string(raw) != "blob" {
				t.Fatalf("FetchRaw via 0x20 resolver = %q, %v", raw, err)
			}
		})
	}
}

// TestFetchByIDAcceptsLowercaseID checks an id copied in lowercase resolves
// to the same verified object.
func TestFetchByIDAcceptsLowercaseID(t *testing.T) {
	srv, res, shutdown := newTestServer(t, objectstore.TXT)
	defer shutdown()
	m, chunks := objectstore.Build([]byte("typed in lowercase"))
	if err := srv.Publish(m, chunks, objectstore.TXT); err != nil {
		t.Fatal(err)
	}
	got, err := res.FetchByID(objectstore.ObjectID(strings.ToLower(string(m.ID()))), objectstore.TXT)
	if err != nil || string(got) != "typed in lowercase" {
		t.Fatalf("FetchByID(lowercase) = %q, %v", got, err)
	}
}

// TestStoreAndForgetAreCaseInsensitive checks a name published in one case is
// replaced and removed by the same name in another.
func TestStoreAndForgetAreCaseInsensitive(t *testing.T) {
	srv := NewServer(Zone("example.com"), 0)
	if err := srv.PublishRaw("ABC.g.Example.COM.", []byte("one"), objectstore.TXT); err != nil {
		t.Fatal(err)
	}
	if err := srv.PublishRaw("abc.g.example.com.", []byte("two"), objectstore.TXT); err != nil {
		t.Fatal(err)
	}
	if n := len(srv.records); n != 1 {
		t.Fatalf("records = %d, want 1 (same name in two cases)", n)
	}
	srv.Forget("Abc.G.example.com.")
	if n := len(srv.records); n != 0 {
		t.Fatalf("Forget left %d records", n)
	}
}
