package dnszone

import (
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// startWithin runs srv.Start(addr) and fails the test if it has not returned
// within d, so a regression to the old blocking behavior fails fast instead of
// hanging the suite.
func startWithin(t *testing.T, srv *Server, addr string, d time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- srv.Start(addr) }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		t.Fatalf("Start(%s) still blocked after %s", addr, d)
		return nil
	}
}

// TestStartFailsWhenTCPPortTaken occupies the TCP side of a port and starts a
// server on it. Start used to swallow the TCP bind error and block forever.
func TestStartFailsWhenTCPPortTaken(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	srv := NewServer(Zone("example.com"), 0)
	if err := startWithin(t, srv, addr, 3*time.Second); err == nil {
		srv.Shutdown()
		t.Fatalf("Start(%s) succeeded with the TCP port taken", addr)
	}
	// The UDP socket bound during the attempt must have been released.
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("UDP port leaked after failed Start: %v", err)
	}
	pc.Close()
}

// TestStartFailsWhenUDPPortTaken is the UDP counterpart.
func TestStartFailsWhenUDPPortTaken(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().String()

	srv := NewServer(Zone("example.com"), 0)
	if err := startWithin(t, srv, addr, 3*time.Second); err == nil {
		srv.Shutdown()
		t.Fatalf("Start(%s) succeeded with the UDP port taken", addr)
	}
}

// TestStartFixedPortServesBothTransports starts on a specific free port and
// checks UDP and TCP both answer there.
func TestStartFixedPortServesBothTransports(t *testing.T) {
	var addr string
	for i := 0; i < 20 && addr == ""; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		candidate := pc.LocalAddr().String()
		pc.Close()
		if ln, err := net.Listen("tcp", candidate); err == nil {
			ln.Close()
			addr = candidate
		}
	}
	if addr == "" {
		t.Skip("no port free for both UDP and TCP")
	}
	srv := NewServer(Zone("example.com"), 0)
	if err := startWithin(t, srv, addr, 3*time.Second); err != nil {
		t.Fatalf("Start(%s): %v", addr, err)
	}
	defer srv.Shutdown()
	if got := "127.0.0.1:" + strconv.Itoa(srv.Port()); got != addr {
		t.Fatalf("Port() reports %s, want %s", got, addr)
	}
	assertAnswersOnBoth(t, srv, addr)
}

// TestStartManyEphemeralServers starts many servers at once on port 0. Each
// must bind UDP and TCP on the same port and answer on both, which exercises
// the retry when the kernel's free UDP port is taken for TCP.
func TestStartManyEphemeralServers(t *testing.T) {
	const n = 40
	servers := make([]*Server, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range servers {
		servers[i] = NewServer(Zone("example.com"), 0)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = servers[i].Start("127.0.0.1:0")
		}(i)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent Start calls blocked")
	}
	ports := map[int]bool{}
	for i, srv := range servers {
		if errs[i] != nil {
			t.Fatalf("server %d: %v", i, errs[i])
		}
		defer srv.Shutdown()
		if ports[srv.Port()] {
			t.Fatalf("port %d assigned twice", srv.Port())
		}
		ports[srv.Port()] = true
		assertAnswersOnBoth(t, srv, "127.0.0.1:"+strconv.Itoa(srv.Port()))
	}
}

// assertAnswersOnBoth publishes a record and queries it over UDP and TCP.
func assertAnswersOnBoth(t *testing.T, srv *Server, addr string) {
	t.Helper()
	name := dns.Fqdn("probe.g.example.com")
	if err := srv.PublishRaw(name, []byte("probe"), objectstore.TXT); err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"udp", "tcp"} {
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeTXT)
		c := &dns.Client{Net: network, Timeout: 2 * time.Second}
		resp, _, err := c.Exchange(q, addr)
		if err != nil {
			t.Fatalf("%s query to %s: %v", network, addr, err)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("%s query to %s: %d answers", network, addr, len(resp.Answer))
		}
	}
}
