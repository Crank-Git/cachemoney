package dnszone

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// startUnbound runs a real Unbound recursive resolver whose only route to
// example.com is a stub zone pointing at authAddr. It randomizes query case
// (use-caps-for-id) and minimizes query names, as public resolvers do, and
// returns its address. The test is skipped when unbound is not installed,
// unless CACHEMONEY_REQUIRE_UNBOUND is set (CI), where that is a failure.
func startUnbound(t *testing.T, authAddr string) string {
	t.Helper()
	bin, err := exec.LookPath("unbound")
	if err != nil {
		for _, p := range []string{"/usr/sbin/unbound", "/opt/homebrew/sbin/unbound", "/usr/local/sbin/unbound"} {
			if _, statErr := os.Stat(p); statErr == nil {
				bin, err = p, nil
				break
			}
		}
	}
	if err != nil {
		if os.Getenv("CACHEMONEY_REQUIRE_UNBOUND") != "" {
			t.Fatal("unbound is required (CACHEMONEY_REQUIRE_UNBOUND) but not installed")
		}
		t.Skip("unbound not installed")
	}
	host, port, err := net.SplitHostPort(authAddr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for attempt := 0; attempt < 5; attempt++ {
		ubPort := freeUDPTCPPort(t)
		conf := fmt.Sprintf(`server:
	interface: 127.0.0.1
	port: %d
	do-ip6: no
	do-daemonize: no
	username: ""
	chroot: ""
	directory: %q
	pidfile: %q
	use-syslog: no
	logfile: ""
	verbosity: 0
	access-control: 127.0.0.0/8 allow
	do-not-query-localhost: no
	module-config: "iterator"
	use-caps-for-id: yes
	qname-minimisation: yes
	edns-buffer-size: 1232
	harden-referral-path: no
	cache-max-ttl: 86400
remote-control:
	control-enable: no
stub-zone:
	name: "example.com"
	stub-addr: %s@%s
`, ubPort, dir, filepath.Join(dir, "unbound.pid"), host, port)
		confPath := filepath.Join(dir, "unbound.conf")
		if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, "-d", "-c", confPath)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			t.Fatalf("start unbound: %v", err)
		}
		addr := "127.0.0.1:" + strconv.Itoa(ubPort)
		exited := make(chan struct{})
		go func() { _ = cmd.Wait(); close(exited) }()
		if waitForResolver(addr, exited) {
			t.Cleanup(func() {
				_ = cmd.Process.Kill()
				<-exited
			})
			return addr
		}
		_ = cmd.Process.Kill()
		<-exited
		t.Logf("unbound attempt %d did not come up: %s", attempt+1, strings.TrimSpace(stderr.String()))
	}
	t.Fatal("unbound did not start")
	return ""
}

// waitForResolver polls addr with an SOA query for the stub zone until it
// answers, or the process exits, or 10 seconds pass.
func waitForResolver(addr string, exited <-chan struct{}) bool {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			return false
		default:
		}
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeSOA)
		if resp, _, err := (&dns.Client{Timeout: 500 * time.Millisecond}).Exchange(q, addr); err == nil && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 1 {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// freeUDPTCPPort returns a port that was free for both UDP and TCP.
func freeUDPTCPPort(t *testing.T) int {
	t.Helper()
	pc, ln, err := listenUDPAndTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	_ = ln.Close()
	return port
}

// TestThroughUnbound fetches objects through a real recursive resolver: the
// deployment this design depends on. It checks content-addressed objects and
// raw (git-scheme) objects resolve on both transports, a missing object fails
// cleanly, and, once the authoritative server is gone, objects are still
// served from the resolver's cache.
func TestThroughUnbound(t *testing.T) {
	for _, tr := range bothTransports {
		t.Run("transport="+strconv.Itoa(int(tr)), func(t *testing.T) {
			srv, _, shutdown := newTestServer(t, tr)
			defer shutdown()
			ub := startUnbound(t, "127.0.0.1:"+strconv.Itoa(srv.Port()))

			data := randBytes(300_000)
			m, chunks := objectstore.Build(data)
			if err := srv.Publish(m, chunks, tr); err != nil {
				t.Fatal(err)
			}
			raw := randBytes(20_000)
			sha := strings.Repeat("0f", 20)
			if err := srv.PublishRaw(dns.Fqdn(sha+".g.example.com"), raw, tr); err != nil {
				t.Fatal(err)
			}

			res := NewResolver(ub, Zone("example.com"), 3*time.Second)
			got, err := res.FetchByID(m.ID(), tr)
			if err != nil {
				t.Fatalf("FetchByID through unbound: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Fatal("FetchByID through unbound: content mismatch")
			}
			gotRaw, err := res.WithObjectSuffix("g").FetchRaw(sha, tr)
			if err != nil || !bytes.Equal(gotRaw, raw) {
				t.Fatalf("FetchRaw through unbound: %v", err)
			}
			missing, _ := objectstore.Build([]byte("never published"))
			if _, err := res.FetchByID(missing.ID(), tr); err == nil {
				t.Fatal("missing object resolved through unbound")
			}

			// Take the origin down. A fresh client (no cache of its own)
			// still gets every record from the resolver's cache.
			shutdown()
			again, err := NewResolver(ub, Zone("example.com"), 3*time.Second).FetchByID(m.ID(), tr)
			if err != nil {
				t.Fatalf("fetch from resolver cache with origin down: %v", err)
			}
			if !bytes.Equal(again, data) {
				t.Fatal("cached fetch: content mismatch")
			}
		})
	}
}
