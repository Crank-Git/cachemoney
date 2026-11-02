package dnszone

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// TestResolverDoH resolves an object over DNS over HTTPS. The test server is a
// plain HTTP handler that unpacks the POSTed application/dns-message, answers it
// from the same in-memory record map, and returns the packed response -- the
// exact shape a public DoH endpoint serves.
func TestResolverDoH(t *testing.T) {
	data := randBytes(3000)
	srv, res, shutdown := newTestServer(t, objectstore.TXT)
	defer shutdown()
	m, chunks := objectstore.Build(data)
	if err := srv.Publish(m, chunks, objectstore.TXT); err != nil {
		t.Fatalf("publish: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		var q dns.Msg
		if err := q.Unpack(body); err != nil {
			http.Error(w, "unpack", http.StatusBadRequest)
			return
		}
		out, err := srv.answer(&q).Pack()
		if err != nil {
			http.Error(w, "pack", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		if _, err := w.Write(out); err != nil {
			http.Error(w, "write", http.StatusInternalServerError)
			return
		}
	})
	doh := httptest.NewServer(mux)
	defer doh.Close()

	// The resolver talks to the DoH endpoint instead of a UDP/TCP server: the
	// server address is irrelevant once WithDoH is set.
	res = res.WithDoH(doh.URL)
	got, err := res.FetchByID(m.ID(), objectstore.TXT)
	if err != nil {
		t.Fatalf("fetch via DoH: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("DoH returned wrong bytes")
	}
}

// TestResolverDoHRejectsHTTPError ensures a DoH endpoint that does not return
// 200 surfaces as an error rather than being misinterpreted as a DNS answer.
func TestResolverDoHRejectsHTTPError(t *testing.T) {
	doh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer doh.Close()

	res := NewResolver("", Zone("example.com"), 5*time.Second).WithDoH(doh.URL)
	if _, err := res.FetchByID("missing", objectstore.TXT); err == nil {
		t.Fatal("fetch via DoH succeeded for a 500, want error")
	}
}

// selfSignedCert returns a server-side *tls.Config carrying a self-signed
// certificate for 127.0.0.1/localhost and a client cert pool trusting that
// certificate, so a DoT test can complete a real TLS handshake without a CA.
func selfSignedCert(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	serverCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	serverCfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(serverCert)
	return serverCfg, clientRoots
}

// startDoTServer runs a raw miekg/dns server over TLS on an ephemeral port,
// answering from srv's record map, and returns its "127.0.0.1:port" address.
func startDoTServer(t *testing.T, srv *Server, serverCfg *tls.Config) string {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		_ = w.WriteMsg(srv.answer(req))
	})
	ready := make(chan struct{})
	dot := &dns.Server{
		Net:               "tcp-tls",
		Addr:              "127.0.0.1:0",
		TLSConfig:         serverCfg,
		Handler:           mux,
		NotifyStartedFunc: func() { close(ready) },
	}
	go func() {
		if err := dot.ListenAndServe(); err != nil {
			t.Errorf("dot server exited: %v", err)
		}
	}()
	<-ready
	t.Cleanup(func() { _ = dot.Shutdown() })
	addr, ok := dot.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("dot server did not bind a TCP listener")
	}
	return addr.String()
}

// TestResolverDoT resolves an object over DNS over TLS against a local TLS
// server presenting a self-signed certificate trusted via a custom root pool.
func TestResolverDoT(t *testing.T) {
	data := randBytes(3000)
	srv, _, shutdown := newTestServer(t, objectstore.AAAA)
	defer shutdown()
	m, chunks := objectstore.Build(data)
	if err := srv.Publish(m, chunks, objectstore.AAAA); err != nil {
		t.Fatalf("publish: %v", err)
	}
	serverCfg, roots := selfSignedCert(t)
	addr := startDoTServer(t, srv, serverCfg)

	res := NewResolver("", Zone("example.com"), 5*time.Second).WithDoTConfig(addr, roots)
	got, err := res.FetchByID(m.ID(), objectstore.AAAA)
	if err != nil {
		t.Fatalf("fetch via DoT: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("DoT returned wrong bytes")
	}
}

// TestResolverOptionSetters verifies the transport option setters configure the
// resolver's network, server, and underlying client as documented, exercising
// the newClient branches (plain TCP and the system-root DoT path) and
// systemRootsTLS.
func TestResolverOptionSetters(t *testing.T) {
	base := NewResolver("", Zone("example.com"), 5*time.Second)

	if got := base.WithNet("tcp").client.Net; got != "tcp" {
		t.Fatalf("WithNet(tcp): client.Net = %q, want tcp", got)
	}
	if got := base.WithNet("udp").client.Net; got != "udp" {
		t.Fatalf("WithNet(udp): client.Net = %q, want udp", got)
	}

	dot := base.WithDoT("1.1.1.1:853")
	if dot.net != "tcp-tls" || dot.server != "1.1.1.1:853" {
		t.Fatalf("WithDoT set net=%q server=%q, want tcp-tls / 1.1.1.1:853", dot.net, dot.server)
	}
	if dot.client.Net != "tcp-tls" {
		t.Fatalf("WithDoT did not build a tcp-tls client, got %q", dot.client.Net)
	}
	if dot.tlsConfig != nil {
		t.Fatal("WithDoT should leave tlsConfig nil (use system roots)")
	}

	_, roots := selfSignedCert(t)
	cfg := base.WithDoTConfig("1.1.1.1:853", roots)
	if cfg.tlsConfig == nil || cfg.tlsConfig.RootCAs != roots {
		t.Fatal("WithDoTConfig should install the supplied root pool")
	}
}

// staticTransport is an http.RoundTripper that returns a fixed response and/or
// error, letting tests drive the DoH client's failure paths directly.
type staticTransport struct {
	resp *http.Response
	err  error
}

func (t staticTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return t.resp, t.err
}

// exchangeDoHResponse builds a 200 response whose body streams from body.
func exchangeDoHResponse(body io.ReadCloser) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       body,
		Header:     make(http.Header),
	}
}

// TestExchangeDoHErrors drives each DoH failure branch: an invalid request URL,
// a transport that refuses the connection, a body that errors mid-read, and a
// well-formed HTTP 200 whose payload is not a valid DNS message.
func TestExchangeDoHErrors(t *testing.T) {
	res := NewResolver("", Zone("example.com"), 5*time.Second)
	m := &dns.Msg{}
	m.SetQuestion("missing.txt.example.com.", dns.TypeTXT)

	tests := []struct {
		name    string
		url     string
		client  *http.Client
		wantSub string
	}{
		{
			name:    "bad-url",
			url:     "://invalid",
			wantSub: "build doh request",
		},
		{
			name:    "transport-error",
			url:     "https://example.com/dns-query",
			client:  &http.Client{Transport: staticTransport{err: errBoom}},
			wantSub: "doh request failed",
		},
		{
			name:    "body-error",
			url:     "https://example.com/dns-query",
			client:  &http.Client{Transport: staticTransport{resp: exchangeDoHResponse(&errBody{err: errBoom})}},
			wantSub: "read doh response",
		},
		{
			name:    "garbage-body",
			url:     "https://example.com/dns-query",
			client:  &http.Client{Transport: staticTransport{resp: exchangeDoHResponse(io.NopCloser(bytes.NewReader([]byte("not a dns message"))))}},
			wantSub: "unpack doh response",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := res.WithDoH(tc.url)
			if tc.client != nil {
				r.dohClient = tc.client
			}
			_, err := r.exchangeDoH(m)
			if err == nil {
				t.Fatalf("exchangeDoH succeeded, want error containing %q", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("exchangeDoH error = %q, want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

var errBoom = errors.New("boom")

// errBody is an io.ReadCloser that fails on Read.
type errBody struct{ err error }

func (e *errBody) Read([]byte) (int, error) { return 0, e.err }
func (e *errBody) Close() error             { return nil }
