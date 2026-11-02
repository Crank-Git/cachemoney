package dnszone

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// rawAnswer sends q to addr over network ("udp" or "tcp") and returns the
// exact message bytes the server wrote, so tests measure the wire rather than
// a re-packed message.
func rawAnswer(t *testing.T, network, addr string, q *dns.Msg) []byte {
	t.Helper()
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if network == "tcp" {
		prefix := make([]byte, 2)
		binary.BigEndian.PutUint16(prefix, uint16(len(wire)))
		wire = append(prefix, wire...)
	}
	if _, err := conn.Write(wire); err != nil {
		t.Fatal(err)
	}
	if network == "tcp" {
		prefix := make([]byte, 2)
		if _, err := io.ReadFull(conn, prefix); err != nil {
			t.Fatal(err)
		}
		msg := make([]byte, binary.BigEndian.Uint16(prefix))
		if _, err := io.ReadFull(conn, msg); err != nil {
			t.Fatal(err)
		}
		return msg
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

// TestAnswerNamesAreCompressed measures a 1 KB AAAA chunk answer on the wire
// over TCP, UDP with EDNS, and UDP without EDNS. With name compression every
// AAAA record costs exactly 28 bytes (2-byte pointer, type, class, TTL,
// rdlength, 16-byte address). TCP and non-EDNS UDP answers used to go out
// uncompressed at 6570 bytes; only EDNS UDP answers were compressed, as a side
// effect of truncation.
func TestAnswerNamesAreCompressed(t *testing.T) {
	srv, _, shutdown := newTestServer(t, objectstore.AAAA)
	defer shutdown()
	m, chunks := objectstore.Build(randBytes(1024))
	if err := srv.Publish(m, chunks, objectstore.AAAA); err != nil {
		t.Fatal(err)
	}
	name := srv.chunkName(m.ChunkIDs[0])
	records := len(objectstore.EncodeAAAA(objectstore.Frame{Payload: chunks[0]}))
	addr := "127.0.0.1:" + strconv.Itoa(srv.Port())

	for _, tc := range []struct {
		name    string
		network string
		edns    bool
	}{
		{"tcp", "tcp", false},
		{"udp-edns", "udp", true},
		{"udp-plain", "udp", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := new(dns.Msg)
			q.SetQuestion(name, dns.TypeAAAA)
			if tc.edns {
				q.SetEdns0(4096, false)
			}
			wire := rawAnswer(t, tc.network, addr, q)
			var resp dns.Msg
			if err := resp.Unpack(wire); err != nil {
				t.Fatal(err)
			}
			if resp.Truncated {
				// A non-EDNS UDP client may be truncated; nothing to measure.
				return
			}
			if len(resp.Answer) != records {
				t.Fatalf("got %d answers, want %d", len(resp.Answer), records)
			}
			question := len(name) + 1 + 4 // wire name (len+1 for an FQDN) + type + class
			opt := 0
			if resp.IsEdns0() != nil {
				opt = 11
			}
			want := 12 + question + records*28 + opt
			if len(wire) != want {
				t.Fatalf("answer is %d bytes on the wire, want %d (%d records x 28 + overhead)", len(wire), want, records)
			}
		})
	}
}
