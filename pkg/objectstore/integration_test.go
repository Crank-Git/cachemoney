package objectstore

import (
	"bytes"
	"encoding/json"
	"testing"
)

// DNSStore is an in-memory stand-in for a DNS zone. It stores the encoded
// transport representation of every record keyed by object id, and lets a
// client "fetch" them exactly as a resolver would return them.
type DNSStore struct {
	transport Transport
	manifests map[ObjectID][]any
	chunks    map[ObjectID][]any
}

// Transport selects how payloads are framed on the way in and out.
type Transport int

const (
	TXT Transport = iota
	AAAA
)

func NewDNSStore(t Transport) *DNSStore {
	return &DNSStore{transport: t, manifests: map[ObjectID][]any{}, chunks: map[ObjectID][]any{}}
}

// Publish frames an already-built object into the store.
func (s *DNSStore) Publish(m *Manifest, chunks [][]byte) {
	b, _ := m.Bytes()
	s.manifests[m.ID()] = []any{string(b)}
	for i, c := range chunks {
		s.chunks[m.ChunkIDs[i]] = s.frame(Frame{Index: i, Payload: c})
	}
}

func (s *DNSStore) frame(f Frame) []any {
	if s.transport == TXT {
		out := make([]any, len(EncodeTXT(f)))
		for i, r := range EncodeTXT(f) {
			out[i] = r
		}
		return out
	}
	out := make([]any, len(EncodeAAAA(f)))
	for i, b := range EncodeAAAA(f) {
		out[i] = b
	}
	return out
}

// Client fetches a manifest and all its chunks, then reassembles.
func (s *DNSStore) Fetch(m *Manifest) ([]byte, error) {
	raw, ok := s.manifests[m.ID()]
	if !ok {
		return nil, errNotFound
	}
	var check Manifest
	if err := json.Unmarshal([]byte(raw[0].(string)), &check); err != nil {
		return nil, err
	}
	chunks := make(map[ObjectID][]byte, len(check.ChunkIDs))
	for _, id := range check.ChunkIDs {
		recs, ok := s.chunks[id]
		if !ok {
			return nil, errNotFound
		}
		p, err := s.unframe(recs)
		if err != nil {
			return nil, err
		}
		chunks[id] = p
	}
	return Reassemble(&check, chunks)
}

func (s *DNSStore) unframe(v []any) ([]byte, error) {
	if s.transport == TXT {
		ss := make([]string, len(v))
		for i, x := range v {
			ss[i] = x.(string)
		}
		return DecodeTXT(ss)
	}
	bb := make([][]byte, len(v))
	for i, x := range v {
		bb[i] = x.([]byte)
	}
	return DecodeAAAA(bb)
}

var errNotFound = &notFoundErr{}

type notFoundErr struct{}

func (*notFoundErr) Error() string { return "object not found in store" }

// TestIntegrationRoundTrip walks the full graph for both transports.
func TestIntegrationRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		transport Transport
	}{
		{"txt", TXT},
		{"aaaa", AAAA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("content-addressed objects over dns: " + tc.name + " transport round-trip test")
			store := NewDNSStore(tc.transport)
			m, chunks := Build(payload)
			if m.ID() == "" {
				t.Fatal("empty manifest id")
			}
			store.Publish(m, chunks)
			got, err := store.Fetch(m)
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("round-trip mismatch: got %q", got)
			}
		})
	}
}

// TestIntegrationMissingRef ensures a missing object fails loudly.
func TestIntegrationMissingRef(t *testing.T) {
	store := NewDNSStore(TXT)
	m, _ := Build([]byte("not published"))
	if _, err := store.Fetch(m); err == nil {
		t.Fatal("expected not-found error, got nil")
	}
}
