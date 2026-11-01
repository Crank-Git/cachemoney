package objectstore

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"testing"
)

func TestContentAddressedSameInputSameID(t *testing.T) {
	m1, _ := Build([]byte("hello world"))
	m2, _ := Build([]byte("hello world"))
	if m1.ID() != m2.ID() {
		t.Fatalf("identical content produced different IDs: %s != %s", m1.ID(), m2.ID())
	}
}

func TestManifestIDStableAndJSONRoundTrip(t *testing.T) {
	m, _ := Build([]byte("the quick brown fox"))
	b, err := m.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	var back Manifest
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.ID() != m.ID() {
		t.Fatalf("round-tripped manifest id changed: %s != %s", back.ID(), m.ID())
	}
}

func TestChunkIDMatchesContent(t *testing.T) {
	data := []byte("chunk me please")
	m, chunks := Build(data)
	for i, c := range chunks {
		if m.ChunkIDs[i] != ChunkID(c) {
			t.Fatalf("chunk %d id mismatch", i)
		}
	}
}

// enc/dec pair signatures for the transport table.
type transport struct {
	name string
	enc  func(Frame) []any
	dec  func([]any) ([]byte, error)
}

func encTXT(f Frame) []any {
	out := make([]any, len(EncodeTXT(f)))
	for i, s := range EncodeTXT(f) {
		out[i] = s
	}
	return out
}

func decTXT(v []any) ([]byte, error) {
	ss := make([]string, len(v))
	for i, x := range v {
		ss[i] = x.(string)
	}
	return DecodeTXT(ss)
}

func encAAAA(f Frame) []any {
	out := make([]any, len(EncodeAAAA(f)))
	for i, b := range EncodeAAAA(f) {
		out[i] = b
	}
	return out
}

func decAAAA(v []any) ([]byte, error) {
	bb := make([][]byte, len(v))
	for i, x := range v {
		bb[i] = x.([]byte)
	}
	return DecodeAAAA(bb)
}

func TestReassembleRoundTripTransports(t *testing.T) {
	transports := []transport{
		{"txt", encTXT, decTXT},
		{"aaaa", encAAAA, decAAAA},
	}
	sizes := []int{0, 1, 100, 1023, 1024, 1025, 5000, 65536}
	for _, tr := range transports {
		for _, size := range sizes {
			data := make([]byte, size)
			if _, err := rand.Read(data); err != nil {
				t.Fatal(err)
			}
			m, chunks := Build(data)
			frames := make([]Frame, len(chunks))
			for i, c := range chunks {
				frames[i] = Frame{Index: i, Payload: c}
			}
			encoded := make([]any, len(frames))
			for i, f := range frames {
				encoded[i] = tr.enc(f)
			}
			rebuilt := make(map[ObjectID][]byte, len(encoded))
			for i, id := range m.ChunkIDs {
				p, err := tr.dec(encoded[i].([]any))
				if err != nil {
					t.Fatalf("%s size=%d: decode: %v", tr.name, size, err)
				}
				// Transports like AAAA right-pad the final record; the manifest's
				// ChunkLens trims this back, which Reassemble also does.
				if len(p) > len(frames[i].Payload) {
					p = p[:len(frames[i].Payload)]
				}
				rebuilt[id] = p
			}
			got, err := Reassemble(m, rebuilt)
			if err != nil {
				t.Fatalf("%s size=%d: reassemble: %v", tr.name, size, err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("%s size=%d: reassembled bytes mismatch", tr.name, size)
			}
		}
	}
}

func TestReassembleOrderSafe(t *testing.T) {
	// >255 bytes so the payload splits across multiple TXT character-strings,
	// which is what lets us prove the decoder is order-independent.
	data := bytes.Repeat([]byte("order "), 100)
	_, chunks := Build(data)
	recs := EncodeTXT(Frame{Index: 0, Payload: chunks[0]})
	if len(recs) < 2 {
		t.Fatalf("expected multiple txt pieces to test reordering, got %d", len(recs))
	}
	reversed := make([]string, len(recs))
	for i, r := range recs {
		reversed[len(recs)-1-i] = r
	}
	got, err := DecodeTXT(reversed)
	if err != nil {
		t.Fatalf("decode shuffled txt: %v", err)
	}
	if !bytes.Equal(got, chunks[0]) {
		t.Fatalf("shuffled txt did not reassemble: got %q want %q", got, chunks[0])
	}
}

func TestReassembleDetectsTampering(t *testing.T) {
	m, chunks := Build([]byte("do not tamper with this payload"))
	recs := EncodeTXT(Frame{Index: 0, Payload: chunks[0]})
	recs[0] = "0:" + "e290b3NvdCByZXR0b3Njb2RlZA==" // wrong base64 body
	rebuilt := map[ObjectID][]byte{m.ChunkIDs[0]: mustDecodeTXT(t, recs)}
	if _, err := Reassemble(m, rebuilt); err == nil {
		t.Fatal("expected tamper to fail hash check, got nil")
	}
}

func TestReassembleDetectsMissingChunk(t *testing.T) {
	// >DefaultChunkSize so Build yields multiple chunks.
	data := make([]byte, 3000)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	m, _ := Build(data)
	if len(m.ChunkIDs) < 2 {
		t.Fatalf("expected >=2 chunks, got %d", len(m.ChunkIDs))
	}
	if _, err := Reassemble(m, map[ObjectID][]byte{}); err == nil {
		t.Fatal("expected missing-chunk error, got nil")
	}
}

func mustDecodeTXT(t *testing.T, recs []string) []byte {
	t.Helper()
	p, err := DecodeTXT(recs)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return p
}
