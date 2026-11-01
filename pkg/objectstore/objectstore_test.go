package objectstore

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// TestUnmarshalManifest ensures manifest bytes round-trip through the parser
// and that invalid JSON is rejected. It is how LoadStore turns a stored
// manifest file back into a Manifest.
func TestUnmarshalManifest(t *testing.T) {
	data := []byte("round-trip the manifest through its own parser")
	m, _ := Build(data)
	b, err := m.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	back, err := UnmarshalManifest(b)
	if err != nil {
		t.Fatalf("UnmarshalManifest: %v", err)
	}
	if back.Version != m.Version || back.TotalSize != m.TotalSize || back.ChunkCount != m.ChunkCount {
		t.Fatalf("scalar fields changed: %+v vs %+v", back, m)
	}
	if len(back.ChunkIDs) != len(m.ChunkIDs) || len(back.ChunkLens) != len(m.ChunkLens) {
		t.Fatalf("chunk slices changed: %d/%d vs %d/%d", len(back.ChunkIDs), len(back.ChunkLens), len(m.ChunkIDs), len(m.ChunkLens))
	}
	if _, err := UnmarshalManifest([]byte("not json")); err == nil {
		t.Fatal("invalid JSON accepted, want error")
	}
}

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

// TestReassembleChunkTooShort ensures a present-but-short chunk is rejected
// before the hash check, so a truncated chunk fails loudly rather than
// silently shortening the reassembled payload.
func TestReassembleChunkTooShort(t *testing.T) {
	data := make([]byte, 3000)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	m, chunks := Build(data)
	if len(m.ChunkIDs) < 2 {
		t.Fatalf("expected >=2 chunks, got %d", len(m.ChunkIDs))
	}
	// Trim the first chunk below its recorded length.
	short := chunks[0][:m.ChunkLens[0]-1]
	rebuilt := map[ObjectID][]byte{m.ChunkIDs[0]: short, m.ChunkIDs[1]: chunks[1]}
	if _, err := Reassemble(m, rebuilt); err == nil {
		t.Fatal("expected too-short chunk to fail, got nil")
	}
}

// TestDecodeAAAAErrorBranches exercises every DecodeAAAA failure path: a record
// too short to carry a sequence byte, an empty answer, a payload too short to
// hold the length prefix, and a length prefix that exceeds the data.
func TestDecodeAAAAErrorBranches(t *testing.T) {
	if _, err := DecodeAAAA([][]byte{{0x00}}); err == nil {
		t.Error("DecodeAAAA: single byte record, want error")
	}
	if _, err := DecodeAAAA([][]byte{}); err == nil {
		t.Error("DecodeAAAA: empty answer, want error")
	}
	// 2 bytes total -> payload is 1 byte, too short for the 4-byte length prefix.
	if _, err := DecodeAAAA([][]byte{{0x00, 0x00}}); err == nil {
		t.Error("DecodeAAAA: payload too short for length prefix, want error")
	}
	// Length prefix claims 100 bytes but only 2 are present.
	bad := make([]byte, 6)
	binary.BigEndian.PutUint32(bad[:4], 100)
	if _, err := DecodeAAAA([][]byte{bad}); err == nil {
		t.Error("DecodeAAAA: length exceeds available, want error")
	}
}

// TestDecodeTXTErrorBranches exercises every DecodeTXT failure path: a record
// with no sequence separator, a non-numeric sequence, and an empty answer.
func TestDecodeTXTErrorBranches(t *testing.T) {
	if _, err := DecodeTXT([]string{"noseparator"}); err == nil {
		t.Error("DecodeTXT: record without ':' separator, want error")
	}
	if _, err := DecodeTXT([]string{"notanum:Zm9v"}); err == nil {
		t.Error("DecodeTXT: non-numeric sequence, want error")
	}
	if _, err := DecodeTXT(nil); err == nil {
		t.Error("DecodeTXT: empty answer, want error")
	}
}

// TestEncodeTXTEmptyPayload documents that an empty payload encodes to a single
// "0:" record and round-trips back to empty rather than to nil or padding.
func TestEncodeTXTEmptyPayload(t *testing.T) {
	recs := EncodeTXT(Frame{Index: 0, Payload: nil})
	if len(recs) != 1 || recs[0] != "0:" {
		t.Fatalf("empty payload encode = %v, want [0:]", recs)
	}
	got, err := DecodeTXT(recs)
	if err != nil {
		t.Fatalf("decode empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty payload round-trip = %d bytes, want 0", len(got))
	}
}
