package objectstore

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestIndirectManifestSmallUnchanged checks a manifest that fits one record is
// stored as is, so small objects need no extra lookups.
func TestIndirectManifestSmallUnchanged(t *testing.T) {
	m, _ := Build([]byte("small"))
	mb, _ := m.Bytes()
	rec, ids, chunks, err := IndirectManifest(mb)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rec, mb) || len(ids) != 0 || len(chunks) != 0 {
		t.Fatalf("small manifest was wrapped: %d extra chunks", len(chunks))
	}
}

// TestIndirectManifestLargeRoundTrip wraps the manifest of a 2 MB object and
// follows the chain back by hand: the outer record must fit one record, every
// extra chunk must be within the chunk size and hash to its id, and
// reassembling level by level must reproduce the original manifest bytes.
func TestIndirectManifestLargeRoundTrip(t *testing.T) {
	data := make([]byte, 2<<20)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	m, _ := Build(data)
	mb, _ := m.Bytes()
	if len(mb) <= MaxRecordPayload {
		t.Fatalf("test needs a manifest over one record, got %d bytes", len(mb))
	}
	rec, ids, chunks, err := IndirectManifest(mb)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec) > MaxRecordPayload {
		t.Fatalf("outer record is %d bytes, limit %d", len(rec), MaxRecordPayload)
	}
	store := map[ObjectID][]byte{}
	for i, c := range chunks {
		if len(c) > DefaultChunkSize {
			t.Fatalf("manifest chunk %d is %d bytes", i, len(c))
		}
		if ChunkID(c) != ids[i] {
			t.Fatalf("manifest chunk %d does not hash to its id", i)
		}
		store[ids[i]] = c
	}
	levels := 0
	cur := rec
	for {
		im, err := UnmarshalManifest(cur)
		if err != nil {
			t.Fatalf("level %d: %v", levels, err)
		}
		if !im.Indirect {
			break
		}
		levels++
		if cur, err = Reassemble(im, store); err != nil {
			t.Fatalf("level %d: %v", levels, err)
		}
	}
	if !bytes.Equal(cur, mb) {
		t.Fatal("following the chain did not reproduce the manifest")
	}
	if levels < 2 {
		t.Fatalf("a 2 MB manifest should need at least 2 levels, got %d", levels)
	}
	if m.Indirect {
		t.Fatal("the object's own manifest must not be marked indirect")
	}
}

// TestRecordPayloadFitsAAAASequence checks the largest record payload encodes
// to far fewer than the 256 AAAA records the sequence byte can number.
func TestRecordPayloadFitsAAAASequence(t *testing.T) {
	addrs := EncodeAAAA(Frame{Payload: make([]byte, MaxRecordPayload)})
	if len(addrs) > 255 {
		t.Fatalf("%d AAAA records would wrap the sequence byte", len(addrs))
	}
	for i, a := range addrs {
		if int(a[0]) != i {
			t.Fatalf("record %d has sequence %d", i, a[0])
		}
	}
}

// TestBuildChunksWithinRecordLimit checks Build never emits a chunk larger than
// one record.
func TestBuildChunksWithinRecordLimit(t *testing.T) {
	for _, n := range []int{0, 1, MaxRecordPayload, MaxRecordPayload + 1, 100_000} {
		_, chunks := Build(make([]byte, n))
		for i, c := range chunks {
			if len(c) > MaxRecordPayload {
				t.Fatalf("Build(%d): chunk %d is %d bytes", n, i, len(c))
			}
		}
	}
}
