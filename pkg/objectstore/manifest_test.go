package objectstore

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// validManifest returns a three-chunk manifest and its chunks for mutation.
func validManifest(t *testing.T) (*Manifest, [][]byte) {
	t.Helper()
	m, chunks := Build(bytes.Repeat([]byte("abcdefgh"), 300))
	if m.ChunkCount < 2 {
		t.Fatalf("need >=2 chunks, got %d", m.ChunkCount)
	}
	return m, chunks
}

// TestValidateRejectsInconsistentManifests covers every way a manifest can
// disagree with itself. Each case would previously panic or mis-read in
// Reassemble.
func TestValidateRejectsInconsistentManifests(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(m *Manifest)
		want   string
	}{
		{"wrong version", func(m *Manifest) { m.Version = 99 }, "version"},
		{"zero version", func(m *Manifest) { m.Version = 0 }, "version"},
		{"lens shorter than ids", func(m *Manifest) { m.ChunkLens = m.ChunkLens[:1] }, "disagree"},
		{"lens missing", func(m *Manifest) { m.ChunkLens = nil }, "disagree"},
		{"ids shorter than lens", func(m *Manifest) { m.ChunkIDs = m.ChunkIDs[:1]; m.ChunkCount = 1 }, "disagree"},
		{"count mismatch", func(m *Manifest) { m.ChunkCount++ }, "disagree"},
		{"negative length", func(m *Manifest) { m.ChunkLens[0] = -1 }, "negative"},
		{"overflowing lengths", func(m *Manifest) {
			m.ChunkLens[0] = math.MaxInt64
			m.ChunkLens[1] = 1
		}, "overflow"},
		{"total too large", func(m *Manifest) { m.TotalSize++ }, "sum"},
		{"total too small", func(m *Manifest) { m.TotalSize-- }, "sum"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := validManifest(t)
			tc.mutate(m)
			err := m.Validate()
			if err == nil {
				t.Fatal("Validate accepted an inconsistent manifest")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestValidateAcceptsBuiltManifests checks Build always produces a manifest
// that passes Validate, including the empty object.
func TestValidateAcceptsBuiltManifests(t *testing.T) {
	for _, n := range []int{0, 1, DefaultChunkSize - 1, DefaultChunkSize, DefaultChunkSize + 1, 10 * DefaultChunkSize} {
		m, _ := Build(make([]byte, n))
		if err := m.Validate(); err != nil {
			t.Fatalf("Build(%d bytes) produced invalid manifest: %v", n, err)
		}
	}
}

// TestReassembleMalformedManifestNoPanic feeds Reassemble manifests that used
// to index out of range or slice with a negative bound. Every one must return
// an error instead of panicking.
func TestReassembleMalformedManifestNoPanic(t *testing.T) {
	m, chunks := validManifest(t)
	have := map[ObjectID][]byte{}
	for i, id := range m.ChunkIDs {
		have[id] = chunks[i]
	}
	bad := []*Manifest{
		{Version: ManifestVersion, ChunkCount: 1, ChunkIDs: m.ChunkIDs[:1]},                                        // no lens
		{Version: ManifestVersion, ChunkCount: 1, ChunkIDs: m.ChunkIDs[:1], ChunkLens: []int64{-5}, TotalSize: -5}, // negative
	}
	for i, bm := range bad {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("case %d: Reassemble panicked: %v", i, r)
				}
			}()
			if _, err := Reassemble(bm, have); err == nil {
				t.Fatalf("case %d: Reassemble accepted a malformed manifest", i)
			}
		}()
	}
}

// TestUnmarshalManifestValidates ensures parsing rejects well-formed JSON that
// describes an inconsistent object, so no caller can skip validation.
func TestUnmarshalManifestValidates(t *testing.T) {
	m, _ := validManifest(t)
	m.ChunkLens = m.ChunkLens[:1]
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalManifest(b); err == nil {
		t.Fatal("UnmarshalManifest accepted an inconsistent manifest")
	}
}

// TestVerifyManifest checks the manifest is accepted only under the id its
// bytes hash to.
func TestVerifyManifest(t *testing.T) {
	m, _ := validManifest(t)
	b, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyManifest(m.ID(), b)
	if err != nil {
		t.Fatalf("VerifyManifest(own id): %v", err)
	}
	if got.ID() != m.ID() {
		t.Fatalf("verified manifest id %s, want %s", got.ID(), m.ID())
	}

	other, _ := Build([]byte("a different object"))
	if _, err := VerifyManifest(other.ID(), b); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("VerifyManifest under a foreign id: err=%v, want hash mismatch", err)
	}

	// One flipped byte anywhere invalidates the address.
	flipped := append([]byte(nil), b...)
	flipped[len(flipped)/2] ^= 0x20
	if _, err := VerifyManifest(m.ID(), flipped); err == nil {
		t.Fatal("VerifyManifest accepted modified bytes")
	}

	// Bytes that hash to the id but fail validation are still rejected.
	bad := []byte(`{"version":1,"totalSize":5,"chunkCount":1,"chunkIDs":["X"],"chunkLens":[]}`)
	if _, err := VerifyManifest(ObjectID(ToLabel(HashBytes(bad))), bad); err == nil {
		t.Fatal("VerifyManifest accepted an inconsistent manifest with a matching hash")
	}
}
