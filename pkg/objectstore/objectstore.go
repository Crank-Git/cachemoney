// Package objectstore is the content-addressed core of cachemoney.
//
// It splits objects into chunks named by their own content hash, describes
// them in a content-addressed manifest, and frames each chunk for DNS
// transport (TXT or AAAA). Because every piece is addressed by its hash,
// caching is always correct: identical bytes always share one identity.
//
// This is the first spike of the project. The on-wire DNS framing here is a
// working, tested model; the exact label scheme is a spec to be finalized
// with contributors (see README "Open questions").
package objectstore

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Constants describing the current framing model. Tunable, not yet canonical.
const (
	// ManifestVersion is the current manifest format version.
	ManifestVersion = 1

	// DefaultChunkSize is the logical chunk size in bytes.
	DefaultChunkSize = 1024

	// TXTCharStrMax is the max bytes per DNS TXT character-string (RFC 1035).
	TXTCharStrMax = 255

	// AAAAPayloadPerRecord is the payload bytes carried per AAAA record.
	// AAAA is a fixed 16-byte address; the top byte holds the sequence
	// number so resolvers may reorder records without corrupting data.
	AAAAPayloadPerRecord = 15
)

// Transport selects how a chunk or manifest is framed for DNS. TXT uses
// character-strings; AAAA packs raw payload into 16-byte addresses.
type Transport int

const (
	// TXT frames payloads as DNS TXT character-strings.
	TXT Transport = iota
	// AAAA frames payloads as DNS AAAA addresses.
	AAAA
)

// b32 is lowercase, unpadded base32 (RFC 4648). A SHA-256 hash -> ~51 chars,
// which fits inside the 63-char DNS label limit (hex would be 64).
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ObjectID is a base32 label: the identity of a chunk, manifest, or object.
type ObjectID string

// HashBytes returns the SHA-256 of data.
func HashBytes(data []byte) [sha256.Size]byte { return sha256.Sum256(data) }

// ToLabel base32-encodes a hash into a DNS label.
func ToLabel(h [sha256.Size]byte) string { return b32.EncodeToString(h[:]) }

// ChunkID returns the base32 label of a chunk's content hash.
func ChunkID(data []byte) ObjectID { return ObjectID(ToLabel(HashBytes(data))) }

// Manifest describes how to reassemble an object from its chunks. Its only
// content-derived fields make the manifest itself content-addressed:
// identical objects produce identical manifests.
//
// ChunkLens records each chunk's exact byte length. This is required because
// some transports (notably AAAA, whose 16-byte address carries 15 payload
// bytes) cannot convey a chunk's length on their own; the decoder pads the
// final record and the manifest tells the client how much to keep.
type Manifest struct {
	Version    int            `json:"version"`
	TotalSize  int64          `json:"totalSize"`
	ChunkCount int            `json:"chunkCount"`
	ChunkIDs   []ObjectID     `json:"chunkIDs"`
	ChunkLens  []int64        `json:"chunkLens"`
	Meta       map[string]any `json:"meta,omitempty"`
}

// Bytes returns the canonical manifest bytes (used as the manifest's own ID).
func (m *Manifest) Bytes() ([]byte, error) { return json.Marshal(m) }

// ID returns the content address of the manifest.
func (m *Manifest) ID() ObjectID {
	b, err := m.Bytes()
	if err != nil {
		return ""
	}
	return ObjectID(ToLabel(HashBytes(b)))
}

// UnmarshalManifest parses manifest bytes and validates them (see Validate).
// The manifest's own ID can be derived from these bytes, so a stored file and
// its address are mutually verifiable.
func UnmarshalManifest(b []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("objectstore: unmarshal manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// VerifyManifest parses manifest bytes fetched under id, first checking that
// the bytes hash to id. It is how a client trusts a manifest it did not build:
// the address is the hash, so bytes that do not hash to it are rejected before
// any field is read.
func VerifyManifest(id ObjectID, b []byte) (*Manifest, error) {
	if got := ObjectID(ToLabel(HashBytes(b))); got != id {
		return nil, fmt.Errorf("objectstore: manifest %s hash mismatch (got %s)", id, got)
	}
	return UnmarshalManifest(b)
}

// Validate checks that a manifest is internally consistent: a known version,
// one length per chunk id, a chunk count that matches, non-negative lengths,
// and lengths that sum to the total size. A manifest that fails Validate is
// never used to reassemble an object.
func (m *Manifest) Validate() error {
	if m.Version != ManifestVersion {
		return fmt.Errorf("objectstore: unsupported manifest version %d", m.Version)
	}
	if m.ChunkCount != len(m.ChunkIDs) || len(m.ChunkLens) != len(m.ChunkIDs) {
		return fmt.Errorf("objectstore: manifest chunk count %d, ids %d, lens %d disagree", m.ChunkCount, len(m.ChunkIDs), len(m.ChunkLens))
	}
	var total int64
	for i, n := range m.ChunkLens {
		if n < 0 {
			return fmt.Errorf("objectstore: manifest chunk %d has negative length %d", i, n)
		}
		if n > math.MaxInt64-total {
			return fmt.Errorf("objectstore: manifest chunk lengths overflow")
		}
		total += n
	}
	if total != m.TotalSize {
		return fmt.Errorf("objectstore: manifest chunk lengths sum to %d, total size is %d", total, m.TotalSize)
	}
	return nil
}

// Build splits data into chunks and returns a manifest plus the raw chunk
// payloads in order.
func Build(data []byte) (*Manifest, [][]byte) {
	chunkSize := DefaultChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	chunks := make([][]byte, 0, len(data)/chunkSize+1)
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	n := len(chunks)
	ids := make([]ObjectID, n)
	lens := make([]int64, n)
	for i, c := range chunks {
		ids[i] = ChunkID(c)
		lens[i] = int64(len(c))
	}
	return &Manifest{
		Version:    ManifestVersion,
		TotalSize:  int64(len(data)),
		ChunkCount: n,
		ChunkIDs:   ids,
		ChunkLens:  lens,
	}, chunks
}

// Frame is one chunk's payload plus its position within the object.
type Frame struct {
	Index   int
	Payload []byte
}

// EncodeTXT encodes a frame into DNS TXT character-strings. Each string is
// "<seq>:<base64-piece>" so a resolver that reorders records can be
// reassembled by sequence number.
func EncodeTXT(f Frame) []string {
	enc := base64.StdEncoding.EncodeToString(f.Payload)
	out := make([]string, 0, len(enc)/TXTCharStrMax+1)
	for i := 0; len(enc) > 0; i++ {
		seq := strconv.Itoa(i)
		// The "<seq>:" prefix counts toward the 255-byte limit, so cap the
		// piece at whatever room remains for this sequence number. room stays
		// positive for any realistic payload (a room of 0 would need a
		// 254-digit sequence number).
		room := TXTCharStrMax - len(seq) - 1
		if room < 1 {
			room = 1
		}
		piece := enc
		if len(piece) > room {
			piece = piece[:room]
		}
		out = append(out, seq+":"+piece)
		enc = enc[len(piece):]
	}
	if len(out) == 0 {
		return []string{"0:"}
	}
	return out
}

// DecodeTXT reconstructs a chunk's payload from TXT character-strings.
func DecodeTXT(records []string) ([]byte, error) {
	type item struct {
		seq int
		val string
		has bool
	}
	items := make([]item, 0, len(records))
	for _, r := range records {
		ci := strings.IndexByte(r, ':')
		if ci < 0 {
			return nil, fmt.Errorf("objectstore: bad txt record %q", r)
		}
		seq, err := strconv.Atoi(r[:ci])
		if err != nil {
			return nil, fmt.Errorf("objectstore: bad seq in %q: %w", r, err)
		}
		items = append(items, item{seq: seq, val: r[ci+1:]})
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("objectstore: no txt records")
	}
	sort.Slice(items, func(i, j int) bool { return items[i].seq < items[j].seq })
	var enc strings.Builder
	for _, it := range items {
		enc.WriteString(it.val)
	}
	return base64.StdEncoding.DecodeString(enc.String())
}

// EncodeAAAA encodes a frame into AAAA addresses. The top byte of each 16-byte
// address is the sequence number; the low 15 bytes carry the payload. Records
// may be returned in any order by a resolver; the sequence byte restores it.
//
// The payload is prefixed with its 4-byte big-endian length. AAAA right-pads
// the final record with null bytes, which is ambiguous with content that
// legitimately ends in a null byte (a binary package file, an index ending in
// its NUL terminator). The recorded length lets the decoder recover the exact
// payload rather than guessing where the content ends.
func EncodeAAAA(f Frame) [][]byte {
	body := make([]byte, 4+len(f.Payload))
	binary.BigEndian.PutUint32(body[:4], uint32(len(f.Payload)))
	copy(body[4:], f.Payload)

	out := make([][]byte, 0, (len(body)+AAAAPayloadPerRecord-1)/AAAAPayloadPerRecord)
	for i := 0; i < len(body); i += AAAAPayloadPerRecord {
		end := i + AAAAPayloadPerRecord
		if end > len(body) {
			end = len(body)
		}
		addr := make([]byte, 16)
		addr[0] = byte(len(out)) // sequence number in the top byte
		copy(addr[1:], body[i:end])
		out = append(out, addr)
	}
	return out
}

// DecodeAAAA reconstructs a chunk's payload from AAAA addresses, reordering by
// the sequence byte.
func DecodeAAAA(addrs [][]byte) ([]byte, error) {
	type item struct {
		seq int
		val []byte
	}
	items := make([]item, 0, len(addrs))
	for _, a := range addrs {
		if len(a) < 2 {
			return nil, fmt.Errorf("objectstore: aaaa record too short (%d bytes)", len(a))
		}
		items = append(items, item{seq: int(a[0]), val: a[1:]})
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("objectstore: no aaaa records")
	}
	sort.Slice(items, func(i, j int) bool { return items[i].seq < items[j].seq })
	var out []byte
	for _, it := range items {
		out = append(out, it.val...)
	}
	// Strip the 4-byte length prefix added by EncodeAAAA. AAAA right-pads the
	// final record with null bytes, so the recorded length is what lets the
	// decoder return the exact payload instead of trailing padding that could
	// be mistaken for content ending in a null byte.
	if len(out) < 4 {
		return nil, fmt.Errorf("objectstore: aaaa payload too short for length prefix")
	}
	length := binary.BigEndian.Uint32(out[:4])
	if int(length) > len(out)-4 {
		return nil, fmt.Errorf("objectstore: aaaa payload length %d exceeds available %d", length, len(out)-4)
	}
	return out[4 : 4+int(length)], nil
}

// Reassemble concatenates the ordered chunks and verifies every hash against
// the manifest. It returns an error (never silent corruption) if the manifest
// is inconsistent or any chunk is missing, reordered, or tampered.
func Reassemble(m *Manifest, chunks map[ObjectID][]byte) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	var out []byte
	for i, id := range m.ChunkIDs {
		c, ok := chunks[id]
		if !ok {
			return nil, fmt.Errorf("objectstore: missing chunk %s", id)
		}
		if int64(len(c)) != m.ChunkLens[i] {
			// AAAA right-pads its final record; the manifest's ChunkLens tells
			// us how many bytes are real. Trim before hashing so the hash is
			// computed over the exact original chunk bytes.
			if int64(len(c)) > m.ChunkLens[i] {
				c = c[:m.ChunkLens[i]]
			} else {
				return nil, fmt.Errorf("objectstore: chunk %s too short (manifest %d, got %d)", id, m.ChunkLens[i], len(c))
			}
		}
		if got := ChunkID(c); got != id {
			return nil, fmt.Errorf("objectstore: chunk %s hash mismatch (got %s)", id, got)
		}
		out = append(out, c...)
	}
	if int64(len(out)) != m.TotalSize {
		return nil, fmt.Errorf("objectstore: size mismatch (manifest %d, got %d)", m.TotalSize, len(out))
	}
	return out, nil
}
