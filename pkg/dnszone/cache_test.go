package dnszone

import (
	"strconv"
	"testing"
	"time"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// TestCachePutGet verifies a put is served by a later get, including the
// manifest that now travels with the object.
func TestCachePutGet(t *testing.T) {
	c := NewCache(0)
	manifest, _ := objectstore.Build([]byte("object"))
	want := []byte("reassembled bytes")

	if _, _, ok := c.Get(manifest.ID()); ok {
		t.Fatal("empty cache should miss")
	}

	c.Put(manifest, want, time.Minute)
	_, obj, ok := c.Get(manifest.ID())
	if !ok {
		t.Fatal("expected a hit after Put")
	}
	if string(obj) != string(want) {
		t.Fatalf("Get: got %q, want %q", obj, want)
	}
	if c.Len() != 1 {
		t.Fatalf("Len: got %d, want 1", c.Len())
	}
}

// TestCacheExpiry verifies an entry is served before its TTL and evicted after.
func TestCacheExpiry(t *testing.T) {
	// now reads from base, so advancing base advances the clock.
	base := time.Unix(1_700_000_000, 0)
	c := NewCache(0)
	c.now = func() time.Time { return base }
	manifest, _ := objectstore.Build([]byte("object"))

	c.Put(manifest, []byte("data"), 60*time.Second)

	// Before expiry: a hit.
	if _, _, ok := c.Get(manifest.ID()); !ok {
		t.Fatal("expected a hit before expiry")
	}

	// After the TTL lapses: a miss, and the entry is evicted.
	base = base.Add(61 * time.Second)
	if _, _, ok := c.Get(manifest.ID()); ok {
		t.Fatal("expected a miss after expiry")
	}
	if c.Len() != 0 {
		t.Fatalf("expired entry should be evicted, Len=%d", c.Len())
	}
}

// TestCacheZeroTTLIsNoop verifies a zero or negative TTL is never stored,
// matching DNS semantics where a zero TTL means "do not cache".
func TestCacheZeroTTLIsNoop(t *testing.T) {
	c := NewCache(0)
	manifest, _ := objectstore.Build([]byte("object"))

	c.Put(manifest, []byte("data"), 0)
	c.Put(manifest, []byte("data"), -time.Second)
	if c.Len() != 0 {
		t.Fatalf("zero/negative TTL must not cache, Len=%d", c.Len())
	}
	if _, _, ok := c.Get(manifest.ID()); ok {
		t.Fatal("zero-TTL entry must miss")
	}
}

// TestCacheUpdateRefreshesDataAndRecency verifies re-putting an id replaces its
// bytes and recency without growing the cache.
func TestCacheUpdateRefreshesDataAndRecency(t *testing.T) {
	c := NewCache(0)
	manifest, _ := objectstore.Build([]byte("object"))

	c.Put(manifest, []byte("v1"), time.Hour)
	c.Put(manifest, []byte("v2"), time.Hour)

	_, obj, ok := c.Get(manifest.ID())
	if !ok || string(obj) != "v2" {
		t.Fatalf("update: got %q ok=%v, want v2", obj, ok)
	}
	if c.Len() != 1 {
		t.Fatalf("updating an existing id must not grow the cache, Len=%d", c.Len())
	}
}

// TestCacheLRUEviction verifies that once the cache exceeds its capacity the
// least-recently-used entry is dropped while recent ones are retained.
func TestCacheLRUEviction(t *testing.T) {
	c := NewCache(2)
	a, _ := objectstore.Build([]byte("a"))
	b, _ := objectstore.Build([]byte("b"))
	cc, _ := objectstore.Build([]byte("c"))

	c.Put(a, []byte("1"), time.Hour)
	c.Put(b, []byte("2"), time.Hour)

	// Touch a so it becomes the most-recently-used; b is now the LRU.
	if _, _, ok := c.Get(a.ID()); !ok {
		t.Fatal("expected a hit on a")
	}

	// Insert c, which must evict b (the least-recently-used).
	c.Put(cc, []byte("3"), time.Hour)

	if _, _, ok := c.Get(b.ID()); ok {
		t.Fatal("b should have been evicted as LRU")
	}
	if _, _, ok := c.Get(a.ID()); !ok {
		t.Fatal("a should still be cached")
	}
	if _, _, ok := c.Get(cc.ID()); !ok {
		t.Fatal("c should still be cached")
	}
}

// TestCacheConcurrent hammers a cache from many goroutines. Run under -race it
// proves the LRU list and index stay consistent under parallel Put/Get and
// eviction.
func TestCacheConcurrent(t *testing.T) {
	c := NewCache(64)
	for g := 0; g < 8; g++ {
		go func(g int) {
			for i := 0; i < 200; i++ {
				// Build produces a manifest whose id is its content hash, so the
				// ids are spread across the cache and force eviction.
				m, _ := objectstore.Build([]byte(strconv.Itoa(g) + "/" + strconv.Itoa(i)))
				c.Put(m, []byte{byte(g), byte(i)}, time.Hour)
				_, _, _ = c.Get(m.ID())
			}
		}(g)
	}
	// Let the goroutines drain, then confirm the cache stayed within its bound
	// and never grew unbounded.
	time.Sleep(50 * time.Millisecond)
	if c.Len() > 64 {
		t.Fatalf("cache exceeded capacity: Len=%d", c.Len())
	}
}
