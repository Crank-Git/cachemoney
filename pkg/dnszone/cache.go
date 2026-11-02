package dnszone

import (
	"container/list"
	"sync"
	"time"

	"github.com/Crank-Git/cachemoney/pkg/objectstore"
)

// defaultCacheMax is the number of live objects the resolver cache holds before
// least-recently-used eviction begins.
const defaultCacheMax = 10000

// cacheEntry is one cached object: its manifest and reassembled bytes, plus the
// instant they expire.
type cacheEntry struct {
	id        objectstore.ObjectID
	manifest  *objectstore.Manifest
	obj       []byte
	expiresAt time.Time
}

// Cache is a bounded, thread-safe, least-recently-used cache of resolved
// objects. Each entry holds the manifest and the reassembled, verified bytes,
// keyed by object id. Entries expire after a TTL; once the cache holds more
// than max live entries the least-recently-used one is evicted.
//
// Content addressing makes the cache sound: identical bytes have one id, so a
// hit always returns the correct bytes for that id. The resolver only stores an
// object after it has reassembled and verified it, so a hit is a verified
// object, not merely a cached guess. A hit short-circuits the whole fetch:
// neither the manifest nor any chunk is fetched from the server.
type Cache struct {
	mu      sync.Mutex
	max     int
	entries map[objectstore.ObjectID]*list.Element
	oldest  *list.List // element.Value is *cacheEntry, front = most recent
	now     func() time.Time
}

// NewCache returns a cache holding at most max live objects. A max <= 0 uses
// the default. The returned cache is safe for concurrent use.
func NewCache(max int) *Cache {
	if max <= 0 {
		max = defaultCacheMax
	}
	return &Cache{
		max:     max,
		entries: make(map[objectstore.ObjectID]*list.Element),
		oldest:  list.New(),
		now:     time.Now,
	}
}

// Get returns the cached manifest and object for id and whether an unexpired
// entry existed. A hit refreshes the entry's recency for LRU ordering.
func (c *Cache) Get(id objectstore.ObjectID) (*objectstore.Manifest, []byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[id]
	if !ok {
		return nil, nil, false
	}
	e := el.Value.(*cacheEntry)
	if c.now().After(e.expiresAt) {
		c.remove(el)
		return nil, nil, false
	}
	c.oldest.MoveToFront(el)
	return e.manifest, e.obj, true
}

// Put stores manifest and its reassembled object for id for the given lifetime.
// A ttl <= 0 is a no-op, matching DNS semantics where a zero TTL means "do not
// cache". Storing past capacity evicts the least-recently-used entry.
func (c *Cache) Put(manifest *objectstore.Manifest, obj []byte, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.entries[manifest.ID()]; ok {
		e := el.Value.(*cacheEntry)
		e.manifest = manifest
		e.obj = obj
		e.expiresAt = c.now().Add(ttl)
		c.oldest.MoveToFront(el)
		return
	}

	id := manifest.ID()
	el := c.oldest.PushFront(&cacheEntry{
		id:        id,
		manifest:  manifest,
		obj:       obj,
		expiresAt: c.now().Add(ttl),
	})
	c.entries[id] = el
	for c.oldest.Len() > c.max {
		c.remove(c.oldest.Back())
	}
}

// remove drops el from both the list and the index. Callers hold the lock.
func (c *Cache) remove(el *list.Element) {
	e := el.Value.(*cacheEntry)
	c.oldest.Remove(el)
	delete(c.entries, e.id)
}

// Len returns the number of live (non-evicted) entries. It is used by tests.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.oldest.Len()
}
