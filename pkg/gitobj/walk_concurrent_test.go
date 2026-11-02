package gitobj

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// historyGraph builds a linear history of n commits, each with a root tree
// holding a shared blob, a per-commit blob, and a subtree. It returns the raw
// objects keyed by SHA and the tip commit.
func historyGraph(n int) (map[string][]byte, string) {
	objs := map[string][]byte{}
	put := func(kind Kind, content []byte) string {
		sha := ObjectSHA(kind, content)
		objs[sha] = rawBytes(kind, content)
		return sha
	}
	shared := put(Blob, []byte("shared\n"))
	parent := ""
	for i := 0; i < n; i++ {
		own := put(Blob, []byte(fmt.Sprintf("file %d\n", i)))
		sub := []Entry{{Mode: "100644", Name: "x", SHA: own}}
		subTree := put(Tree, MarshalTree(sub))
		root := []Entry{{Mode: "100644", Name: "shared", SHA: shared}, {Mode: "100644", Name: "own", SHA: own}, {Mode: "40000", Name: "dir", SHA: subTree}}
		SortEntries(root)
		tree := put(Tree, MarshalTree(root))
		c := "tree " + tree + "\n"
		if parent != "" {
			c += "parent " + parent + "\n"
		}
		c += fmt.Sprintf("author A <a@x> %d +0000\ncommitter A <a@x> %d +0000\n\ncommit %d\n", i, i, i)
		parent = put(Commit, []byte(c))
	}
	return objs, parent
}

// TestWalkConcurrentMatchesWalk checks every worker count returns exactly the
// objects the sequential walk does.
func TestWalkConcurrentMatchesWalk(t *testing.T) {
	objs, tip := historyGraph(40)
	fetch := func(sha string) ([]byte, error) {
		if raw, ok := objs[sha]; ok {
			return raw, nil
		}
		return nil, fmt.Errorf("missing %s", sha)
	}
	want, err := Walk(fetch, tip)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != len(objs) {
		t.Fatalf("Walk found %d of %d objects", len(want), len(objs))
	}
	for _, workers := range []int{0, 1, 4, 32, 1000} {
		var calls atomic.Int64
		got, err := WalkConcurrent(func(sha string) ([]byte, error) {
			calls.Add(1)
			return fetch(sha)
		}, tip, workers)
		if err != nil {
			t.Fatalf("workers=%d: %v", workers, err)
		}
		if len(got) != len(want) {
			t.Fatalf("workers=%d: %d objects, want %d", workers, len(got), len(want))
		}
		for sha, o := range want {
			if g := got[sha]; g == nil || string(g.Raw) != string(o.Raw) {
				t.Fatalf("workers=%d: object %s differs", workers, sha)
			}
		}
		if int(calls.Load()) != len(objs) {
			t.Fatalf("workers=%d: %d fetches for %d objects (each must be fetched once)", workers, calls.Load(), len(objs))
		}
	}
}

// TestWalkConcurrentOverlapsFetches uses a slow fetch and records how many
// calls are in flight at once: more than one, never more than workers.
func TestWalkConcurrentOverlapsFetches(t *testing.T) {
	objs, tip := historyGraph(20)
	const workers = 8
	var inflight, peak atomic.Int64
	start := time.Now()
	got, err := WalkConcurrent(func(sha string) ([]byte, error) {
		n := inflight.Add(1)
		defer inflight.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		return objs[sha], nil
	}, tip, workers)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(objs) {
		t.Fatalf("%d objects, want %d", len(got), len(objs))
	}
	if p := peak.Load(); p < 4 || p > workers {
		t.Fatalf("peak in-flight fetches %d, want between 4 and %d", p, workers)
	}
	if sequential := time.Duration(len(objs)) * 5 * time.Millisecond; time.Since(start) > sequential/2 {
		t.Fatalf("walk took %s; sequential would be %s", time.Since(start), sequential)
	}
}

// TestWalkConcurrentStopsOnError checks a failed fetch is returned, no new
// fetches start afterwards, and none are still running once it returns.
func TestWalkConcurrentStopsOnError(t *testing.T) {
	objs, tip := historyGraph(30)
	// Remove a commit deep in history so the walk fails part-way.
	var victim string
	for sha, raw := range objs {
		if strings.HasPrefix(string(raw), "commit") && strings.Contains(string(raw), "commit 3\n") {
			victim = sha
		}
	}
	delete(objs, victim)
	errMissing := errors.New("not here")
	var inflight atomic.Int64
	var mu sync.Mutex
	afterErr := 0
	failed := false
	_, err := WalkConcurrent(func(sha string) ([]byte, error) {
		inflight.Add(1)
		defer inflight.Add(-1)
		time.Sleep(time.Millisecond)
		mu.Lock()
		defer mu.Unlock()
		if failed {
			afterErr++
		}
		raw, ok := objs[sha]
		if !ok {
			failed = true
			return nil, errMissing
		}
		return raw, nil
	}, tip, 8)
	if !errors.Is(err, errMissing) || !strings.Contains(err.Error(), victim) {
		t.Fatalf("err=%v, want the missing-object error for %s", err, victim)
	}
	if n := inflight.Load(); n != 0 {
		t.Fatalf("%d fetches still running after WalkConcurrent returned", n)
	}
	if afterErr > 8 {
		t.Fatalf("%d fetches ran after the failure; only those already in flight may", afterErr)
	}
}

// TestWalkConcurrentDetectsTampering checks an object whose bytes do not hash
// to the requested SHA fails the walk.
func TestWalkConcurrentDetectsTampering(t *testing.T) {
	objs, tip := historyGraph(10)
	for sha, raw := range objs {
		if strings.HasPrefix(string(raw), "blob") && strings.Contains(string(raw), "file 5") {
			objs[sha] = rawBytes(Blob, []byte("file X\n"))
		}
	}
	if _, err := WalkConcurrent(func(sha string) ([]byte, error) { return objs[sha], nil }, tip, 8); err == nil || !strings.Contains(err.Error(), "resolved to object") {
		t.Fatalf("err=%v, want SHA mismatch", err)
	}
}
