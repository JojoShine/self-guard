//go:build pcre2 && cgo

package main

import (
	"strings"
	"sync"
	"testing"
)

func TestSecRegexCacheCountsNativeJITMemoryWithinItsBudget(t *testing.T) {
	cache := newSecRegexCache(4, 1<<20)
	defer cache.close()
	entry, release, err := cache.acquire(`(?i)(attack|danger)`)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if entry.jitBytes <= 0 || entry.bytes < entry.jitBytes+len(entry.pattern)+128 {
		t.Fatal("native JIT code is absent or excluded from cache accounting")
	}
}

func TestSecRegexCacheReusesCompiledPatternsWithIndependentCaptures(t *testing.T) {
	cache := newSecRegexCache(4, 1<<20)
	defer cache.close()
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for n := 0; n < 30; n++ {
				matched, captures, err := captureSecRegexCached(cache, `(attack)([0-9]+)`, "attack123")
				if err != nil || !matched || captures["1"] != "attack" || captures["2"] != "123" {
					t.Errorf("capture state leaked: %+v %v", captures, err)
				}
			}
		}()
	}
	workers.Wait()
	entries, bytes, compiled := cache.stats()
	if entries != 1 || bytes <= 0 || compiled != 1 {
		t.Fatalf("patterns were recompiled: %d %d %d", entries, bytes, compiled)
	}
}
func TestSecRegexCacheDoesNotFreeBorrowedPatternsAndStaysBounded(t *testing.T) {
	cache := newSecRegexCache(1, 1<<20)
	defer cache.close()
	first, release, err := cache.acquire("first")
	if err != nil {
		t.Fatal(err)
	}
	_, otherRelease, err := cache.acquire("other")
	if err != nil {
		t.Fatal(err)
	}
	entries, bytes, _ := cache.stats()
	if entries != 1 || bytes > 1<<20 {
		t.Fatal("cache exceeded budget")
	}
	otherRelease()
	again, againRelease, err := cache.acquire("first")
	if err != nil || again != first {
		t.Fatal("borrowed pattern was evicted")
	}
	againRelease()
	release()
	matched, _, err := captureSecRegexCached(cache, "other", "other")
	if err != nil || !matched {
		t.Fatal("evicted slot unusable")
	}
	entries, bytes, _ = cache.stats()
	if entries != 1 || bytes > 1<<20 {
		t.Fatal("eviction did not retain bounded storage")
	}
}
func TestSecRegexCachePreservesCompilationErrorsAndExecutionBudgets(t *testing.T) {
	cache := newSecRegexCache(2, 1<<20)
	defer cache.close()
	if _, _, err := captureSecRegexCached(cache, "(", "input"); err == nil {
		t.Fatal("invalid pattern accepted")
	}
	if _, _, err := captureSecRegexCached(cache, `^(a+)+$`, strings.Repeat("a", 3000)+"!"); err == nil {
		t.Fatal("execution limit converted into a clean negative")
	}
}
