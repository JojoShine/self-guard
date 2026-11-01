//go:build pcre2 && cgo

package main

/*
#cgo LDFLAGS: -lpcre2-8
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <stdlib.h>
static pcre2_code *selfguard_pcre_compile(const unsigned char *pattern, size_t pattern_len) {
 int error; PCRE2_SIZE offset;
 pcre2_code *code = pcre2_compile(pattern, pattern_len, PCRE2_DOTALL | PCRE2_DOLLAR_ENDONLY, &error, &offset, NULL);
 if (code) pcre2_jit_compile(code, PCRE2_JIT_COMPLETE);
 return code;
}
static size_t selfguard_pcre_jit_size(pcre2_code *code) {
 size_t size = 0;
 if (pcre2_pattern_info(code, PCRE2_INFO_JITSIZE, &size) != 0) return 0;
 return size;
}
static size_t selfguard_pcre_size(pcre2_code *code) {
 size_t size = 0;
 if (pcre2_pattern_info(code, PCRE2_INFO_SIZE, &size) != 0) return 0;
 return size + selfguard_pcre_jit_size(code);
}
typedef struct {
 pcre2_match_context *context;
 pcre2_jit_stack *stack;
 size_t captures[200];
} selfguard_pcre_execution;
static void selfguard_pcre_execution_free(selfguard_pcre_execution *execution) {
 if (!execution) return;
 pcre2_jit_stack_free(execution->stack);
 pcre2_match_context_free(execution->context);
 free(execution);
}
static selfguard_pcre_execution *selfguard_pcre_execution_create(void) {
 selfguard_pcre_execution *execution = calloc(1, sizeof(*execution));
 if (!execution) return NULL;
 pcre2_match_context *ctx = pcre2_match_context_create(NULL);
 execution->context = ctx;
 execution->stack = pcre2_jit_stack_create(32768, 262144, NULL);
 if (!ctx || !execution->stack) { selfguard_pcre_execution_free(execution); return NULL; }
 pcre2_set_match_limit(ctx, 100000);
 pcre2_set_depth_limit(ctx, 1000);
 pcre2_set_heap_limit(ctx, 8192);
 pcre2_jit_stack_assign(ctx, NULL, execution->stack);
 return execution;
}
static int selfguard_pcre_match(selfguard_pcre_execution *execution, pcre2_code *code, _GoString_ input, size_t *captures) {
 size_t subject_len = _GoStringLen(input);
 const unsigned char *subject = subject_len ? (const unsigned char *)_GoStringPtr(input) : (const unsigned char *)"";
 pcre2_match_context *ctx = execution->context;
 // A fixed 100k budget rejects linear CRS rules on legitimate large fields.
 // Scale only match work with the already bounded subject, and reset it for
 // every borrowed execution context so small requests never inherit it.
 size_t work_limit = subject_len * 4;
 if (work_limit < 100000) work_limit = 100000;
 if (work_limit > 4000000) work_limit = 4000000;
 pcre2_set_match_limit(ctx, (uint32_t)work_limit);
 // An exclusively borrowed context reuses its bounded 32..256 KiB JIT stack.
 // If that is exhausted, the bounded interpreter retries.
 // https://www.pcre.org/current/doc/html/pcre2jit.html
 pcre2_match_data *data = pcre2_match_data_create_from_pattern(code, NULL);
 if (!data) return -1002;
 int result = pcre2_match(code, subject, subject_len, 0, 0, data, ctx);
 if (result == PCRE2_ERROR_JIT_STACKLIMIT)
  result = pcre2_match(code, subject, subject_len, 0, PCRE2_NO_JIT, data, ctx);
 if (result > 0 && captures) {
  PCRE2_SIZE *offsets = pcre2_get_ovector_pointer(data);
  int count = result < 100 ? result : 100;
  for (int i = 0; i < count * 2; i++) captures[i] = offsets[i];
 }
 // The borrowed Go bytes are read-only and must not survive this call.
 // Match data can retain a subject pointer, so it is deliberately freed here.
 pcre2_match_data_free(data);
 return result;
}
*/
import "C"
import (
	"container/list"
	"fmt"
	"strconv"
	"sync"
)

type secRegexEntry struct {
	pattern     string
	code        *C.pcre2_code
	bytes, refs int
	jitBytes    int
	cached      bool
	element     *list.Element
}
type secRegexCache struct {
	mu                                    sync.Mutex
	entries                               map[string]*secRegexEntry
	lru                                   *list.List
	maxEntries, maxBytes, bytes, compiled int
	closed                                bool
}

func newSecRegexCache(entries, bytes int) *secRegexCache {
	return &secRegexCache{entries: map[string]*secRegexEntry{}, lru: list.New(), maxEntries: entries, maxBytes: bytes}
}

var defaultSecRegexCache = newSecRegexCache(1024, 32<<20)

// Four retained native execution contexts cost at most1 MiB of JIT stack
// capacity. A context is never shared by concurrent matches; excess contexts
// are freed when returned. Worker HTTP concurrency remains independently bounded.
var secRegexExecutions = make(chan *C.selfguard_pcre_execution, 4)

func takeSecRegexExecution() *C.selfguard_pcre_execution {
	select {
	case execution := <-secRegexExecutions:
		return execution
	default:
		return C.selfguard_pcre_execution_create()
	}
}
func returnSecRegexExecution(execution *C.selfguard_pcre_execution) {
	select {
	case secRegexExecutions <- execution:
	default:
		C.selfguard_pcre_execution_free(execution)
	}
}

func (c *secRegexCache) acquire(pattern string) (*secRegexEntry, func(), error) {
	if len(pattern) > 65536 {
		return nil, nil, fmt.Errorf("regex input limit exceeded")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, nil, fmt.Errorf("regex cache closed")
	}
	if entry := c.entries[pattern]; entry != nil {
		entry.refs++
		c.lru.MoveToFront(entry.element)
		return entry, func() { c.release(entry) }, nil
	}
	// Serialize only compilation/admission. Each execution owns its match context
	// and captures, and runs outside this lock while holding a borrowed reference.
	p := C.CBytes([]byte(pattern))
	code := C.selfguard_pcre_compile((*C.uchar)(p), C.size_t(len(pattern)))
	C.free(p)
	if code == nil {
		return nil, nil, fmt.Errorf("PCRE2 compilation or execution budget failure (-1000)")
	}
	size := int(C.selfguard_pcre_size(code)) + len(pattern) + 128
	c.compiled++
	entry := &secRegexEntry{pattern: pattern, code: code, bytes: size, refs: 1, jitBytes: int(C.selfguard_pcre_jit_size(code))}
	if size <= c.maxBytes && c.maxEntries > 0 {
		for len(c.entries) >= c.maxEntries || c.bytes+size > c.maxBytes {
			var removable *secRegexEntry
			for item := c.lru.Back(); item != nil; item = item.Prev() {
				candidate := item.Value.(*secRegexEntry)
				if candidate.refs == 0 {
					removable = candidate
					break
				}
			}
			if removable == nil {
				break
			}
			delete(c.entries, removable.pattern)
			c.lru.Remove(removable.element)
			c.bytes -= removable.bytes
			removable.cached = false
			C.pcre2_code_free(removable.code)
		}
		if len(c.entries) < c.maxEntries && c.bytes+size <= c.maxBytes {
			entry.cached = true
			entry.element = c.lru.PushFront(entry)
			c.entries[pattern] = entry
			c.bytes += size
		}
	}
	return entry, func() { c.release(entry) }, nil
}
func (c *secRegexCache) release(entry *secRegexEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry.refs--
	if entry.refs == 0 && !entry.cached {
		C.pcre2_code_free(entry.code)
	}
}
func (c *secRegexCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	for _, entry := range c.entries {
		entry.cached = false
		if entry.refs == 0 {
			C.pcre2_code_free(entry.code)
		}
	}
	c.entries = map[string]*secRegexEntry{}
	c.lru.Init()
	c.bytes = 0
}
func (c *secRegexCache) stats() (int, int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries), c.bytes, c.compiled
}

func secRegexAvailable() bool { return true }
func matchSecRegex(pattern, subject string) (bool, error) {
	ok, _, err := executeSecRegexCached(defaultSecRegexCache, pattern, subject, false)
	return ok, err
}
func captureSecRegex(pattern, subject string) (bool, map[string]string, error) {
	return captureSecRegexCached(defaultSecRegexCache, pattern, subject)
}
func captureSecRegexCached(cache *secRegexCache, pattern, subject string) (bool, map[string]string, error) {
	return executeSecRegexCached(cache, pattern, subject, true)
}
func executeSecRegexCached(cache *secRegexCache, pattern, subject string, capture bool) (bool, map[string]string, error) {
	if len(pattern) > 65536 || len(subject) > 1<<20 {
		return false, nil, fmt.Errorf("regex input limit exceeded")
	}
	entry, release, err := cache.acquire(pattern)
	if err != nil {
		return false, nil, err
	}
	defer release()
	execution := takeSecRegexExecution()
	if execution == nil {
		return false, nil, fmt.Errorf("PCRE2 execution context allocation failed")
	}
	defer returnSecRegexExecution(execution)
	// Boolean checks use the same bounded PCRE execution without allocating
	// a Go capture buffer or copying groups that the caller never reads.
	var output *C.size_t
	if capture {
		output = &execution.captures[0]
	}
	code := int(C.selfguard_pcre_match(execution, entry.code, subject, output))
	if code == int(C.PCRE2_ERROR_NOMATCH) {
		return false, nil, nil
	}
	if code < 0 {
		return false, nil, fmt.Errorf("PCRE2 compilation or execution budget failure (%d)", code)
	}
	if !capture {
		return true, nil, nil
	}
	captures := map[string]string{}
	for i := 0; i < code && i < 100; i++ {
		start, end := uint64(execution.captures[2*i]), uint64(execution.captures[2*i+1])
		if start <= end && end <= uint64(len(subject)) {
			captures[strconv.Itoa(i)] = subject[start:end]
		}
	}
	return true, captures, nil
}
