package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestTransactionTransformCacheKeepsExactStagesOrderAndBounds(t *testing.T) {
	cache := secTransformCache{}
	input := strings.Repeat("%41&lt;A&gt; ", 100)
	for _, transforms := range [][]string{{"none", "urlDecodeUni", "htmlEntityDecode", "lowercase"}, {"lowercase", "none", "urlDecodeUni"}, {"urlDecodeUni", "lowercase"}} {
		for _, multi := range []bool{false, true} {
			want, err := secTransformStages(input, transforms, multi)
			if err != nil {
				t.Fatal(err)
			}
			for repeat := 0; repeat < 3; repeat++ {
				got, err := cache.stages(input, transforms, multi)
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("stages differ: %v %v", got, err)
				}
			}
		}
	}
	if len(cache.entries) != 6 {
		t.Fatalf("transforms or multimatch identities collided: %d", len(cache.entries))
	}
	_, _ = cache.stages(input, nil, false)
	if _, err := cache.stages(input, []string{""}, false); err == nil {
		t.Fatal("cached empty transform list masked invalid transform")
	}
	for index := 0; index < 1000; index++ {
		_, _ = cache.stages(strings.Repeat("a", 4096)+strings.Repeat("b", index), []string{"lowercase"}, false)
	}
	if len(cache.entries) > 128 || cache.bytes > 2<<20 {
		t.Fatal("transaction cache exceeded memory/count budget")
	}
	if len((secTransformCache{}).entries) != 0 {
		t.Fatal("cache leaked across transactions")
	}
}
