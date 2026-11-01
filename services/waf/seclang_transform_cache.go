package main

import "encoding/json"

type secTransformKey struct {
	value, transforms string
	multi             bool
}
type secTransformCache struct {
	entries map[secTransformKey][]string
	bytes   int
}

// A transaction only reuses deterministic transformations of the exact same
// bytes and ordered actions. Small scalars avoid cache overhead. Results are
// read-only within evaluation and never survive the current request.
func (cache *secTransformCache) stages(value string, transforms []string, multi bool) ([]string, error) {
	if len(value) < 256 {
		return secTransformStages(value, transforms, multi)
	}
	signature, _ := json.Marshal(transforms)
	key := secTransformKey{value, string(signature), multi}
	if stages, ok := cache.entries[key]; ok {
		return stages, nil
	}
	stages, err := secTransformStages(value, transforms, multi)
	if err != nil {
		return nil, err
	}
	size := len(value) + len(key.transforms) + 128
	for _, stage := range stages {
		size += len(stage) + 16
	}
	if len(cache.entries) < 128 && cache.bytes+size <= 2<<20 {
		if cache.entries == nil {
			cache.entries = map[secTransformKey][]string{}
		}
		cache.entries[key] = stages
		cache.bytes += size
	}
	return stages, nil
}
