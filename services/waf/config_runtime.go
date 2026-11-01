package main

import "encoding/json"

func cloneSiteVersionFloors(source map[string]int) map[string]int {
	result := map[string]int{}
	for id, version := range source {
		result[id] = version
	}
	return result
}

// Persist only a fully validated candidate, including locally retained version
// floors. A rejected downgrade must never overwrite the cache before a restart.
func (e *engine) applyRemoteConfig(path string, raw []byte) error {
	c, err := readConfig(raw)
	if err != nil {
		return err
	}
	e.configMu.Lock()
	defer e.configMu.Unlock()
	c.SiteVersionFloors = nil // Remote input cannot reset or supply local history.
	candidate := newEngine()
	candidate.rulePublicKey = e.rulePublicKey
	candidate.rulePool = e.rulePool
	candidate.siteVersionFloors = cloneSiteVersionFloors(e.siteVersionFloors)
	candidate.sites.Store(e.sites.Load())
	if err = candidate.update(c); err != nil {
		return err
	}
	c.SiteVersionFloors = candidate.siteVersionFloors
	cache, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err = persistConfig(path, cache); err != nil {
		return err
	}
	e.siteVersionFloors = candidate.siteVersionFloors
	e.sites.Store(candidate.sites.Load())
	return nil
}
