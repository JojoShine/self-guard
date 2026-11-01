package main

import "time"

type RuleApplicability struct {
	AssetIDs   []string `json:"assetIds,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Businesses []string `json:"businesses,omitempty"`
}
type RuleException struct {
	AssetID   string `json:"assetId"`
	Path      string `json:"path,omitempty"`
	ExpiresAt string `json:"expiresAt"`
	Reason    string `json:"reason"`
}
type PolicyAsset struct {
	ID       string   `json:"id"`
	Tags     []string `json:"tags"`
	Business string   `json:"business"`
}

func listHas(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func ruleApplies(config PolicyConfig, asset PolicyAsset) bool {
	scope := config.Applicability
	if len(scope.AssetIDs) > 0 && !listHas(scope.AssetIDs, asset.ID) {
		return false
	}
	if len(scope.Businesses) > 0 && !listHas(scope.Businesses, asset.Business) {
		return false
	}
	if len(scope.Tags) > 0 {
		found := false
		for _, tag := range asset.Tags {
			if listHas(scope.Tags, tag) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func baselineExempt(config PolicyConfig, asset PolicyAsset, now time.Time) bool {
	for _, x := range config.Exceptions {
		until, err := time.Parse(time.RFC3339Nano, x.ExpiresAt)
		if err == nil && x.AssetID == asset.ID && asset.ID != "" && until.After(now) && (x.Path == "" || x.Path == config.Path) {
			return true
		}
	}
	return false
}
