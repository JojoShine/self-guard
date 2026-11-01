package main

import (
	"errors"
	"strings"
)

type secTransaction struct {
	transforms            secTransformCache
	controls              []secControl
	matchedBytes, txBytes int
	processor             string
	forceBody             bool
	input                 map[string][]string
	inputCollections      map[string]map[string][]string
	matched               []secVariable
	last                  secVariable
	hasLast               bool
}

func secMatchCollection(name string) bool {
	collection, _, _ := strings.Cut(strings.ToUpper(name), ":")
	return collection == "MATCHED_VAR" || collection == "MATCHED_VAR_NAME" || collection == "MATCHED_VARS" || collection == "MATCHED_VARS_NAMES"
}
func (tx *secTransaction) variables() map[string][]string {
	return tx.variablesFor(nil)
}
func (tx *secTransaction) variablesFor(collections map[string]bool) map[string][]string {
	if tx.inputCollections == nil {
		tx.inputCollections = map[string]map[string][]string{}
		for name, values := range tx.input {
			collection, _, _ := strings.Cut(name, ":")
			collection = strings.ToUpper(collection)
			if collection == "TX" || secMatchCollection(collection) {
				continue
			}
			if tx.inputCollections[collection] == nil {
				tx.inputCollections[collection] = map[string][]string{}
			}
			tx.inputCollections[collection][name] = values
		}
	}
	wanted := func(name string) bool { return collections == nil || collections[name] }
	capacity := len(collections) * 2
	if collections == nil {
		capacity = len(tx.input) + 2
	}
	input := make(map[string][]string, capacity)
	for collection, values := range tx.inputCollections {
		if wanted(collection) {
			for name, value := range values {
				input[name] = value
			}
		}
	}
	if tx.hasLast {
		if wanted("MATCHED_VAR") {
			input["MATCHED_VAR"] = []string{tx.last.value}
		}
		if wanted("MATCHED_VAR_NAME") {
			input["MATCHED_VAR_NAME"] = []string{tx.last.name}
		}
	}
	if wanted("MATCHED_VARS") || wanted("MATCHED_VARS_NAMES") {
		for _, variable := range tx.matched {
			if wanted("MATCHED_VARS") {
				input["MATCHED_VARS:"+variable.name] = append(input["MATCHED_VARS:"+variable.name], variable.value)
			}
			if wanted("MATCHED_VARS_NAMES") {
				input["MATCHED_VARS_NAMES"] = append(input["MATCHED_VARS_NAMES"], variable.name)
			}
		}
	}
	return input
}
func (tx *secTransaction) record(name, value string) error {
	if len(tx.matched) >= 10000 || tx.matchedBytes+len(name)+len(value) > 4<<20 {
		return errors.New("matched-variable budget exceeded")
	}
	tx.matchedBytes += len(name) + len(value)
	tx.last = secVariable{name, value}
	tx.hasLast = true
	tx.matched = append(tx.matched, tx.last)
	return nil
}
func secMacroSupported(name string) bool {
	if strings.HasPrefix(name, "tx.") {
		return true
	}
	if name == "rule.id" || name == "rule.msg" {
		return true
	}
	collection, _, _ := strings.Cut(name, ".")
	return secTargetCollections[strings.ToUpper(collection)]
}
func (tx *secTransaction) macro(name string, rule secRule) (string, error) {
	if !secMacroSupported(name) {
		return "", errors.New("unsupported macro collection")
	}
	switch name {
	case "rule.id":
		return rule.ID, nil
	case "rule.msg":
		return secFirst(rule.Actions, "msg"), nil
	}
	collection, key, keyed := strings.Cut(name, ".")
	target := strings.ToUpper(collection)
	if keyed {
		target += ":" + key
	}
	values, err := secRuleVariables(target, tx.variables(), nil)
	if err != nil {
		return "", err
	}
	if len(values) == 0 {
		return "", nil
	}
	return values[0].value, nil
}

func (frame *secTransaction) setTX(tx map[string]string, name, value string) error {
	previous, exists := tx[name]
	if len(name) == 0 || len(name) > 1024 || len(value) > 1<<20 || !exists && len(tx) >= 10000 {
		return errors.New("transaction variable budget exceeded")
	}
	added := len(value) - len(previous)
	if !exists {
		added += len(name)
	}
	if frame.txBytes+added > 4<<20 {
		return errors.New("transaction byte budget exceeded")
	}
	frame.txBytes += added
	tx[name] = value
	return nil
}
func (frame *secTransaction) deleteTX(tx map[string]string, name string) {
	if value, exists := tx[name]; exists {
		frame.txBytes -= len(name) + len(value)
		delete(tx, name)
	}
}
