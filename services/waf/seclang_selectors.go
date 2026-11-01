package main

import (
	"errors"
	"sort"
	"strconv"
	"strings"
)

type secVariable struct{ name, value string }
type secSelector struct {
	target, collection, key      string
	exclude, count, keyed, regex bool
}

// A pipe inside /.../ belongs to the selector expression, not the target list.
func secParseSelectors(targets string) ([]secSelector, error) {
	result := []secSelector{}
	for len(targets) > 0 {
		selector := secSelector{}
		if targets[0] == '!' {
			selector.exclude = true
			targets = targets[1:]
		} else if targets[0] == '&' {
			selector.count = true
			targets = targets[1:]
		}
		end := strings.IndexAny(targets, ":|")
		if end < 0 {
			end = len(targets)
		}
		selector.collection = strings.ToUpper(targets[:end])
		selector.target = selector.collection
		targets = targets[end:]
		if selector.collection == "" {
			return nil, errors.New("empty target collection")
		}
		if strings.HasPrefix(targets, ":") {
			selector.keyed = true
			targets = targets[1:]
			if selector.collection == "XML" {
				end = strings.IndexByte(targets, '|')
				if end < 0 {
					end = len(targets)
				}
				selector.key = targets[:end]
				targets = targets[end:]
				selector.target += ":" + selector.key
				if selector.key != "/*" && selector.key != "//@*" {
					return nil, errors.New("unsupported XPath selector")
				}
			} else if strings.HasPrefix(targets, "/") {
				selector.regex = true
				end = 1
				for end < len(targets) {
					if targets[end] == '\\' {
						end += 2
						continue
					}
					if targets[end] == '/' {
						break
					}
					end++
				}
				if end >= len(targets) {
					return nil, errors.New("unclosed selector expression")
				}
				selector.key = targets[1:end]
				targets = targets[end+1:]
				if targets != "" && !strings.HasPrefix(targets, "|") {
					return nil, errors.New("unexpected selector suffix")
				}
				selector.target += ":/" + selector.key + "/"
			} else {
				end = strings.IndexByte(targets, '|')
				if end < 0 {
					end = len(targets)
				}
				selector.key = targets[:end]
				targets = targets[end:]
				selector.target += ":" + selector.key
				if selector.key == "" {
					return nil, errors.New("empty target key")
				}
			}
		}
		result = append(result, selector)
		if len(result) > 256 {
			return nil, errors.New("selector count limit")
		}
		if strings.HasPrefix(targets, "|") {
			targets = targets[1:]
			if targets == "" {
				return nil, errors.New("empty trailing target")
			}
		}
	}
	return result, nil
}
func (s secSelector) selects(name string) (bool, error) {
	collection, key, keyed := strings.Cut(name, ":")
	if !strings.EqualFold(collection, s.collection) {
		return false, nil
	}
	if !s.keyed {
		return true, nil
	}
	if !keyed {
		return false, nil
	}
	if s.regex {
		return matchSecRegex("(?i)"+s.key, key)
	}
	return strings.EqualFold(s.key, key), nil
}
func secRuleVariables(targets string, input map[string][]string, tx map[string]string) ([]secVariable, error) {
	selection, err := prepareSecSelection(targets)
	if err != nil {
		return nil, err
	}
	return selection.variables(input, tx)
}

type secSelection struct {
	selectors   []secSelector
	collections map[string]bool
}

func prepareSecSelection(targets string) (*secSelection, error) {
	selectors, err := secParseSelectors(targets)
	if err != nil {
		return nil, err
	}
	// Include exclusion collections too: their matching and error behavior must
	// remain unchanged even when no positive selector uses that collection.
	collections := make(map[string]bool, len(selectors))
	for _, selector := range selectors {
		collections[selector.collection] = true
	}
	return &secSelection{selectors, collections}, nil
}
func (selection *secSelection) variables(input map[string][]string, tx map[string]string) ([]secVariable, error) {
	selectors, collections := selection.selectors, selection.collections
	valueCount, nameCount := 0, len(input)
	for _, values := range input {
		valueCount += len(values)
	}
	if collections["TX"] {
		valueCount += len(tx)
		nameCount += len(tx)
	}
	all := make([]secVariable, 0, valueCount)
	names := make([]string, 0, nameCount)
	for name := range input {
		collection, _, _ := strings.Cut(name, ":")
		if collections[strings.ToUpper(collection)] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range input[name] {
			variableName := name
			if !strings.Contains(name, ":") && strings.HasSuffix(name, "_NAMES") {
				variableName = name + ":" + value
			}
			all = append(all, secVariable{variableName, value})
		}
	}
	names = names[:0]
	if collections["TX"] {
		for name := range tx {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		all = append(all, secVariable{"TX:" + name, tx[name]})
	}
	filtered := all
	hasExclusions := false
	for _, selector := range selectors {
		if selector.exclude {
			hasExclusions = true
			break
		}
	}
	if hasExclusions {
		filtered = make([]secVariable, 0, len(all))
		for _, variable := range all {
			omit := false
			for _, selector := range selectors {
				if !selector.exclude {
					continue
				}
				ok, err := selector.selects(variable.name)
				if err != nil {
					return nil, err
				}
				if ok {
					omit = true
					break
				}
			}
			if !omit {
				filtered = append(filtered, variable)
			}
		}
	}
	result := []secVariable{}
	for _, selector := range selectors {
		if selector.exclude {
			continue
		}
		selectedCount := 0
		for _, variable := range filtered {
			ok, err := selector.selects(variable.name)
			if err != nil {
				return nil, err
			}
			if ok {
				if selector.count {
					selectedCount++
				} else {
					result = append(result, variable)
				}
			}
		}
		if selector.count {
			result = append(result, secVariable{"&" + selector.target, strconv.Itoa(selectedCount)})
		}
	}
	return result, nil
}
