package main

import (
	"errors"
	"strings"
)

type secControl struct{ name, tag, target string }

func parseSecControl(value string) (secControl, error) {
	name, operand, ok := strings.Cut(value, "=")
	control := secControl{name: strings.ToLower(name)}
	if !ok || strings.Contains(value, "%{") {
		return control, errors.New("static control operand required")
	}
	switch control.name {
	case "requestbodyprocessor":
		switch operand {
		case "URLENCODED", "JSON", "XML", "MULTIPART":
			control.target = operand
			return control, nil
		default:
			return control, errors.New("unsupported body processor")
		}
	case "forcerequestbodyvariable":
		if operand != "On" && operand != "Off" {
			return control, errors.New("raw body control requires On or Off")
		}
		control.target = operand
		return control, nil
	case "auditengine":
		if operand != "Off" && operand != "On" {
			return control, errors.New("unsupported audit mode")
		}
		control.target = operand
		return control, nil
	case "ruleremovebytag":
		control.tag = operand
	case "ruleremovetargetbytag":
		var found bool
		control.tag, control.target, found = strings.Cut(operand, ";")
		if !found {
			return control, errors.New("tag and target required")
		}
		selectors, err := secParseSelectors(control.target)
		if err != nil || len(selectors) != 1 || selectors[0].exclude || selectors[0].count || !secTargetCollections[selectors[0].collection] {
			return control, errors.New("unsupported control target")
		}
		if selectors[0].regex {
			if _, err := matchSecRegex("(?i)"+selectors[0].key, ""); err != nil {
				return control, err
			}
		}
	default:
		return control, errors.New("unsupported runtime control")
	}
	if control.tag == "" {
		return control, errors.New("empty tag expression")
	}
	if _, err := matchSecRegex(control.tag, ""); err != nil {
		return control, err
	}
	return control, nil
}
func (c secControl) matchesTags(rules ...secRule) (bool, error) {
	for _, rule := range rules {
		for _, tag := range rule.Actions["tag"] {
			ok, err := matchSecRegex(c.tag, tag)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
	}
	return false, nil
}
func (tx *secTransaction) disabled(rule secRule) (bool, error) {
	for _, control := range tx.controls {
		if control.name != "ruleremovebytag" {
			continue
		}
		ok, err := control.matchesTags(rule)
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}
func (tx *secTransaction) targets(rule, root secRule) (string, error) {
	targets := rule.Targets
	for _, control := range tx.controls {
		if control.name != "ruleremovetargetbytag" {
			continue
		}
		ok, err := control.matchesTags(rule, root)
		if err != nil {
			return "", err
		}
		if ok {
			targets += "|!" + control.target
		}
	}
	return targets, nil
}
