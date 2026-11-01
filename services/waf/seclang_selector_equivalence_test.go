package main

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func referenceSecRuleVariables(targets string, input map[string][]string, tx map[string]string) ([]secVariable, error) {
	selectors, err := secParseSelectors(targets)
	if err != nil {
		return nil, err
	}
	all := make([]secVariable, 0)
	names := make([]string, 0, len(input))
	for name := range input {
		names = append(names, name)
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
	for name := range tx {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		all = append(all, secVariable{"TX:" + name, tx[name]})
	}
	filtered := make([]secVariable, 0, len(all))
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
	result := []secVariable{}
	for _, selector := range selectors {
		if selector.exclude {
			continue
		}
		selected := []secVariable{}
		for _, variable := range filtered {
			ok, err := selector.selects(variable.name)
			if err != nil {
				return nil, err
			}
			if ok {
				selected = append(selected, variable)
			}
		}
		if selector.count {
			result = append(result, secVariable{"&" + selector.target, strconv.Itoa(len(selected))})
		} else {
			result = append(result, selected...)
		}
	}
	return result, nil
}

func TestRelevantVariableSelectionPreservesOrderingCountsAndExclusionErrors(t *testing.T) {
	random := rand.New(rand.NewSource(41027))
	cases := []string{"ARGS", "ARGS|TX", "ARGS|ARGS|&ARGS|!ARGS:secret", "REQUEST_HEADERS|!REQUEST_HEADERS:/^X-/", "TX|!TX:secret", "&TX|&ARGS", "ARGS_NAMES", "REQUEST_HEADERS_NAMES", "REQUEST_HEADERS:/^X-|^Y-/|TX", "ARGS|!REQUEST_HEADERS:/(/", "TX|!ARGS:/(/", "!TX:/(/", "ARGS|!UNKNOWN:/(/", "", "ARGS|"}
	for iteration := 0; iteration < 30; iteration++ {
		input := map[string][]string{"ARGS:secret": {"hidden"}, "ARGS:q": {"value", "duplicate"}, "REQUEST_HEADERS:X-Fixture": {"header"}, "REQUEST_HEADERS:Other": {"plain"}, "ARGS_NAMES": {"secret", "q", "q"}, "REQUEST_HEADERS_NAMES": {"X-Fixture", "Other"}, "REQUEST_METHOD": {"POST"}, "args:Mixed": {"case"}}
		for index := 0; index < random.Intn(30); index++ {
			input[fmt.Sprintf("UNRELATED%d:key", index)] = []string{"untouched"}
		}
		tx := map[string]string{"secret": "private", "ordinary": "safe", "0": "capture"}
		for _, targets := range cases {
			want, wantErr := referenceSecRuleVariables(targets, input, tx)
			got, gotErr := secRuleVariables(targets, input, tx)
			if (wantErr == nil) != (gotErr == nil) || wantErr == nil && !reflect.DeepEqual(got, want) {
				t.Fatalf("selector %q differs: got=%+v/%v want=%+v/%v", targets, got, gotErr, want, wantErr)
			}
			selection, compiledErr := prepareSecSelection(targets)
			if compiledErr == nil {
				frame := secTransaction{input: input}
				selected, selectedErr := selection.variables(frame.variablesFor(selection.collections), tx)
				if (wantErr == nil) != (selectedErr == nil) || wantErr == nil && !reflect.DeepEqual(selected, want) {
					t.Fatalf("compiled selector %q differs: %+v/%v versus %+v/%v", targets, selected, selectedErr, want, wantErr)
				}
			} else if wantErr == nil {
				t.Fatal(compiledErr)
			}
		}
	}
}
