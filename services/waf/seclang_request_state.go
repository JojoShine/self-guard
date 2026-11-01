package main

import (
	"errors"
	"net/http"
	"strconv"
)

type secRequestState struct {
	request *http.Request
	body    []byte
}

func (state *secRequestState) load(processor string, force bool) (map[string][]string, error) {
	input, err := secRequestInputOptions(state.request, state.body, processor, true)
	if err == nil {
		// CRS's processor-dependent body contract: URLencoded keeps raw bytes;
		// structured processors expose parsed collections instead. An unknown
		// media type is inspected only after an explicit header-phase control.
		selected := ""
		if values := input["REQBODY_PROCESSOR"]; len(values) > 0 {
			selected = values[0]
		}
		if selected != "" && selected != "URLENCODED" || selected == "" && !force {
			delete(input, "REQUEST_BODY")
		}
		return input, nil
	}
	// Do not retain a partially parsed dependency/argument collection. The raw
	// bytes and protocol error remain available for rules and incomplete coverage.
	input, headerErr := secRequestInputOptions(state.request, state.body, processor, false)
	if headerErr != nil {
		return nil, headerErr
	}
	input["REQUEST_BODY"] = []string{string(state.body)}
	input["REQUEST_BODY_LENGTH"] = []string{strconv.Itoa(len(state.body))}
	input["REQBODY_ERROR"] = []string{"1"}
	input["REQBODY_PROCESSOR_ERROR"] = []string{"1"}
	input["REQBODY_ERROR_MSG"] = []string{"request body parser rejected malformed or resource-limited content"}
	if errors.Is(err, errSecMultipartHeader) {
		input["REQBODY_ERROR_MSG"] = []string{errSecMultipartHeader.Error()}
	}
	input["REQBODY_PROCESSOR_ERROR_MSG"] = input["REQBODY_ERROR_MSG"]
	return input, nil
}
