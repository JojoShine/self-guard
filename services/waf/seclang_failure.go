package main

import (
	"context"
	"errors"
)

// Persist only this bounded classification, never private process output or request data.
type secInspectionFailure struct {
	kind  string
	cause error
}

func (e *secInspectionFailure) Error() string   { return e.cause.Error() }
func (e *secInspectionFailure) Unwrap() error   { return e.cause }
func secFailure(kind string, cause error) error { return &secInspectionFailure{kind, cause} }
func secFailureKind(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return "CANCELLED"
	}
	if errors.Is(err, errSecPoolCapacity) {
		return "QUEUE_CAPACITY"
	}
	var failure *secInspectionFailure
	if errors.As(err, &failure) {
		return failure.kind
	}
	return "INSPECTION_INCOMPLETE_OR_UNAVAILABLE"
}
