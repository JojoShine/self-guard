//go:build !linux

package main

import (
	"context"
	"errors"
)

func lockTrafficMonitor(string) (func(), error) {
	return nil, errors.New("traffic monitor requires Linux")
}
func captureTrafficMonitor(context.Context, TrafficCaptureConfig, func(*TrafficSummary) error) error {
	return errors.New("traffic monitor requires Linux")
}
