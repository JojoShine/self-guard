//go:build !linux

package main

import (
	"errors"
	"io"
)

func captureTraffic(TrafficCaptureConfig, *TrafficSummary, io.Writer) error {
	return errors.New("native packet capture requires Linux")
}
