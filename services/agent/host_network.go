package main

import (
	"errors"
	"os"
)

func hostNetworkAgent() (*Agent, error) {
	path := os.Getenv("AGENT_CONFIG")
	if path == "" {
		path = "/etc/selfguard-agent/collector.json"
	}
	if err := executorTrustedConfig(path); err != nil {
		return nil, err
	}
	var c Config
	if err := read(path, &c); err != nil {
		return nil, err
	}
	if c.Server == "" || c.StateDir == "" {
		return nil, errors.New("installed agent connection configuration required")
	}
	client, err := clientForConfig(c)
	if err != nil {
		return nil, err
	}
	var identity Identity
	if err = read(c.StateDir+"/identity.json", &identity); err != nil {
		return nil, err
	}
	if identity.AssetID == "" || identity.Token == "" {
		return nil, errors.New("registered agent identity required")
	}
	return &Agent{Config: c, Client: client, Identity: identity}, nil
}
func publishNetworkReport(path string) error {
	if err := executorPlatform(); err != nil {
		return err
	}
	if err := executorTrustedConfig(path); err != nil {
		return err
	}
	b, err := readBoundedFile(path, 1<<20)
	if err != nil {
		return err
	}
	// Only metadata from our summary is accepted. The server enforces a strict schema.
	var summary TrafficSummary
	if err = decodeExecutorParameters(b, &summary); err != nil {
		return err
	}
	a, err := hostNetworkAgent()
	if err != nil {
		return err
	}
	return a.request("POST", "/agent/network-report", a.Identity.Token, summary, nil)
}
