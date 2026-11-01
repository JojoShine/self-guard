package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Local manifests use operator-selected files. Remote certificates arrive only
// through the separately authenticated certificate management channel.
type certificateStore struct{ certificates atomic.Value }
type certificateFile struct {
	Hostname string `json:"hostname"`
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

func (s *certificateStore) reload(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("TLS manifest must be an absolute local path")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(b) > 1<<20 {
		return fmt.Errorf("TLS manifest too large")
	}
	var files []certificateFile
	if err = json.Unmarshal(b, &files); err != nil {
		return err
	}
	if len(files) == 0 || len(files) > 1000 {
		return fmt.Errorf("invalid certificate count")
	}
	next := map[string]*tls.Certificate{}
	for _, file := range files {
		host := strings.ToLower(file.Hostname)
		if host == "" || strings.ContainsAny(host, " /:*") || !filepath.IsAbs(file.CertFile) || !filepath.IsAbs(file.KeyFile) || next[host] != nil {
			return fmt.Errorf("invalid certificate entry")
		}
		cert, err := tls.LoadX509KeyPair(file.CertFile, file.KeyFile)
		if err != nil {
			return fmt.Errorf("certificate load failed for %s", host)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil || leaf.VerifyHostname(host) != nil {
			return fmt.Errorf("certificate hostname mismatch for %s", host)
		}
		if now := time.Now(); now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
			return fmt.Errorf("certificate expired or not yet valid for %s", host)
		}
		cert.Leaf = leaf
		next[host] = &cert
	}
	s.certificates.Store(next)
	return nil
}
func (s *certificateStore) tlsConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if snapshot := s.certificates.Load(); snapshot != nil {
			if cert := snapshot.(map[string]*tls.Certificate)[strings.ToLower(hello.ServerName)]; cert != nil {
				now := time.Now()
				if cert.Leaf == nil || now.Before(cert.Leaf.NotBefore) || !now.Before(cert.Leaf.NotAfter) {
					return nil, fmt.Errorf("TLS certificate expired or not yet valid")
				}
				return cert, nil
			}
		}
		return nil, fmt.Errorf("unconfigured TLS server name")
	}}
}
