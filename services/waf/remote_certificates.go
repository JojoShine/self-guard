package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type remoteCertificate struct {
	Hostname    string `json:"hostname"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
	Version     int    `json:"version"`
}
type remoteCertificateResponse struct {
	Items       []remoteCertificate `json:"items"`
	GeneratedAt string              `json:"generatedAt"`
}

func parseRemoteCertificates(items []remoteCertificate, checkValidity bool) (map[string]*tls.Certificate, error) {
	if items == nil {
		return nil, fmt.Errorf("remote certificate list is required")
	}
	if len(items) > 200 {
		return nil, fmt.Errorf("remote certificate count exceeds limit")
	}
	next := map[string]*tls.Certificate{}
	for _, item := range items {
		host := strings.ToLower(item.Hostname)
		if host == "" || strings.ContainsAny(host, " /:*\x00") || next[host] != nil {
			return nil, fmt.Errorf("invalid remote certificate hostname")
		}
		cert, err := tls.X509KeyPair([]byte(item.Certificate), []byte(item.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("remote certificate or key rejected")
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil || leaf.VerifyHostname(host) != nil {
			return nil, fmt.Errorf("remote certificate hostname rejected")
		}
		now := time.Now()
		if checkValidity && (now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter)) {
			return nil, fmt.Errorf("remote certificate validity rejected")
		}
		cert.Leaf = leaf
		next[host] = &cert
	}
	return next, nil
}
func certificateCipher(token string) (cipher.AEAD, error) {
	if len(token) < 32 {
		return nil, fmt.Errorf("remote certificates require WAF_TOKEN of at least 32 characters")
	}
	key := sha256.Sum256([]byte("selfguard-waf-certificates-v1\x00" + token))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func (s *certificateStore) saveRemoteCache(dir, token string, b []byte) error {
	aead, err := certificateCipher(token)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	sealed := aead.Seal(nonce, nonce, b, []byte("selfguard-waf-certificates-v1"))
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err = persistConfig(filepath.Join(dir, "certificates.enc"), sealed); err != nil {
		return fmt.Errorf("certificate cache persistence failed")
	}
	return syncDirectory(dir)
}
func (s *certificateStore) loadRemoteCache(dir, token string) error {
	aead, err := certificateCipher(token)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(dir, "certificates.enc"))
	if err != nil {
		return err
	}
	if len(b) < aead.NonceSize()+aead.Overhead() || len(b) > 24<<20 {
		return fmt.Errorf("invalid encrypted certificate cache")
	}
	plain, err := aead.Open(nil, b[:aead.NonceSize()], b[aead.NonceSize():], []byte("selfguard-waf-certificates-v1"))
	if err != nil {
		return fmt.Errorf("certificate cache authentication failed")
	}
	var payload remoteCertificateResponse
	if json.Unmarshal(plain, &payload) != nil {
		return fmt.Errorf("invalid certificate cache payload")
	}
	next, err := parseRemoteCertificates(payload.Items, false)
	if err != nil {
		return err
	}
	s.certificates.Store(next)
	return nil
}
func (s *certificateStore) syncRemote(client *http.Client, base, token, dir string) error {
	req, err := http.NewRequest("GET", base+"/api/waf/certificates", nil)
	if err != nil {
		return fmt.Errorf("invalid certificate management address")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("certificate management request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("certificate management status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (24<<20)+1))
	if err != nil || len(b) > 24<<20 {
		return fmt.Errorf("certificate management response exceeds limit")
	}
	var payload remoteCertificateResponse
	if json.Unmarshal(b, &payload) != nil {
		return fmt.Errorf("invalid certificate management response")
	}
	next, err := parseRemoteCertificates(payload.Items, true)
	if err != nil {
		return err
	}
	if err = s.saveRemoteCache(dir, token, b); err != nil {
		return err
	}
	s.certificates.Store(next)
	return nil
}
