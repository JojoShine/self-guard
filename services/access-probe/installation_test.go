package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
)

func TestInstallationSeparatesContinuousCaptureDecoderAndOfflineExpiry(t *testing.T) {
	c := ProbeLocalConfig{SourceID: "6bc04a33-c4cf-48e3-8282-9833e52d0b97", StateDir: "/var/lib/selfguard/access-probe/6bc04a33-c4cf-48e3-8282-9833e52d0b97"}
	decoder, capture, expiry, timer := probeUnits(c, "sgp6bc04a33c4cf48e3", false)
	if strings.Contains(decoder, "CAP_NET_RAW") || !strings.Contains(decoder, "CapabilityBoundingSet=\n") || !strings.Contains(decoder, "User=sgp") {
		t.Fatal("decoder inherited capture privileges")
	}
	if !strings.Contains(capture, "CAP_NET_RAW") || !strings.Contains(capture, "--capture-config") || !strings.Contains(capture, "Restart=on-failure") || strings.Contains(capture, "--duration") {
		t.Fatal("continuous capture unit invalid")
	}
	if !strings.Contains(expiry, "--expire-queue") || !strings.Contains(timer, "OnUnitActiveSec=1h") {
		t.Fatal("offline 7-day purge timer missing")
	}
	_, tlsCapture, _, _ := probeUnits(c, "sgp6bc04a33c4cf48e3", true)
	if !strings.Contains(tlsCapture, "--openssl-capture-config") || !strings.Contains(tlsCapture, "CAP_BPF") {
		t.Fatal("separate TLS collector missing")
	}
}

func TestInstallerCopiesPublicCertificatesOnly(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if out, err := publicCACertificates(certificate); err != nil || !bytes.Equal(out, certificate) {
		t.Fatal("public certificate", err)
	}
	combined := append(certificate, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("synthetic-only")})...)
	if _, err := publicCACertificates(combined); err == nil {
		t.Fatal("combined private key accepted for decoder CA file")
	}
}
