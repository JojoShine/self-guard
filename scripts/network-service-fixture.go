// Controlled private-network service fixture, never part of the scanner runtime.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	now := time.Now()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	makeCertificate := func(expired bool) tls.Certificate {
		end := now.Add(48 * time.Hour)
		if expired {
			end = now.Add(-24 * time.Hour)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(end.Unix()), Subject: pkix.Name{CommonName: "owned-network.fixture.test"}, DNSNames: []string{"owned-network.fixture.test"}, NotBefore: now.Add(-72 * time.Hour), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
		raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			log.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: key}
	}
	expired, valid := makeCertificate(true), makeCertificate(false)
	fingerprint := sha256.Sum256(expired.Certificate[0])
	var tcpCount, expiredCount, validCount, weakCount, slowCount, applicationBytes atomic.Int64
	listeners := []net.Listener{}
	start := func(port string, settings *tls.Config, counter *atomic.Int64) {
		listener, err := net.Listen("tcp", "0.0.0.0:"+port)
		if err != nil {
			log.Fatal(err)
		}
		listeners = append(listeners, listener)
		go func() {
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				counter.Add(1)
				go func() {
					defer connection.Close()
					connection.SetDeadline(time.Now().Add(3 * time.Second))
					if settings != nil {
						session := tls.Server(connection, settings)
						session.Handshake()
						return
					}
					if port == "8095" {
						time.Sleep(time.Second)
					}
					connection.Write([]byte("owned-legacy-service 1.0\r\n"))
					buffer := make([]byte, 1)
					n, _ := connection.Read(buffer)
					applicationBytes.Add(int64(n))
				}()
			}
		}()
	}
	start("8091", nil, &tcpCount)
	start("8095", nil, &slowCount)
	start("8092", &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{expired}}, &expiredCount)
	start("8093", &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{valid}}, &validCount)
	start("8094", &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10, Certificates: []tls.Certificate{valid}, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}}, &weakCount)
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"tcpConnections": tcpCount.Load(), "slowConnections": slowCount.Load(), "expiredConnections": expiredCount.Load(), "validConnections": validCount.Load(), "weakConnections": weakCount.Load(), "applicationBytes": applicationBytes.Load(), "expiredCertificateSha256": hex.EncodeToString(fingerprint[:]), "fixture": "owned-network-services-v1"})
	})
	server := &http.Server{Addr: "0.0.0.0:8090", Handler: mux, ReadHeaderTimeout: time.Second, WriteTimeout: time.Second, MaxHeaderBytes: 4096}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	fmt.Println("Owned network service fixture ready")
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGTERM, syscall.SIGINT)
	<-done
	for _, listener := range listeners {
		listener.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	server.Shutdown(ctx)
}
