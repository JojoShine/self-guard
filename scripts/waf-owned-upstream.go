// Dedicated business upstream for the owned WAF reference VM. Both baseline
// and protected requests reach this same independent process over loopback.
package main

import (
	"io"
	"log"
	"net/http"
	"time"
)

func main() {
	server := &http.Server{Addr: "127.0.0.1:18082", ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			http.Error(w, "owned upstream body incomplete", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, "owned persistent upstream")
	})
	log.Fatal(server.ListenAndServe())
}
