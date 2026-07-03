// Command feedserver is the hermetic stand-in for real threat-feed
// providers in integration and e2e tests. Tests must never depend on live
// feeds: providers rate-limit and ban aggressive fetchers, contents change
// under the test, and CI without egress would flake. Serving the shared
// fixture zoo over plain HTTP keeps every test layer (unit, netns, Vagrant)
// exercising identical bytes.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18080", "listen address")
	dir := flag.String("dir", "test/fixtures/feeds", "directory to serve")
	flag.Parse()

	if _, err := os.Stat(*dir); err != nil {
		log.Fatalf("fixture dir: %v", err)
	}

	// Listen explicitly (rather than http.ListenAndServe) so "READY" is
	// printed only when the socket is actually accepting — test scripts
	// poll for that line instead of sleeping arbitrary durations.
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("READY %s\n", ln.Addr())

	// Deliberately NOT http.FileServer: its Last-Modified/304 handling has
	// one-second mtime granularity, so a test that rewrites a fixture and
	// immediately re-fetches would be served the stale body. Tests need
	// every GET to return the file as it is right now; the client's
	// conditional-request logic has its own unit tests against httptest.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := os.ReadFile(filepath.Join(*dir, filepath.Clean("/"+r.URL.Path)))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	})
	log.Fatal(http.Serve(ln, handler))
}
