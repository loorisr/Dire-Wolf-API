// Direwolf API Bridge — connects to a Dire Wolf KISS TCP feed and exposes
// decoded AX.25/APRS packets over an HTTP REST+WebSocket API with an
// embedded web UI.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	kissAddr := flag.String("kiss", "localhost:8001", "Direwolf KISS TCP address")
	apiAddr := flag.String("api", ":8080", "API listen address")
	tlsAddr := flag.String("tls", "", "HTTPS/WSS listen address (e.g. :8443), disabled if empty")
	certFile := flag.String("cert", "", "TLS certificate file (auto-generated if empty)")
	keyFile := flag.String("key", "", "TLS private key file (auto-generated if empty)")
	maxPackets := flag.Int("max", 1000, "Max packets to keep in memory")
	csvPath := flag.String("csv", "", "CSV output file path (disabled if empty)")
	flag.Parse()

	log.Printf("Direwolf API Bridge")
	log.Printf("  KISS address : %s", *kissAddr)
	log.Printf("  API address  : %s", *apiAddr)
	if *tlsAddr != "" {
		log.Printf("  TLS address  : %s (cert=%s, key=%s)", *tlsAddr, *certFile, *keyFile)
	}
	log.Printf("  Max packets  : %d", *maxPackets)
	if *csvPath != "" {
		log.Printf("  CSV output   : %s", *csvPath)
	}

	// Graceful shutdown on SIGINT / SIGTERM.
	ctx, cancel := context.WithCancel(context.Background())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("Shutting down...")
		cancel()
	}()

	// Wire up KISS client and HTTP API server.
	kissClient := NewClient(*kissAddr)
	server := NewServer(*apiAddr, *tlsAddr, *certFile, *keyFile, *maxPackets, *csvPath, kissClient)

	kissClient.Start(ctx)

	log.Printf("Web UI: http://localhost%s", *apiAddr)
	if err := server.Start(ctx); err != nil {
		log.Fatal(err)
	}
}
