// Direwolf API Bridge — connects to a Dire Wolf KISS TCP feed and exposes
// decoded AX.25/APRS packets over an HTTP REST+WebSocket API with an
// embedded web UI.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
)

func main() {
	loaded, err := loadConfig(os.Args[1:], os.Getenv)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	cfg := loaded.Config

	log.Printf("Direwolf API Bridge")
	if loaded.Meta.Path != "" {
		log.Printf("  Config file  : %s", loaded.Meta.Path)
	}
	log.Printf("  KISS address : %s", cfg.KISS)
	log.Printf("  API address  : %s", cfg.API)
	if cfg.TLS != "" {
		log.Printf("  TLS address  : %s (cert=%s, key=%s)", cfg.TLS, cfg.Cert, cfg.Key)
	}
	log.Printf("  Max packets  : %d", cfg.MaxPackets)
	if cfg.CSV != "" {
		log.Printf("  CSV output   : %s", cfg.CSV)
	}
	if cfg.Forward.URL != "" {
		log.Printf("  Forward      : %s (node=%s, spool=%s)", cfg.Forward.URL, cfg.Forward.NodeID, cfg.Forward.SpoolDir)
		log.Printf("  Forward auth : token from %s", loaded.Meta.TokenSource)
		if cfg.Forward.HealthURL != "" {
			log.Printf("  Forward check: %s every %s", cfg.Forward.HealthURL, cfg.Forward.HealthInterval.Std())
		}
		warnConfigPermissions(loaded)
	} else {
		log.Printf("  Forward      : disabled")
	}

	// Graceful shutdown on SIGINT / SIGTERM.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("Shutting down...")
		cancel()
	}()

	// Packet forwarder (optional).
	var forwarder *Forwarder
	if cfg.Forward.URL != "" {
		forwarder, err = NewForwarder(cfg.Forward)
		if err != nil {
			log.Fatalf("forwarding setup failed: %v", err)
		}
		forwarder.Start(ctx)
	}

	// Wire up KISS client and HTTP API server.
	kissClient := NewClient(cfg.KISS)
	server := NewServer(cfg.API, cfg.TLS, cfg.Cert, cfg.Key, cfg.MaxPackets, cfg.CSV, kissClient)
	if forwarder != nil {
		server.SetForwarder(forwarder)
	}

	kissClient.Start(ctx)

	log.Printf("Web UI: http://%s", uiAddress(cfg.API))
	startErr := server.Start(ctx)

	if forwarder != nil {
		if err := forwarder.Close(); err != nil {
			log.Printf("[FWD] shutdown: %v", err)
		}
	}
	if startErr != nil {
		log.Fatal(startErr)
	}
}

// uiAddress renders a clickable address for the startup log.
func uiAddress(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "localhost" + addr
	}
	return addr
}

// warnConfigPermissions warns when a hand-edited config file holding the
// forwarding token is readable by group or others.
func warnConfigPermissions(loaded LoadedConfig) {
	if loaded.Meta.Path == "" || loaded.Meta.TokenSource != "config" || runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(loaded.Meta.Path)
	if err != nil {
		return
	}
	if info.Mode().Perm()&0o077 != 0 {
		log.Printf("[CONFIG] warning: %s contains the forwarding token and is readable by group/others; chmod 600 is recommended", loaded.Meta.Path)
	}
}
