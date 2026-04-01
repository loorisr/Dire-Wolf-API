package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"direwolf_api/api"
	"direwolf_api/kiss"
)

func main() {
	kissAddr := flag.String("kiss", "localhost:8001", "Direwolf KISS TCP address")
	apiAddr := flag.String("api", ":8080", "API listen address")
	maxPackets := flag.Int("max", 1000, "Max packets to keep in memory")
	flag.Parse()

	log.Printf("Direwolf API Bridge")
	log.Printf("  KISS address : %s", *kissAddr)
	log.Printf("  API address  : %s", *apiAddr)
	log.Printf("  Max packets  : %d", *maxPackets)

	ctx, cancel := context.WithCancel(context.Background())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("Shutting down...")
		cancel()
	}()

	kissClient := kiss.NewClient(*kissAddr)
	server := api.NewServer(*apiAddr, *maxPackets, kissClient)

	kissClient.Start(ctx)

	log.Printf("Web UI: http://localhost%s", *apiAddr)
	if err := server.Start(ctx); err != nil {
		log.Fatal(err)
	}
}
