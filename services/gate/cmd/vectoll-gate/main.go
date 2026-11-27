package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/vectoll/vectoll/services/gate/internal/gate"
)

func main() {
	defaultCfg := os.Getenv("VECTOLL_CONFIG")
	if defaultCfg == "" {
		defaultCfg = "vectoll.yaml"
	}
	configPath := flag.String("config", defaultCfg, "Path to vectoll.yaml configuration")
	listenOverride := flag.String("listen", os.Getenv("VECTOLL_GATE_LISTEN"), "Override listen address (e.g. :4020)")
	flag.Parse()

	cfg, err := gate.LoadConfigFile(*configPath)
	if err != nil {
		log.Fatalf("vectoll-gate: failed to load config %s: %v", *configPath, err)
	}
	if *listenOverride != "" {
		cfg.Service.Listen = *listenOverride
	}

	proxy, err := gate.NewProxyServer(cfg)
	if err != nil {
		log.Fatalf("vectoll-gate: failed to initialize proxy: %v", err)
	}

	srv := &http.Server{
		Addr:              cfg.Service.Listen,
		Handler:           proxy,
		ReadHeaderTimeout: 5 * time.Second,
	}

	fmt.Printf("vectoll-gate v0.1 listening on %s -> origin %s (service=%s)\n",
		cfg.Service.Listen, cfg.Service.Origin, cfg.Service.Name)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("vectoll-gate server error: %v", err)
	}
}
