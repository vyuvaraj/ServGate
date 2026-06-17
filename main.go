package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"servgate/pkg/otel"
	"servgate/pkg/proxy"
	"servgate/pkg/wasm"
)

type Config struct {
	Addr      string        `json:"addr"`
	AuthToken string        `json:"auth_token"`
	TlsCert   string        `json:"tls_cert"`
	TlsKey    string        `json:"tls_key"`
	Routes    []proxy.Route `json:"routes"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "replay" {
		runReplayCommand()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "install" {
		runInstallCommand()
		return
	}

	// Initialize distributed tracing
	otel.Init()

	configFile, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("Gateway: failed to open config: %v", err)
	}
	defer configFile.Close()

	var cfg Config
	if err := json.NewDecoder(configFile).Decode(&cfg); err != nil {
		log.Fatalf("Gateway: failed to parse config: %v", err)
	}

	wasmManager, err := wasm.GetMiddlewareManager(context.Background())
	if err != nil {
		log.Fatalf("Gateway: failed to start WASM: %v", err)
	}

	handler := proxy.NewGatewayHandler(cfg.Routes, wasmManager, cfg.AuthToken)

	// Admin API endpoint to dynamically register WASM middlewares on the fly
	mux := http.NewServeMux()
	mux.Handle("/", handler)
	mux.HandleFunc("/api/admin/middleware/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		
		// Auth check for admin registration
		if cfg.AuthToken != "" {
			if r.Header.Get("Authorization") != "Bearer "+cfg.AuthToken {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 5 {
			http.Error(w, "Invalid path. Use /api/admin/middleware/{name}", http.StatusBadRequest)
			return
		}
		name := parts[4]

		wasmBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		err = wasmManager.Register(r.Context(), name, wasmBytes)
		if err != nil {
			http.Error(w, "Failed to compile WASM: "+err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("WASM Middleware " + name + " compiled and registered"))
	})

	log.Printf("Starting ServGate reverse proxy on %s...", cfg.Addr)
	server := &http.Server{
		Addr:    cfg.Addr,
		Handler: mux,
	}

	if cfg.TlsCert != "" && cfg.TlsKey != "" {
		if err := server.ListenAndServeTLS(cfg.TlsCert, cfg.TlsKey); err != nil {
			log.Fatalf("Gateway: HTTP server error: %v", err)
		}
	} else {
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Gateway: HTTP server error: %v", err)
		}
	}
}

func runReplayCommand() {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	logPath := fs.String("log", "", "Path to JSONL traffic log file")
	mwPath := fs.String("middleware", "", "Path to WASM middleware file")
	outPath := fs.String("output", "", "Optional path to save JSON report file")

	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Replay: failed to parse arguments: %v", err)
	}

	if *logPath == "" || *mwPath == "" {
		log.Fatalf("Replay: --log and --middleware flags are required. Example: servgate replay --log traffic.jsonl --middleware auth.wasm")
	}

	wasmBytes, err := os.ReadFile(*mwPath)
	if err != nil {
		log.Fatalf("Replay: failed to read WASM file: %v", err)
	}

	stats, err := proxy.ReplayTraffic(context.Background(), *logPath, wasmBytes)
	if err != nil {
		log.Fatalf("Replay: execution error: %v", err)
	}

	reportBytes, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		log.Fatalf("Replay: failed to marshal stats report: %v", err)
	}

	fmt.Println("--- Traffic Replay Summary Report ---")
	fmt.Printf("Total Requests:  %d\n", stats.Total)
	fmt.Printf("Successes:       %d\n", stats.Successes)
	fmt.Printf("Failures:        %d\n", stats.Failures)
	if stats.Successes > 0 {
		fmt.Printf("Min Latency:     %v\n", stats.MinLatency)
		fmt.Printf("Max Latency:     %v\n", stats.MaxLatency)
		fmt.Printf("Avg Latency:     %v\n", stats.AvgLatency)
		fmt.Printf("P50 Latency:     %v\n", stats.P50Latency)
		fmt.Printf("P90 Latency:     %v\n", stats.P90Latency)
		fmt.Printf("P99 Latency:     %v\n", stats.P99Latency)
	}

	if *outPath != "" {
		if err := os.WriteFile(*outPath, reportBytes, 0644); err != nil {
			log.Fatalf("Replay: failed to write output file: %v", err)
		}
		fmt.Printf("\nReport saved to: %s\n", *outPath)
	}
}

func runInstallCommand() {
	if len(os.Args) < 3 {
		log.Fatalf("Install: middleware name is required. Example: servgate install jwt-auth")
	}
	name := os.Args[2]

	registry := os.Getenv("SERV_REGISTRY")
	if registry == "" {
		registry = "https://registry.serv-lang.org"
	}
	registry = strings.TrimSuffix(registry, "/")

	url := fmt.Sprintf("%s/middlewares/%s.wasm", registry, name)
	fmt.Printf("Installing middleware '%s' from %s...\n", name, url)

	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Install: failed to connect to registry: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Install: registry returned status %d", resp.StatusCode)
	}

	if err := os.MkdirAll("middlewares", 0755); err != nil {
		log.Fatalf("Install: failed to create middlewares directory: %v", err)
	}

	destPath := filepath.Join("middlewares", name+".wasm")
	destFile, err := os.Create(destPath)
	if err != nil {
		log.Fatalf("Install: failed to create destination file: %v", err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, resp.Body)
	if err != nil {
		log.Fatalf("Install: failed to write file: %v", err)
	}

	fmt.Printf("✓ Middleware '%s' successfully installed to %s\n", name, destPath)
}
