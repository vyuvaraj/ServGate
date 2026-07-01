package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"servgate/pkg/otel"
	"servgate/pkg/proxy"
	"servgate/pkg/wasm"

	"golang.org/x/crypto/acme/autocert"

	"github.com/vyuvaraj/ServShared"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "replay" {
		runReplayCommand()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "install" {
		runInstallCommand()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "policy" {
		runPolicyCommand()
		return
	}

	// Initialize distributed tracing
	otel.Init()

	var prov proxy.ConfigProvider
	if os.Getenv("SERV_CONFIG_S3_BUCKET") != "" || os.Getenv("SERVVERSE_DISCOVERY") != "" {
		log.Println("Gateway: Using S3-compatible configuration provider")
		prov = proxy.NewS3ConfigProvider()
	} else {
		log.Println("Gateway: Using local file config provider")
		prov = proxy.NewLocalFileProvider("config.json")
	}

	cfg, err := prov.Load()
	if err != nil {
		log.Fatalf("Gateway: failed to load config: %v", err)
	}

	wasmManager, err := wasm.GetMiddlewareManager(context.Background())
	if err != nil {
		log.Fatalf("Gateway: failed to start WASM: %v", err)
	}

	handler := proxy.NewGatewayHandler(cfg.Routes, wasmManager, cfg.AuthToken)

	// If using S3 configuration provider, poll for updates in background
	if s3Prov, ok := prov.(*proxy.S3ConfigProvider); ok {
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			
			var lastRoutesBytes []byte
			if rb, err := json.Marshal(cfg.Routes); err == nil {
				lastRoutesBytes = rb
			}

			for range ticker.C {
				newCfg, err := s3Prov.Load()
				if err != nil {
					continue
				}
				
				rb, err := json.Marshal(newCfg.Routes)
				if err == nil && !bytes.Equal(rb, lastRoutesBytes) {
					log.Printf("Gateway: Config changed on S3. Reloading routes dynamically...")
					handler.UpdateRoutes(newCfg.Routes)
					lastRoutesBytes = rb
				}
			}
		}()
	}

	// Admin API endpoint to dynamically register WASM middlewares on the fly
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", ServShared.HealthzHandler)
	mux.HandleFunc("/readyz", ServShared.ReadyzHandler)
	mux.HandleFunc("/api/version", ServShared.VersionHandler("servgate", "1.0.0"))
	mux.Handle("/", handler)

	handleMiddleware := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			proxy.WriteJSONError(w, r, "Method not allowed", "ERR_METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}
		
		// Auth check for admin registration
		if cfg.AuthToken != "" {
			if r.Header.Get("Authorization") != "Bearer "+cfg.AuthToken {
				proxy.WriteJSONError(w, r, "Unauthorized", "ERR_UNAUTHORIZED", http.StatusUnauthorized)
				return
			}
		}

		parts := strings.Split(r.URL.Path, "/")
		var name string
		if len(parts) >= 6 && parts[2] == "v1" {
			name = parts[5]
		} else if len(parts) >= 5 {
			name = parts[4]
		} else {
			proxy.WriteJSONError(w, r, "Invalid path. Use /api/v1/admin/middleware/{name}", "ERR_INVALID_PATH", http.StatusBadRequest)
			return
		}

		wasmBytes, err := io.ReadAll(r.Body)
		if err != nil {
			proxy.WriteJSONError(w, r, "Internal Server Error", "ERR_INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		err = wasmManager.Register(r.Context(), name, wasmBytes)
		if err != nil {
			proxy.WriteJSONError(w, r, "Failed to compile WASM: "+err.Error(), "ERR_WASM_COMPILATION_FAILED", http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("WASM Middleware " + name + " compiled and registered"))
	}

	handleConnections := func(w http.ResponseWriter, r *http.Request) {
		if cfg.AuthToken != "" {
			if r.Header.Get("Authorization") != "Bearer "+cfg.AuthToken {
				proxy.WriteJSONError(w, r, "Unauthorized", "ERR_UNAUTHORIZED", http.StatusUnauthorized)
				return
			}
		}

		if r.Method != http.MethodGet {
			proxy.WriteJSONError(w, r, "Method not allowed", "ERR_METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(handler.GetActiveConnections())
	}

	handleRoutes := func(w http.ResponseWriter, r *http.Request) {
		if cfg.AuthToken != "" {
			authHeader := r.Header.Get("Authorization")
			token := strings.TrimPrefix(authHeader, "Bearer ")
			authenticated := false
			if token == cfg.AuthToken {
				authenticated = true
			} else if jwtSec := os.Getenv("SERV_JWT_SECRET"); jwtSec != "" {
				if _, ok := proxy.ValidateJWT(token, []byte(jwtSec)); ok {
					authenticated = true
				}
			}

			if !authenticated {
				proxy.WriteJSONError(w, r, "Unauthorized", "ERR_UNAUTHORIZED", http.StatusUnauthorized)
				return
			}
		}

		if r.Method == http.MethodPost {
			var newRoute proxy.Route
			if err := json.NewDecoder(r.Body).Decode(&newRoute); err != nil {
				proxy.WriteJSONError(w, r, "Invalid route payload", "ERR_INVALID_ROUTE_PAYLOAD", http.StatusBadRequest)
				return
			}
			
			currentCfg, err := prov.Load()
			if err != nil {
				if os.IsNotExist(err) {
					currentCfg = cfg
				} else {
					proxy.WriteJSONError(w, r, "Failed to load config: "+err.Error(), "ERR_CONFIG_LOAD_FAILED", http.StatusInternalServerError)
					return
				}
			}
			
			found := false
			for i, rt := range currentCfg.Routes {
				if rt.Prefix == newRoute.Prefix {
					currentCfg.Routes[i] = newRoute
					found = true
					break
				}
			}
			if !found {
				currentCfg.Routes = append(currentCfg.Routes, newRoute)
			}
			
			if err := prov.Save(currentCfg); err != nil {
				proxy.WriteJSONError(w, r, "Failed to save config: "+err.Error(), "ERR_CONFIG_SAVE_FAILED", http.StatusInternalServerError)
				return
			}
			
			handler.UpdateRoutes(currentCfg.Routes)
			
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Route registered successfully"))
			return
		}

		if r.Method == http.MethodDelete {
			prefix := r.URL.Query().Get("prefix")
			if prefix == "" {
				proxy.WriteJSONError(w, r, "Missing prefix query parameter", "ERR_INVALID_ROUTE_PAYLOAD", http.StatusBadRequest)
				return
			}

			currentCfg, err := prov.Load()
			if err != nil {
				proxy.WriteJSONError(w, r, "Failed to load config: "+err.Error(), "ERR_CONFIG_LOAD_FAILED", http.StatusInternalServerError)
				return
			}

			newRoutes := []proxy.Route{}
			found := false
			for _, rt := range currentCfg.Routes {
				if rt.Prefix == prefix {
					found = true
				} else {
					newRoutes = append(newRoutes, rt)
				}
			}

			if !found {
				proxy.WriteJSONError(w, r, "Route not found", "ERR_ROUTE_NOT_FOUND", http.StatusNotFound)
				return
			}

			currentCfg.Routes = newRoutes
			if err := prov.Save(currentCfg); err != nil {
				proxy.WriteJSONError(w, r, "Failed to save config: "+err.Error(), "ERR_CONFIG_SAVE_FAILED", http.StatusInternalServerError)
				return
			}

			handler.UpdateRoutes(currentCfg.Routes)

			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Route deleted successfully"))
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(handler.GetRoutes())
	}

	handleRouteRegister := func(w http.ResponseWriter, r *http.Request) {
		if cfg.AuthToken != "" {
			authHeader := r.Header.Get("Authorization")
			token := strings.TrimPrefix(authHeader, "Bearer ")
			authenticated := false
			if token == cfg.AuthToken {
				authenticated = true
			} else if jwtSec := os.Getenv("SERV_JWT_SECRET"); jwtSec != "" {
				if _, ok := proxy.ValidateJWT(token, []byte(jwtSec)); ok {
					authenticated = true
				}
			}

			if !authenticated {
				proxy.WriteJSONError(w, r, "Unauthorized", "ERR_UNAUTHORIZED", http.StatusUnauthorized)
				return
			}
		}

		if r.Method != http.MethodPost {
			proxy.WriteJSONError(w, r, "Method not allowed", "ERR_METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		var newRoute proxy.Route
		if err := json.NewDecoder(r.Body).Decode(&newRoute); err != nil {
			proxy.WriteJSONError(w, r, "Invalid route payload", "ERR_INVALID_ROUTE_PAYLOAD", http.StatusBadRequest)
			return
		}

		handler.RegisterRoute(newRoute)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success","message":"Route registered successfully via compiler connector"}`))
	}

	handleConsoleSync := func(w http.ResponseWriter, r *http.Request) {
		if cfg.AuthToken != "" {
			authHeader := r.Header.Get("Authorization")
			token := strings.TrimPrefix(authHeader, "Bearer ")
			authenticated := false
			if token == cfg.AuthToken {
				authenticated = true
			} else if jwtSec := os.Getenv("SERV_JWT_SECRET"); jwtSec != "" {
				if _, ok := proxy.ValidateJWT(token, []byte(jwtSec)); ok {
					authenticated = true
				}
			}

			if !authenticated {
				proxy.WriteJSONError(w, r, "Unauthorized", "ERR_UNAUTHORIZED", http.StatusUnauthorized)
				return
			}
		}

		if r.Method == http.MethodPost {
			var payload struct {
				Routes []proxy.Route `json:"routes"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				proxy.WriteJSONError(w, r, "Invalid payload", "ERR_INVALID_PAYLOAD", http.StatusBadRequest)
				return
			}

			currentCfg, err := prov.Load()
			if err == nil {
				currentCfg.Routes = payload.Routes
				_ = prov.Save(currentCfg)
			}

			handler.UpdateRoutes(payload.Routes)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"success","message":"Console sync updated configuration successfully"}`))
			return
		}

		if r.Method == http.MethodGet {
			snapshot := map[string]interface{}{
				"routes":              handler.GetRoutes(),
				"active_connections":  handler.GetActiveConnections(),
				"metrics":             handler.GetMetricsSnapshot(),
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(snapshot)
			return
		}

		proxy.WriteJSONError(w, r, "Method not allowed", "ERR_METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
	}

	handleGitOpsWebhook := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			proxy.WriteJSONError(w, r, "Method not allowed", "ERR_METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		if cfg.AuthToken != "" {
			authHeader := r.Header.Get("Authorization")
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token != cfg.AuthToken {
				proxy.WriteJSONError(w, r, "Unauthorized", "ERR_UNAUTHORIZED", http.StatusUnauthorized)
				return
			}
		}

		configDir := "."
		if filePath, ok := prov.(*proxy.LocalFileProvider); ok {
			configDir = filepath.Dir(filePath.Path)
		}

		log.Printf("GitOps: Webhook triggered. Running git pull in directory: %s", configDir)
		cmd := exec.Command("git", "pull")
		cmd.Dir = configDir
		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			log.Printf("GitOps: git pull failed: %v, stderr: %s", err, stderr.String())
		} else {
			log.Printf("GitOps: git pull completed. Output: %s", out.String())
		}

		newCfg, err := prov.Load()
		if err != nil {
			proxy.WriteJSONError(w, r, "Failed to load reloaded config: "+err.Error(), "ERR_CONFIG_LOAD_FAILED", http.StatusInternalServerError)
			return
		}

		handler.UpdateRoutes(newCfg.Routes)
		log.Println("GitOps: Configuration re-sync completed successfully.")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success","message":"GitOps config sync completed successfully","git_output":"` + strings.TrimSpace(out.String()) + `"}`))
	}

	mux.HandleFunc("/api/gitops/webhook", withAdminRateLimit(60, handleGitOpsWebhook))
	mux.HandleFunc("/api/v1/gitops/webhook", withAdminRateLimit(60, handleGitOpsWebhook))

	mux.HandleFunc("/api/v1/routes/register", withAdminRateLimit(60, handleRouteRegister))
	mux.HandleFunc("/api/admin/console/sync", withAdminRateLimit(60, handleConsoleSync))
	mux.HandleFunc("/api/v1/admin/console/sync", withAdminRateLimit(60, handleConsoleSync))
	mux.HandleFunc("/api/admin/middleware/", withAdminRateLimit(60, handleMiddleware))
	mux.HandleFunc("/api/v1/admin/middleware/", withAdminRateLimit(60, handleMiddleware))
	mux.HandleFunc("/api/routes", withAdminRateLimit(60, handleRoutes))
	mux.HandleFunc("/api/v1/routes", withAdminRateLimit(60, handleRoutes))
	mux.HandleFunc("/api/admin/connections", withAdminRateLimit(60, handleConnections))
	mux.HandleFunc("/api/v1/admin/connections", withAdminRateLimit(60, handleConnections))

	// Cache invalidation admin endpoint
	handleCacheInvalidation := func(w http.ResponseWriter, r *http.Request) {
		if cfg.AuthToken != "" {
			if r.Header.Get("Authorization") != "Bearer "+cfg.AuthToken {
				proxy.WriteJSONError(w, r, "Unauthorized", "ERR_UNAUTHORIZED", http.StatusUnauthorized)
				return
			}
		}

		if r.Method != http.MethodDelete {
			proxy.WriteJSONError(w, r, "Method not allowed", "ERR_METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		prefix := r.URL.Query().Get("prefix")
		count := handler.InvalidateCache(prefix, "")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":            "success",
			"entries_invalidated": count,
			"prefix":            prefix,
		})
	}
	mux.HandleFunc("/api/admin/cache", withAdminRateLimit(60, handleCacheInvalidation))
	mux.HandleFunc("/api/v1/admin/cache", withAdminRateLimit(60, handleCacheInvalidation))

	// AI Billing API endpoint
	handleAIBilling := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			metrics := handler.GetAIBillingMetrics()
			json.NewEncoder(w).Encode(metrics)
		case http.MethodPost:
			// Set budget
			var req struct {
				TenantID           string  `json:"tenant_id"`
				MaxCostPerDay      float64 `json:"max_cost_per_day_usd"`
				MaxTokensPerMinute int     `json:"max_tokens_per_minute"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}
			handler.SetAIBudget(req.TenantID, req.MaxCostPerDay, req.MaxTokensPerMinute)
			w.Write([]byte(`{"status":"budget_updated"}`))
		}
	}
	mux.HandleFunc("/api/admin/ai-billing", withAdminRateLimit(60, handleAIBilling))
	mux.HandleFunc("/api/v1/admin/ai-billing", withAdminRateLimit(60, handleAIBilling))

	handleMetricsWS := func(w http.ResponseWriter, r *http.Request) {
		if cfg.AuthToken != "" {
			token := r.Header.Get("Authorization")
			token = strings.TrimPrefix(token, "Bearer ")
			if token == "" {
				token = r.URL.Query().Get("token")
			}
			if token != cfg.AuthToken {
				proxy.WriteJSONError(w, r, "Unauthorized", "ERR_UNAUTHORIZED", http.StatusUnauthorized)
				return
			}
		}
		proxy.HandleWebSocketMetrics(w, r, handler)
	}
	mux.HandleFunc("/api/admin/metrics/ws", handleMetricsWS)
	mux.HandleFunc("/api/v1/admin/metrics/ws", handleMetricsWS)

	log.Printf("Starting ServGate reverse proxy on %s...", cfg.Addr)
	server := &http.Server{
		Addr:    cfg.Addr,
		Handler: mux,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	autoTLS := os.Getenv("SERV_AUTO_TLS") == "true"
	autoTLSDomain := os.Getenv("SERV_AUTO_TLS_DOMAIN")

	go func() {
		if autoTLS && autoTLSDomain != "" {
			log.Printf("Gateway: Enabling Let's Encrypt Auto TLS for domain: %s", autoTLSDomain)
			certManager := autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(autoTLSDomain),
				Cache:      autocert.DirCache("certs"),
			}
			server.Addr = ":443"
			server.TLSConfig = certManager.TLSConfig()
			
			go func() {
				log.Printf("Gateway: Starting Let's Encrypt HTTP challenge redirect on :80")
				if err := http.ListenAndServe(":80", certManager.HTTPHandler(nil)); err != nil {
					log.Printf("autocert HTTP challenge listener error: %v", err)
				}
			}()
			
			if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Gateway: HTTP server error: %v", err)
			}
		} else if cfg.TlsCert != "" && cfg.TlsKey != "" {
			if err := server.ListenAndServeTLS(cfg.TlsCert, cfg.TlsKey); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Gateway: HTTP server error: %v", err)
			}
		} else {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Gateway: HTTP server error: %v", err)
			}
		}
	}()

	<-ctx.Done()
	log.Println("Gateway: Shutting down gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Gateway: Server forced to shutdown: %v", err)
	} else {
		log.Println("Gateway: Server exited cleanly")
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

func runPolicyCommand() {
	if len(os.Args) < 5 || os.Args[2] != "compile" {
		log.Fatal("Usage: servgate policy compile <file.policy> -o <file.wasm>")
	}
	policyFile := os.Args[3]
	outputWasm := os.Args[5]

	content, err := os.ReadFile(policyFile)
	if err != nil {
		log.Fatalf("Failed to read policy file: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	var rulesCode strings.Builder

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		action := parts[0] // "allow" or "deny"
		method := parts[1] // "GET", "POST", "*"
		path := parts[2]   // "/api/data", "*"

		var cond string
		if len(parts) >= 6 && parts[3] == "if" && strings.HasPrefix(parts[4], "header.") && parts[5] == "==" {
			hdrName := strings.ToLower(strings.TrimPrefix(parts[4], "header."))
			val := strings.Join(parts[6:], " ")
			val = strings.Trim(val, "\"")
			cond = fmt.Sprintf(" && req.Headers[%q] == %q", hdrName, val)
		}

		methodCond := fmt.Sprintf("req.Method == %q", method)
		if method == "*" {
			methodCond = "true"
		}

		pathCond := fmt.Sprintf("req.Path == %q", path)
		if path == "*" {
			pathCond = "true"
		}

		rulesCode.WriteString(fmt.Sprintf(`	if %s && %s%s {
		fmt.Print(%q)
		return
	}
`, methodCond, pathCond, cond, action))
	}

	goSource := fmt.Sprintf(`package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type Request struct {
	Method  string            ` + "`" + `json:"method"` + "`" + `
	Path    string            ` + "`" + `json:"path"` + "`" + `
	Headers map[string]string ` + "`" + `json:"headers"` + "`" + `
}

func main() {
	body, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Print("deny")
		return
	}

	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		fmt.Print("deny")
		return
	}

%s
	// Default fallback
	fmt.Print("deny")
}
`, rulesCode.String())

	tmpDir, err := os.MkdirTemp("", "policy_build")
	if err != nil {
		log.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	srcPath := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(srcPath, []byte(goSource), 0644); err != nil {
		log.Fatalf("Failed to write source: %v", err)
	}

	// Initialize a dummy go.mod in the temp directory to compile outside a workspace
	initCmd := exec.Command("go", "mod", "init", "policy")
	initCmd.Dir = tmpDir
	initCmd.Env = append(os.Environ(), "GOWORK=off")
	if err := initCmd.Run(); err != nil {
		log.Fatalf("Failed to initialize temporary go module: %v", err)
	}

	cmd := exec.Command("go", "build", "-o", outputWasm, ".")
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "GOWORK=off")

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to compile policy to WASM: %v\nStderr: %s", err, stderr.String())
	}

	fmt.Printf("✓ Successfully compiled policy to %s\n", outputWasm)
}

type adminRateLimiter struct {
	mu      sync.Mutex
	history map[string][]time.Time
}

func (al *adminRateLimiter) Limit(ip string, limit int) bool {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.history == nil {
		al.history = make(map[string][]time.Time)
	}

	now := time.Now()
	cutoff := now.Add(-1 * time.Minute)

	history := al.history[ip]
	valid := history[:0]
	for _, t := range history {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= limit {
		al.history[ip] = valid
		return true // rate limited
	}

	valid = append(valid, now)
	al.history[ip] = valid
	return false
}

func withAdminRateLimit(limit int, next http.HandlerFunc) http.HandlerFunc {
	limiter := &adminRateLimiter{}
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}
		if limiter.Limit(clientIP, limit) {
			proxy.WriteJSONError(w, r, "Too Many Requests", "ERR_RATE_LIMIT_EXCEEDED", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}
