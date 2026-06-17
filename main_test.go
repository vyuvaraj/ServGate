package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"servgate/pkg/proxy"
	"servgate/pkg/wasm"
)

func TestServGateReverseProxy(t *testing.T) {
	// 1. Start a mock backend target server
	backendReceivedPath := ""
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendReceivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend-response"))
	})
	backendServer := &http.Server{
		Addr:    "127.0.0.1:8091",
		Handler: backendHandler,
	}
	go backendServer.ListenAndServe()

	// 2. Setup gateway handler
	routes := []proxy.Route{
		{
			Prefix: "/api/v1/orders",
			Target: "http://127.0.0.1:8091",
		},
	}

	wasmManager, err := wasm.GetMiddlewareManager(context.Background())
	if err != nil {
		t.Fatalf("WASM setup failed: %v", err)
	}

	gatewayHandler := proxy.NewGatewayHandler(routes, wasmManager, "")
	gatewayServer := &http.Server{
		Addr:    "127.0.0.1:8092",
		Handler: gatewayHandler,
	}
	go gatewayServer.ListenAndServe()

	time.Sleep(200 * time.Millisecond)

	// 3. Issue proxy request
	resp, err := http.Get("http://127.0.0.1:8092/api/v1/orders/create")
	if err != nil {
		t.Fatalf("Failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend-response" {
		t.Errorf("Expected body 'backend-response', got %q", string(body))
	}

	if backendReceivedPath != "/create" {
		t.Errorf("Expected backend path prefix strip logic to target '/create', got %q", backendReceivedPath)
	}

	// Clean servers
	_ = backendServer.Shutdown(context.Background())
	_ = gatewayServer.Shutdown(context.Background())
}

func TestWasmMiddlewareInjection(t *testing.T) {
	// 1. Setup wazero manager
	wasmManager, err := wasm.GetMiddlewareManager(context.Background())
	if err != nil {
		t.Fatalf("WASM setup failed: %v", err)
	}

	// Register empty/no-op transform for test
	err = wasmManager.Register(context.Background(), "noop", []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // Magic wasm version
	})
	if err != nil {
		t.Fatalf("Failed to compile WASM: %v", err)
	}

	res, err := wasmManager.Run(context.Background(), "noop", []byte("raw-bytes"))
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// No-op module should compile and return empty bytes safely without error
	if len(res) > 0 {
		t.Errorf("Expected empty bytes response, got %v", res)
	}
}

func TestRateLimiting(t *testing.T) {
	// 1. Start a mock backend target server
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend-response"))
	})
	backendServer := &http.Server{
		Addr:    "127.0.0.1:8093",
		Handler: backendHandler,
	}
	go backendServer.ListenAndServe()
	defer backendServer.Shutdown(context.Background())

	// 2. Setup gateway handler with rate limit of 2 requests per minute
	routes := []proxy.Route{
		{
			Prefix:       "/api/v1/limited",
			Target:       "http://127.0.0.1:8093",
			RateLimitRPM: 2,
		},
	}

	wasmManager, err := wasm.GetMiddlewareManager(context.Background())
	if err != nil {
		t.Fatalf("WASM setup failed: %v", err)
	}

	gatewayHandler := proxy.NewGatewayHandler(routes, wasmManager, "")
	gatewayServer := &http.Server{
		Addr:    "127.0.0.1:8094",
		Handler: gatewayHandler,
	}
	go gatewayServer.ListenAndServe()
	defer gatewayServer.Shutdown(context.Background())

	time.Sleep(200 * time.Millisecond)

	// Issue 2 requests, which should succeed
	for i := 0; i < 2; i++ {
		resp, err := http.Get("http://127.0.0.1:8094/api/v1/limited/test")
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Request %d: expected status 200, got %d", i, resp.StatusCode)
		}
	}

	// The 3rd request should be rate limited (429)
	resp, err := http.Get("http://127.0.0.1:8094/api/v1/limited/test")
	if err != nil {
		t.Fatalf("3rd request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected 3rd request to be rate limited with 429, got %d", resp.StatusCode)
	}
}

func buildWASM(t *testing.T, src string) []byte {
	t.Helper()

	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "main.go")
	wasmPath := filepath.Join(tmpDir, "transform.wasm")

	if err := os.WriteFile(srcPath, []byte(src), 0644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	cmd := exec.Command("go", "build", "-o", wasmPath, srcPath)
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "unsupported GOOS") || strings.Contains(string(out), "unsupported") {
			t.Skipf("GOOS=wasip1 not supported by this Go toolchain: %s", out)
		}
		t.Fatalf("go build wasip1 failed: %v\n%s", err, out)
	}

	data, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("read wasm: %v", err)
	}
	return data
}

func TestDirectMemoryPassingAndResponseFilters(t *testing.T) {
	// 1. Static WASM bytecode with memory export, allocate() returning 0, and transform() incrementing each byte by 1
	wasmBytes := []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // Magic & Version
		// Section 1: Type
		0x01, 0x0c, 0x02,
		0x60, 0x01, 0x7f, 0x01, 0x7f,       // Type 0: (i32) -> i32
		0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7e, // Type 1: (i32, i32) -> i64
		// Section 3: Function
		0x03, 0x03, 0x02, 0x00, 0x01,
		// Section 5: Memory
		0x05, 0x03, 0x01, 0x00, 0x01,
		// Section 7: Export
		0x07, 0x21, 0x03,
		0x06, 'm', 'e', 'm', 'o', 'r', 'y', 0x02, 0x00,
		0x08, 'a', 'l', 'l', 'o', 'c', 'a', 't', 'e', 0x00, 0x00,
		0x09, 't', 'r', 'a', 'n', 's', 'f', 'o', 'r', 'm', 0x00, 0x01,
		// Section 10: Code
		0x0a, 0x35, 0x02,
		// Body 0 (allocate)
		0x04, 0x00, 0x41, 0x00, 0x0b,
		// Body 1 (transform)
		46,
		0x01, 0x01, 0x7f,             // 1 local (i32)
		0x41, 0x00, 0x21, 0x02,       // i = 0
		0x02, 0x40,                   // block
		0x03, 0x40,                   // loop
		0x20, 0x02, 0x20, 0x01, 0x46, // i == size
		0x0d, 0x01,                   // br_if 1
		0x20, 0x02, 0x20, 0x02,       // address, address
		0x2d, 0x00, 0x00,             // i32.load8_u
		0x41, 0x01, 0x6a,             // + 1
		0x3a, 0x00, 0x00,             // i32.store8
		0x20, 0x02, 0x41, 0x01, 0x6a, 0x21, 0x02, // i++
		0x0c, 0x00,                   // br 0
		0x0b, 0x0b,                   // end loop, end block
		0x20, 0x01, 0xac, 0x0b,       // return size (as i64), end func
	}

	// 2. Set up WASM manager and register the compiled module
	wasmManager, err := wasm.GetMiddlewareManager(context.Background())
	if err != nil {
		t.Fatalf("WASM setup failed: %v", err)
	}
	
	err = wasmManager.Register(context.Background(), "direct-mem-inc", wasmBytes)
	if err != nil {
		t.Fatalf("Failed to register direct-mem-inc: %v", err)
	}

	// 3. Start a mock backend target server
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqBody, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend:" + string(reqBody)))
	})
	backendServer := &http.Server{
		Addr:    "127.0.0.1:8095",
		Handler: backendHandler,
	}
	go backendServer.ListenAndServe()
	defer backendServer.Shutdown(context.Background())

	// 4. Setup gateway handler with both request and response WASM middlewares
	routes := []proxy.Route{
		{
			Prefix:             "/api/v1/direct",
			Target:             "http://127.0.0.1:8095",
			Middleware:         "direct-mem-inc",
			ResponseMiddleware: "direct-mem-inc",
		},
	}

	gatewayHandler := proxy.NewGatewayHandler(routes, wasmManager, "")
	gatewayServer := &http.Server{
		Addr:    "127.0.0.1:8096",
		Handler: gatewayHandler,
	}
	go gatewayServer.ListenAndServe()
	defer gatewayServer.Shutdown(context.Background())

	time.Sleep(200 * time.Millisecond)

	// 5. Issue proxy request
	reqBody := []byte("hello-wasm")
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8096/api/v1/direct/test", bytes.NewReader(reqBody))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	expected := "cbdlfoe;jgnnq/ycuo"
	if string(body) != expected {
		t.Errorf("Expected body %q, got %q", expected, string(body))
	}
}

func TestInstallCommand(t *testing.T) {
	mockWasmContent := []byte("wasm-binary-content")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/middlewares/auth-token.wasm" {
			w.WriteHeader(http.StatusOK)
			w.Write(mockWasmContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"servgate", "install", "auth-token"}

	os.Setenv("SERV_REGISTRY", ts.URL)
	defer os.Unsetenv("SERV_REGISTRY")

	destPath := filepath.Join("middlewares", "auth-token.wasm")
	os.Remove(destPath)
	defer os.Remove(destPath)

	runInstallCommand()

	data, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("Failed to read installed middleware: %v", err)
	}

	if string(data) != "wasm-binary-content" {
		t.Errorf("Expected content 'wasm-binary-content', got %q", string(data))
	}
}
