package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"servgate/pkg/proxy"
)

// Helper to generate self-signed certs and write them to temp files
func generateTestCerts(t *testing.T) (caFile, clientCertFile, clientKeyFile, serverCertFile, serverKeyFile string) {
	tmpDir := t.TempDir()

	// 1. Generate CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}

	caPEM := &pem.Block{Type: "CERTIFICATE", Bytes: caBytes}
	caFile = filepath.Join(tmpDir, "ca.pem")
	caOut, _ := os.Create(caFile)
	pem.Encode(caOut, caPEM)
	caOut.Close()

	// 2. Generate Server Cert
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}

	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(1 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	serverBytes, err := x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create server cert: %v", err)
	}

	serverPEM := &pem.Block{Type: "CERTIFICATE", Bytes: serverBytes}
	serverCertFile = filepath.Join(tmpDir, "server.pem")
	serverOut, _ := os.Create(serverCertFile)
	pem.Encode(serverOut, serverPEM)
	serverOut.Close()

	serverKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)}
	serverKeyFile = filepath.Join(tmpDir, "server.key")
	serverKeyOut, _ := os.Create(serverKeyFile)
	pem.Encode(serverKeyOut, serverKeyPEM)
	serverKeyOut.Close()

	// 3. Generate Client Cert
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "Test Client",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(1 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	clientBytes, err := x509.CreateCertificate(rand.Reader, &clientTemplate, &caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create client cert: %v", err)
	}

	clientPEM := &pem.Block{Type: "CERTIFICATE", Bytes: clientBytes}
	clientCertFile = filepath.Join(tmpDir, "client.pem")
	clientOut, _ := os.Create(clientCertFile)
	pem.Encode(clientOut, clientPEM)
	clientOut.Close()

	clientKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)}
	clientKeyFile = filepath.Join(tmpDir, "client.key")
	clientKeyOut, _ := os.Create(clientKeyFile)
	pem.Encode(clientKeyOut, clientKeyPEM)
	clientKeyOut.Close()

	return
}

func TestMutualTLSBackends(t *testing.T) {
	caFile, clientCertFile, clientKeyFile, serverCertFile, serverKeyFile := generateTestCerts(t)

	// Start a backend HTTPS server requiring client certificates
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatalf("failed to read CA file: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	serverCert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		t.Fatalf("failed to load server key pair: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	backendServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello Secure World!"))
	}))
	backendServer.TLS = tlsConfig
	backendServer.StartTLS()
	defer backendServer.Close()

	// Initialize Gateway Route with mTLS credentials
	routes := []proxy.Route{
		{
			Prefix:         "/secure",
			Target:         backendServer.URL,
			ClientCertPath: clientCertFile,
			ClientKeyPath:  clientKeyFile,
			RootCAPath:     caFile,
		},
	}

	handler := proxy.NewGatewayHandler(routes, nil, "")
	defer handler.Close()

	req := httptest.NewRequest("GET", "/secure/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status OK, got %d. Body: %s", resp.StatusCode, string(body))
	}

	if string(body) != "Hello Secure World!" {
		t.Fatalf("unexpected body: %s", string(body))
	}
}

func TestRequestQueuingAndBackpressure(t *testing.T) {
	// Start a slow backend server
	var wg sync.WaitGroup
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wg.Done()
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("slow success"))
	}))
	defer backendServer.Close()

	// Concurrency 2, Queue 2, Timeout 50ms
	routes := []proxy.Route{
		{
			Prefix:                 "/slow",
			Target:                 backendServer.URL,
			MaxConcurrentRequests: 2,
			MaxQueueSize:           2,
			QueueTimeoutMs:         50,
		},
	}

	handler := proxy.NewGatewayHandler(routes, nil, "")
	defer handler.Close()

	// We expect 2 concurrent requests to succeed, 2 to enter queue, and 5th to fail immediately (queue full)
	wg.Add(2)
	var testWG sync.WaitGroup

	// Start 2 concurrent requests that will occupy the slots
	for i := 0; i < 2; i++ {
		testWG.Add(1)
		go func() {
			defer testWG.Done()
			req := httptest.NewRequest("GET", "/slow/test", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Errorf("expected 200 for active slots, got %d", w.Code)
			}
		}()
	}

	// Wait for both to be actively processing in the backend
	wg.Wait()

	// Start the 5th request. It should fail immediately with 429 (Queue Full) because slots=2, queued=2
	// But wait, let's start the 2 queued requests first to fill the queue.
	var queuedWG sync.WaitGroup
	for i := 0; i < 2; i++ {
		queuedWG.Add(1)
		go func() {
			defer queuedWG.Done()
			req := httptest.NewRequest("GET", "/slow/test", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			// These will time out (50ms timeout vs 200ms processing) and return 503
			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("expected 503 for timeout queued requests, got %d", w.Code)
			}
		}()
	}

	// Give a tiny moment to ensure they enter the queue
	time.Sleep(10 * time.Millisecond)

	// Now send 5th request. It must fail with 429 (queue full)
	req5 := httptest.NewRequest("GET", "/slow/test", nil)
	w5 := httptest.NewRecorder()
	handler.ServeHTTP(w5, req5)

	if w5.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for full queue request, got %d", w5.Code)
	}

	testWG.Wait()
	queuedWG.Wait()
}

type dummyPlugin struct{}

func (d *dummyPlugin) OnRequest(r *http.Request) (*http.Response, error) {
	r.Header.Set("X-Test-Plugin-Req", "processed")
	if r.URL.Path == "/plugin/shortcircuit" {
		return &http.Response{
			StatusCode: http.StatusTeapot,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader([]byte("shortcircuited"))),
		}, nil
	}
	return nil, nil
}

func (d *dummyPlugin) OnResponse(r *http.Request, w http.ResponseWriter, resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	newBody := string(body) + "-plugin-modified"
	resp.Body = io.NopCloser(bytes.NewReader([]byte(newBody)))
	return nil
}

func TestGoPluginSDK(t *testing.T) {
	// Register dummy plugin
	proxy.RegisterPlugin("test-plugin", &dummyPlugin{})

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqHeaderVal := r.Header.Get("X-Test-Plugin-Req")
		w.Header().Set("X-Backend-Received", reqHeaderVal)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend-response"))
	}))
	defer backendServer.Close()

	routes := []proxy.Route{
		{
			Prefix:       "/plugin",
			Target:       backendServer.URL,
			GoMiddleware: "test-plugin",
		},
	}

	handler := proxy.NewGatewayHandler(routes, nil, "")
	defer handler.Close()

	// 1. Test normal path modifying request and response
	req := httptest.NewRequest("GET", "/plugin/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	if resp.Header.Get("X-Backend-Received") != "processed" {
		t.Fatalf("expected X-Backend-Received: processed, got %q", resp.Header.Get("X-Backend-Received"))
	}

	if string(body) != "backend-response-plugin-modified" {
		t.Fatalf("expected modified response body, got %q", string(body))
	}

	// 2. Test short-circuiting OnRequest path
	req2 := httptest.NewRequest("GET", "/plugin/shortcircuit", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	resp2 := w2.Result()
	body2, _ := io.ReadAll(resp2.Body)

	if resp2.StatusCode != http.StatusTeapot {
		t.Fatalf("expected 418, got %d", resp2.StatusCode)
	}

	if string(body2) != "shortcircuited" {
		t.Fatalf("expected 'shortcircuited', got %q", string(body2))
	}
}
