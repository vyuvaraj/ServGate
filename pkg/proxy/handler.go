package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"servgate/pkg/otel"
	"servgate/pkg/wasm"
)

type Route struct {
	Prefix             string   `json:"prefix"`
	Target             string   `json:"target"`
	Targets            []string `json:"targets,omitempty"`             // Multiple backend targets
	LoadBalancer       string   `json:"load_balancer,omitempty"`       // "round_robin" or "least_conn"
	TranspileType      string   `json:"transpile_type,omitempty"`      // "rest_to_grpc" or "grpc_to_rest"
	Middleware         string   `json:"middleware,omitempty"`          // Request Middleware
	ResponseMiddleware string   `json:"response_middleware,omitempty"` // Response Middleware
	RateLimitRPM       int      `json:"rate_limit_rpm,omitempty"`      // Requests Per Minute Limit
	PromptGuard        bool     `json:"prompt_guard,omitempty"`        // AI Prompt Guard
	PiiRedact          bool     `json:"pii_redact,omitempty"`          // AI PII Redaction
	SemanticCache      bool     `json:"semantic_cache,omitempty"`      // AI Semantic Cache
}

type rateLimiter struct {
	mu      sync.Mutex
	history []time.Time
}

type GatewayHandler struct {
	routes         []Route
	routesMu       sync.RWMutex
	wasm           *wasm.MiddlewareManager
	authToken      string
	rateLimiters   map[string]*rateLimiter   // key: clientIP + routePrefix
	limiterMu      sync.Mutex
	rrIndices      map[string]int            // route prefix -> current index
	activeConns    map[string]int            // target URL -> active conn count
	balancerMu     sync.Mutex
	semanticCaches map[string]*SemanticCache // route prefix -> cache
}

func NewGatewayHandler(routes []Route, wasm *wasm.MiddlewareManager, authToken string) *GatewayHandler {
	semanticCaches := make(map[string]*SemanticCache)
	for _, route := range routes {
		if route.SemanticCache {
			semanticCaches[route.Prefix] = NewSemanticCache(0.85)
		}
	}
	return &GatewayHandler{
		routes:         routes,
		wasm:           wasm,
		authToken:      authToken,
		rateLimiters:   make(map[string]*rateLimiter),
		rrIndices:      make(map[string]int),
		activeConns:    make(map[string]int),
		semanticCaches: semanticCaches,
	}
}

func (h *GatewayHandler) UpdateRoutes(newRoutes []Route) {
	h.routesMu.Lock()
	defer h.routesMu.Unlock()
	h.routes = newRoutes

	h.balancerMu.Lock()
	defer h.balancerMu.Unlock()
	for _, route := range newRoutes {
		if route.SemanticCache {
			if _, exists := h.semanticCaches[route.Prefix]; !exists {
				h.semanticCaches[route.Prefix] = NewSemanticCache(0.85)
			}
		}
	}
}

// RetryingTransport implements http.RoundTripper executing retries on network drops
type RetryingTransport struct {
	base http.RoundTripper
}

func (rt *RetryingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	// Read body to allow re-sending on retries
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}

	maxRetries := 3
	backoff := 50 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		if len(bodyBytes) > 0 {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		resp, err = rt.base.RoundTrip(req)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}

		// Backoff before retrying
		time.Sleep(backoff)
		backoff *= 2
	}

	return resp, err
}

func (h *GatewayHandler) isRateLimited(clientIP, routePrefix string, limit int) bool {
	if limit <= 0 {
		return false
	}

	key := clientIP + ":" + routePrefix
	h.limiterMu.Lock()
	lim, exists := h.rateLimiters[key]
	if !exists {
		lim = &rateLimiter{}
		h.rateLimiters[key] = lim
	}
	h.limiterMu.Unlock()

	lim.mu.Lock()
	defer lim.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-1 * time.Minute)

	// Filter out requests older than 1 minute
	valid := lim.history[:0]
	for _, t := range lim.history {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	lim.history = valid

	if len(lim.history) >= limit {
		return true // rate limited
	}

	lim.history = append(lim.history, now)
	return false
}

func (h *GatewayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Authentication
	if h.authToken != "" {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		
		authenticated := false
		if token == h.authToken {
			authenticated = true
		} else if jwtSec := os.Getenv("SERV_JWT_SECRET"); jwtSec != "" {
			if _, ok := validateJWT(token, []byte(jwtSec)); ok {
				authenticated = true
			}
		}

		if !authenticated {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Route Matching
	var matchedRoute Route
	found := false
	h.routesMu.RLock()
	for _, route := range h.routes {
		if strings.HasPrefix(r.URL.Path, route.Prefix) {
			matchedRoute = route
			found = true
			break
		}
	}
	h.routesMu.RUnlock()

	if !found {
		http.Error(w, "Bad gateway: route match not found", http.StatusBadGateway)
		return
	}

	// Rate Limiting Check
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if h.isRateLimited(clientIP, matchedRoute.Prefix, matchedRoute.RateLimitRPM) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// Distributed Tracing: Extract or start trace context span
	traceparent := r.Header.Get("traceparent")
	span := otel.StartSpan(fmt.Sprintf("%s %s", r.Method, r.URL.Path), traceparent)
	
	// Inject trace context headers
	if span != nil {
		traceparent = fmt.Sprintf("00-%s-%s-01", span.TraceID, span.SpanID)
		r.Header.Set("traceparent", traceparent)
	}

	// Read request body to apply AI checks
	var reqBody []byte
	if matchedRoute.PromptGuard || matchedRoute.PiiRedact || matchedRoute.SemanticCache {
		reqBody, _ = io.ReadAll(r.Body)
		r.Body.Close()

		prompt := extractPrompt(reqBody)

		// 1. AI Prompt Guard
		if matchedRoute.PromptGuard && prompt != "" {
			if IsPromptInjection(prompt) {
				otel.EndSpan(span, fmt.Errorf("AI Prompt Guard: Injection attempt blocked"), map[string]interface{}{})
				http.Error(w, "AI Prompt Guard: Validation failed due to safety policy violation", http.StatusBadRequest)
				return
			}
		}

		// 2. AI PII Redactor
		if matchedRoute.PiiRedact {
			redactedText := RedactPii(string(reqBody))
			reqBody = []byte(redactedText)
			prompt = extractPrompt(reqBody) // re-extract redacted prompt
		}

		// 3. AI Semantic Cache (Lookup)
		if matchedRoute.SemanticCache && prompt != "" {
			if cache, ok := h.semanticCaches[matchedRoute.Prefix]; ok {
				if cachedResp, hit := cache.Get(prompt); hit {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("X-Cache", "HIT-SEMANTIC")
					w.WriteHeader(http.StatusOK)
					w.Write(cachedResp)
					otel.EndSpan(span, nil, map[string]interface{}{
						"http.route": matchedRoute.Prefix,
						"cache.hit":  true,
					})
					return
				}
			}
		}

		// Restore request body for subsequent handlers
		r.Body = io.NopCloser(bytes.NewReader(reqBody))
		r.ContentLength = int64(len(reqBody))
	}

	// WASM Request Middleware execution if registered
	if matchedRoute.Middleware != "" {
		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body.Close()

		wasmSpan := otel.StartSpan(fmt.Sprintf("WASM Middleware %s", matchedRoute.Middleware), traceparent)
		outputBytes, err := h.wasm.Run(r.Context(), matchedRoute.Middleware, bodyBytes)
		otel.EndSpan(wasmSpan, err, map[string]interface{}{})

		if err != nil {
			otel.EndSpan(span, err, map[string]interface{}{})
			http.Error(w, "Internal Server Error: WASM Middleware execution failed", http.StatusInternalServerError)
			return
		}

		r.Body = io.NopCloser(bytes.NewReader(outputBytes))
		r.ContentLength = int64(len(outputBytes))
	}

	// Load Balancing Target Selection
	selectedTarget := h.selectTarget(&matchedRoute)
	h.incConn(selectedTarget)
	defer h.decConn(selectedTarget)

	targetURL, err := url.Parse(selectedTarget)
	if err != nil {
		otel.EndSpan(span, err, map[string]interface{}{})
		http.Error(w, "Bad Gateway Target", http.StatusBadGateway)
		return
	}

	// WebSocket Proxying check
	if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
		r.URL.Path = "/" + strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, matchedRoute.Prefix), "/")
		h.proxyWebSocket(w, r, targetURL)
		otel.EndSpan(span, nil, map[string]interface{}{
			"http.route":   matchedRoute.Prefix,
			"proxy.target": selectedTarget,
			"protocol":     "websocket",
		})
		return
	}

	// gRPC-to-REST Transpiling (Direction B - incoming request unpacking)
	if matchedRoute.TranspileType == "grpc_to_rest" {
		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if len(bodyBytes) >= 5 {
			payloadLen := binary.BigEndian.Uint32(bodyBytes[1:5])
			if len(bodyBytes) >= int(5+payloadLen) {
				jsonBody := bodyBytes[5 : 5+payloadLen]
				r.Body = io.NopCloser(bytes.NewReader(jsonBody))
				r.ContentLength = int64(len(jsonBody))
				r.Header.Set("Content-Type", "application/json")
				r.Method = http.MethodPost
			}
		}
	}

	// REST-to-gRPC Transpiling (Direction A - incoming request packing)
	if matchedRoute.TranspileType == "rest_to_grpc" {
		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body.Close()
		header := make([]byte, 5)
		header[0] = 0 // Compression flag = 0
		binary.BigEndian.PutUint32(header[1:], uint32(len(bodyBytes)))
		grpcBody := append(header, bodyBytes...)
		r.Body = io.NopCloser(bytes.NewReader(grpcBody))
		r.ContentLength = int64(len(grpcBody))
		r.Header.Set("Content-Type", "application/grpc+json")
		r.Header.Set("TE", "trailers")
		r.Method = http.MethodPost
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = &RetryingTransport{base: http.DefaultTransport}

	proxy.ModifyResponse = func(resp *http.Response) error {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		resp.Body.Close()

		// Run WASM Response Middleware if registered
		if matchedRoute.ResponseMiddleware != "" {
			wasmSpan := otel.StartSpan(fmt.Sprintf("WASM Response Middleware %s", matchedRoute.ResponseMiddleware), traceparent)
			var wasmErr error
			bodyBytes, wasmErr = h.wasm.Run(resp.Request.Context(), matchedRoute.ResponseMiddleware, bodyBytes)
			otel.EndSpan(wasmSpan, wasmErr, map[string]interface{}{})
			if wasmErr != nil {
				return fmt.Errorf("response middleware execution failed: %w", wasmErr)
			}
		}

		// REST-to-gRPC Response Transpiling (Direction A - unpacking response)
		if matchedRoute.TranspileType == "rest_to_grpc" {
			if len(bodyBytes) >= 5 {
				payloadLen := binary.BigEndian.Uint32(bodyBytes[1:5])
				if len(bodyBytes) >= int(5+payloadLen) {
					bodyBytes = bodyBytes[5 : 5+payloadLen]
					resp.Header.Set("Content-Type", "application/json")
				}
			}
		}

		// gRPC-to-REST Response Transpiling (Direction B - packing response)
		if matchedRoute.TranspileType == "grpc_to_rest" {
			header := make([]byte, 5)
			header[0] = 0 // Compression flag = 0
			binary.BigEndian.PutUint32(header[1:], uint32(len(bodyBytes)))
			bodyBytes = append(header, bodyBytes...)
			resp.Header.Set("Content-Type", "application/grpc+json")
		}

		// Cache response semantically
		if matchedRoute.SemanticCache {
			prompt := extractPrompt(reqBody)
			if prompt != "" {
				if cache, ok := h.semanticCaches[matchedRoute.Prefix]; ok {
					cache.Set(prompt, bodyBytes)
				}
			}
		}

		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		resp.ContentLength = int64(len(bodyBytes))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))
		return nil
	}

	r.URL.Host = targetURL.Host
	r.URL.Scheme = targetURL.Scheme
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	r.Host = targetURL.Host

	// Custom Director rewrite to strip routing prefix
	r.URL.Path = "/" + strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, matchedRoute.Prefix), "/")

	proxy.ServeHTTP(w, r)
	otel.EndSpan(span, nil, map[string]interface{}{
		"http.route":   matchedRoute.Prefix,
		"proxy.target": selectedTarget,
	})
}

func (h *GatewayHandler) selectTarget(route *Route) string {
	if len(route.Targets) == 0 {
		return route.Target
	}

	h.balancerMu.Lock()
	defer h.balancerMu.Unlock()

	if route.LoadBalancer == "least_conn" {
		minVal := -1
		var selected string
		for _, target := range route.Targets {
			conns := h.activeConns[target]
			if minVal == -1 || conns < minVal {
				minVal = conns
				selected = target
			}
		}
		return selected
	}

	// Default: Round Robin
	idx := h.rrIndices[route.Prefix]
	selected := route.Targets[idx%len(route.Targets)]
	h.rrIndices[route.Prefix] = (idx + 1) % len(route.Targets)
	return selected
}

func (h *GatewayHandler) incConn(target string) {
	h.balancerMu.Lock()
	h.activeConns[target]++
	h.balancerMu.Unlock()
}

func (h *GatewayHandler) decConn(target string) {
	h.balancerMu.Lock()
	h.activeConns[target]--
	if h.activeConns[target] < 0 {
		h.activeConns[target] = 0
	}
	h.balancerMu.Unlock()
}

func (h *GatewayHandler) proxyWebSocket(w http.ResponseWriter, r *http.Request, targetURL *url.URL) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Websocket hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	backendAddr := targetURL.Host
	if !strings.Contains(backendAddr, ":") {
		if targetURL.Scheme == "https" || targetURL.Scheme == "wss" {
			backendAddr += ":443"
		} else {
			backendAddr += ":80"
		}
	}

	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		fmt.Printf("proxyWebSocket: net.Dial failed to %s: %v\n", backendAddr, err)
		return
	}
	defer backendConn.Close()

	// Forward client request line and headers
	reqLine := fmt.Sprintf("%s %s %s\r\n", r.Method, r.URL.RequestURI(), r.Proto)
	backendConn.Write([]byte(reqLine))
	r.Header.Set("Host", targetURL.Host)
	r.Header.Write(backendConn)
	backendConn.Write([]byte("\r\n"))

	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(backendConn, clientConn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, backendConn)
		errChan <- err
	}()
	<-errChan
}

func validateJWT(tokenStr string, secret []byte) (string, bool) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return "", false
	}

	headerPart, payloadPart, signaturePart := parts[0], parts[1], parts[2]
	
	// Validate signature
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(headerPart + "." + payloadPart))
	expectedMac := mac.Sum(nil)
	
	// Base64Url decode signaturePart
	sigBytes, err := base64UrlDecode(signaturePart)
	if err != nil || !hmac.Equal(sigBytes, expectedMac) {
		return "", false
	}

	// Base64Url decode payloadPart and extract username, exp
	payloadBytes, err := base64UrlDecode(payloadPart)
	if err != nil {
		return "", false
	}

	var claims struct {
		Username string `json:"username"`
		Exp      int64  `json:"exp"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", false
	}

	// Check expiration
	if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
		return "", false
	}

	return claims.Username, true
}

func base64UrlDecode(s string) ([]byte, error) {
	if l := len(s) % 4; l > 0 {
		s += strings.Repeat("=", 4-l)
	}
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	return base64.URLEncoding.DecodeString(s)
}
