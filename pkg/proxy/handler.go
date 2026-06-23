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
	Prefix             string            `json:"prefix"`
	Target             string            `json:"target"`
	Targets            []string          `json:"targets,omitempty"`             // Multiple backend targets
	LoadBalancer       string            `json:"load_balancer,omitempty"`       // "round_robin" or "least_conn"
	TranspileType      string            `json:"transpile_type,omitempty"`      // "rest_to_grpc" or "grpc_to_rest"
	Middleware         string            `json:"middleware,omitempty"`          // Request Middleware
	ResponseMiddleware string            `json:"response_middleware,omitempty"` // Response Middleware
	RateLimitRPM       int               `json:"rate_limit_rpm,omitempty"`      // Requests Per Minute Limit
	PromptGuard        bool              `json:"prompt_guard,omitempty"`        // AI Prompt Guard
	PiiRedact          bool              `json:"pii_redact,omitempty"`          // AI PII Redaction
	SemanticCache      bool              `json:"semantic_cache,omitempty"`      // AI Semantic Cache
	ValidationSchema   map[string]string `json:"validation_schema,omitempty"`   // Edge request validation rules
	IPAllowlist        []string          `json:"ip_allowlist,omitempty"`        // Allowed IP or CIDR list
	IPBlocklist        []string          `json:"ip_blocklist,omitempty"`        // Blocked IP or CIDR list
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

func (h *GatewayHandler) GetRoutes() []Route {
	h.routesMu.RLock()
	defer h.routesMu.RUnlock()
	return h.routes
}

func (h *GatewayHandler) GetActiveConnections() map[string]int {
	h.balancerMu.Lock()
	defer h.balancerMu.Unlock()

	res := make(map[string]int)
	for k, v := range h.activeConns {
		res[k] = v
	}
	return res
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
	if r.URL.Path == "/api/docs" {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(docsHTML))
		return
	}
	if r.URL.Path == "/api/docs/openapi.json" {
		h.serveOpenAPIDocs(w, r)
		return
	}

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
			WriteJSONError(w, r, "Unauthorized", "ERR_UNAUTHORIZED", http.StatusUnauthorized)
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
		WriteJSONError(w, r, "Bad gateway: route match not found", "ERR_ROUTE_NOT_FOUND", http.StatusBadGateway)
		return
	}

	// IP Allowlisting & Blocklisting Check
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		clientIP = r.RemoteAddr
		if strings.HasPrefix(clientIP, "[") && strings.HasSuffix(clientIP, "]") {
			clientIP = clientIP[1 : len(clientIP)-1]
		}
	}
	if !checkIPAccess(clientIP, matchedRoute.IPAllowlist, matchedRoute.IPBlocklist) {
		WriteJSONError(w, r, "Forbidden: IP access denied", "ERR_IP_ACCESS_DENIED", http.StatusForbidden)
		return
	}

	// Rate Limiting Check
	if h.isRateLimited(clientIP, matchedRoute.Prefix, matchedRoute.RateLimitRPM) {
		WriteJSONError(w, r, "Too Many Requests", "ERR_RATE_LIMIT_EXCEEDED", http.StatusTooManyRequests)
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

	// Edge Request Validation (JSON Schema)
	if len(matchedRoute.ValidationSchema) > 0 {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			otel.EndSpan(span, err, map[string]interface{}{})
			WriteJSONError(w, r, "Bad request: failed to read body", "ERR_VALIDATION_FAILED", http.StatusBadRequest)
			return
		}
		r.Body.Close()

		if err := ValidateRequest(bodyBytes, matchedRoute.ValidationSchema); err != nil {
			otel.EndSpan(span, err, map[string]interface{}{})
			WriteJSONError(w, r, err.Error(), "ERR_VALIDATION_FAILED", http.StatusBadRequest)
			return
		}

		// Restore request body for subsequent handlers
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))
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
				WriteJSONError(w, r, "AI Prompt Guard: Validation failed due to safety policy violation", "ERR_PROMPT_INJECTION_DETECTED", http.StatusBadRequest)
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
		var inputBytes []byte
		isPolicy := strings.Contains(strings.ToLower(matchedRoute.Middleware), "policy")

		if isPolicy {
			// Construct metadata JSON
			hdrs := make(map[string]string)
			for k, v := range r.Header {
				if len(v) > 0 {
					hdrs[strings.ToLower(k)] = v[0]
				}
			}
			meta := map[string]interface{}{
				"method":  r.Method,
				"path":    r.URL.Path,
				"headers": hdrs,
			}
			inputBytes, _ = json.Marshal(meta)
		} else {
			bodyBytes, _ := io.ReadAll(r.Body)
			r.Body.Close()
			inputBytes = bodyBytes
		}

		wasmSpan := otel.StartSpan(fmt.Sprintf("WASM Middleware %s", matchedRoute.Middleware), traceparent)
		outputBytes, err := h.wasm.Run(r.Context(), matchedRoute.Middleware, inputBytes)
		otel.EndSpan(wasmSpan, err, map[string]interface{}{})

		if err != nil {
			otel.EndSpan(span, err, map[string]interface{}{})
			WriteJSONError(w, r, "Internal Server Error: WASM Middleware execution failed", "ERR_WASM_MIDDLEWARE_FAILED", http.StatusInternalServerError)
			return
		}

		if isPolicy {
			decision := strings.TrimSpace(string(outputBytes))
			if decision == "deny" {
				otel.EndSpan(span, fmt.Errorf("Forbidden: Access Denied by Policy"), map[string]interface{}{})
				WriteJSONError(w, r, "Forbidden: Access Denied by Policy", "ERR_ACCESS_DENIED", http.StatusForbidden)
				return
			}
			// If allowed, proceed with original request body (untouched)
		} else {
			r.Body = io.NopCloser(bytes.NewReader(outputBytes))
			r.ContentLength = int64(len(outputBytes))
		}
	}

	// Load Balancing Target Selection
	selectedTarget := h.selectTarget(&matchedRoute)
	h.incConn(selectedTarget)
	defer h.decConn(selectedTarget)

	// Webhook bridge check
	if strings.HasPrefix(selectedTarget, "servqueue://") {
		topic := strings.TrimPrefix(selectedTarget, "servqueue://")
		// Read body
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			otel.EndSpan(span, err, map[string]interface{}{})
			WriteJSONError(w, r, "Bad Request: failed to read body", "ERR_BAD_REQUEST_BODY", http.StatusBadRequest)
			return
		}
		r.Body.Close()

		// Resolve queueUrl
		queueUrl := "http://localhost:8082"
		if rawDisc := os.Getenv("SERVVERSE_DISCOVERY"); rawDisc != "" {
			var manifest struct {
				Queue string `json:"queue"`
			}
			if json.Unmarshal([]byte(rawDisc), &manifest) == nil && manifest.Queue != "" {
				queueUrl = manifest.Queue
			}
		}

		// Send request to ServQueue API
		publishUrl := fmt.Sprintf("%s/api/publish", strings.TrimSuffix(queueUrl, "/"))
		payloadMap := map[string]string{
			"topic":   topic,
			"payload": string(bodyBytes),
		}
		jsonPayload, _ := json.Marshal(payloadMap)

		req, err := http.NewRequestWithContext(r.Context(), "POST", publishUrl, bytes.NewReader(jsonPayload))
		if err != nil {
			otel.EndSpan(span, err, map[string]interface{}{})
			WriteJSONError(w, r, "Internal Server Error", "ERR_INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer secret-token") // default authorization

		// Propagate traceparent if active
		if traceparent != "" {
			req.Header.Set("traceparent", traceparent)
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			otel.EndSpan(span, err, map[string]interface{}{})
			WriteJSONError(w, r, "Service Unavailable: failed to bridge to queue", "ERR_QUEUE_BRIDGE_FAILED", http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 400 {
			otel.EndSpan(span, fmt.Errorf("queue publish returned %d", resp.StatusCode), map[string]interface{}{})
			WriteJSONError(w, r, fmt.Sprintf("Queue Error: %s", string(respBody)), "ERR_QUEUE_RESPONSE_ERROR", resp.StatusCode)
			return
		}

		// Return success to the HTTP caller
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success","message":"Event bridged to topic: ` + topic + `"}`))

		otel.EndSpan(span, nil, map[string]interface{}{
			"http.route":   matchedRoute.Prefix,
			"proxy.target": selectedTarget,
			"bridge.topic": topic,
		})
		return
	}

	targetURL, err := url.Parse(selectedTarget)
	if err != nil {
		otel.EndSpan(span, err, map[string]interface{}{})
		WriteJSONError(w, r, "Bad Gateway Target", "ERR_BAD_GATEWAY_TARGET", http.StatusBadGateway)
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
		WriteJSONError(w, r, "Websocket hijacking not supported", "ERR_WS_HIJACK_NOT_SUPPORTED", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		WriteJSONError(w, r, "Failed to hijack connection: "+err.Error(), "ERR_WS_HIJACK_FAILED", http.StatusInternalServerError)
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

func (h *GatewayHandler) serveOpenAPIDocs(w http.ResponseWriter, r *http.Request) {
	h.routesMu.RLock()
	routes := h.routes
	h.routesMu.RUnlock()

	openapi := map[string]interface{}{
		"openapi": "3.1.0",
		"info": map[string]interface{}{
			"title":       "ServGate API Gateway Discovery",
			"version":     "1.0.0",
			"description": "Auto-discovered gateway proxy routes",
		},
		"paths": make(map[string]interface{}),
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{
				"BearerAuth": map[string]interface{}{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
				},
			},
		},
		"security": []interface{}{
			map[string]interface{}{
				"BearerAuth": []interface{}{},
			},
		},
	}

	paths := openapi["paths"].(map[string]interface{})

	for _, route := range routes {
		pathKey := route.Prefix
		if !strings.HasSuffix(pathKey, "/") {
			pathKey += "/"
		}
		pathKey += "{path}"

		pathItem := map[string]interface{}{
			"parameters": []interface{}{
				map[string]interface{}{
					"name":        "path",
					"in":          "path",
					"required":    true,
					"description": "Sub-route path parameter",
					"schema": map[string]interface{}{
						"type": "string",
					},
				},
			},
		}

		methods := []string{"get", "post", "put", "delete", "patch"}
		for _, m := range methods {
			op := map[string]interface{}{
				"summary":     fmt.Sprintf("Proxy to %s", route.Target),
				"description": fmt.Sprintf("Proxies requests starting with %s to target: %s", route.Prefix, route.Target),
				"responses": map[string]interface{}{
					"200": map[string]interface{}{
						"description": "Successful proxy response",
					},
				},
			}

			if (m == "post" || m == "put") && len(route.ValidationSchema) > 0 {
				properties := make(map[string]interface{})
				var required []string
				for fieldName, fieldType := range route.ValidationSchema {
					pType := "string"
					req := false
					parts := strings.Split(fieldType, ",")
					for _, part := range parts {
						p := strings.TrimSpace(part)
						if p == "required" {
							req = true
						} else if p == "int" || p == "integer" {
							pType = "integer"
						} else if p == "float" || p == "number" {
							pType = "number"
						} else if p == "bool" || p == "boolean" {
							pType = "boolean"
						} else if p == "string" {
							pType = "string"
						}
					}
					properties[fieldName] = map[string]interface{}{
						"type": pType,
					}
					if req {
						required = append(required, fieldName)
					}
				}

				reqBodySchema := map[string]interface{}{
					"type":       "object",
					"properties": properties,
				}
				if len(required) > 0 {
					reqBodySchema["required"] = required
				}

				op["requestBody"] = map[string]interface{}{
					"required": true,
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": reqBodySchema,
						},
					},
				}
			}

			pathItem[m] = op
		}

		paths[pathKey] = pathItem
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(openapi)
}

func checkIPAccess(clientIP string, allowlist, blocklist []string) bool {
	parsedIP := net.ParseIP(clientIP)
	if parsedIP == nil {
		return true
	}

	ipMatches := func(ip net.IP, pattern string) bool {
		if strings.Contains(pattern, "/") {
			_, subnet, err := net.ParseCIDR(pattern)
			if err == nil {
				return subnet.Contains(ip)
			}
		}
		patternIP := net.ParseIP(pattern)
		if patternIP != nil {
			return patternIP.Equal(ip)
		}
		return false
	}

	// Check Blocklist first
	for _, pattern := range blocklist {
		if ipMatches(parsedIP, pattern) {
			return false
		}
	}

	// Check Allowlist second (if populated)
	if len(allowlist) > 0 {
		allowed := false
		for _, pattern := range allowlist {
			if ipMatches(parsedIP, pattern) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	return true
}

const docsHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ServGate API Portal</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css" />
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@100..900&display=swap" rel="stylesheet">
  <style>
    body {
      margin: 0;
      background: #0f172a;
      color: #f8fafc;
      font-family: 'Outfit', sans-serif;
    }
    .swagger-ui {
      filter: invert(88%) hue-rotate(180deg);
    }
    .swagger-ui .topbar {
      display: none;
    }
    .header-panel {
      background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 100%);
      padding: 24px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .header-panel h1 {
      margin: 0;
      font-size: 24px;
      font-weight: 700;
      color: #fff;
    }
    .badge {
      background: #4f46e5;
      color: #fff;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 12px;
      margin-left: 8px;
    }
  </style>
</head>
<body>
  <div class="header-panel">
    <div>
      <h1>⚡ ServGate <span style="color: #818cf8;">Developer Portal</span><span class="badge">Docs</span></h1>
    </div>
  </div>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: '/api/docs/openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.swaggerPlugins.DownloadUrl
        ],
        layout: "BaseLayout"
      });
    };
  </script>
</body>
</html>
`
