package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"servgate/pkg/otel"
	"servgate/pkg/wasm"
)

type Route struct {
	Prefix       string `json:"prefix"`
	Target       string `json:"target"`
	Middleware   string `json:"middleware,omitempty"`
	RateLimitRPM int    `json:"rate_limit_rpm,omitempty"` // Requests Per Minute Limit
}

type rateLimiter struct {
	mu      sync.Mutex
	history []time.Time
}

type GatewayHandler struct {
	routes       []Route
	wasm         *wasm.MiddlewareManager
	authToken    string
	rateLimiters map[string]*rateLimiter // key: clientIP + routePrefix
	limiterMu    sync.Mutex
}

func NewGatewayHandler(routes []Route, wasm *wasm.MiddlewareManager, authToken string) *GatewayHandler {
	return &GatewayHandler{
		routes:       routes,
		wasm:         wasm,
		authToken:    authToken,
		rateLimiters: make(map[string]*rateLimiter),
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
		if token != h.authToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Route Matching
	var matchedRoute *Route
	for _, route := range h.routes {
		if strings.HasPrefix(r.URL.Path, route.Prefix) {
			matchedRoute = &route
			break
		}
	}

	if matchedRoute == nil {
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

	// Reverse Proxy Forwarding
	targetURL, err := url.Parse(matchedRoute.Target)
	if err != nil {
		otel.EndSpan(span, err, map[string]interface{}{})
		http.Error(w, "Bad Gateway Target", http.StatusBadGateway)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = &RetryingTransport{base: http.DefaultTransport}
	
	r.URL.Host = targetURL.Host
	r.URL.Scheme = targetURL.Scheme
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	r.Host = targetURL.Host

	// Custom Director rewrite to strip routing prefix
	r.URL.Path = "/" + strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, matchedRoute.Prefix), "/")

	proxy.ServeHTTP(w, r)
	otel.EndSpan(span, nil, map[string]interface{}{
		"http.route":   matchedRoute.Prefix,
		"proxy.target": matchedRoute.Target,
	})
}
