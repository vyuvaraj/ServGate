package proxy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
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

// WeightedTarget represents a backend target with a traffic weight for canary/blue-green deployments.
type WeightedTarget struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

type LLMTarget struct {
	URL   string `json:"url"`
	Model string `json:"model"`
}

type LLMRoutingConfig struct {
	Primary          LLMTarget `json:"primary"`
	Fallback         LLMTarget `json:"fallback"`
	ConfidenceHeader string    `json:"confidence_header"` // Header to inspect for confidence or quality score
	MinConfidence    float64   `json:"min_confidence"`     // Trigger fallback if confidence is below this
}

type WASMTarget struct {
	MiddlewareName string `json:"middleware_name"`
	Weight         int    `json:"weight"`
}

type WASMSplitConfig struct {
	Targets []WASMTarget `json:"targets"`
}

type Route struct {
	Prefix             string            `json:"prefix"`
	Target             string            `json:"target"`
	Targets            []string          `json:"targets,omitempty"`             // Multiple backend targets
	TargetsWeighted    []WeightedTarget  `json:"targets_weighted,omitempty"`    // Weighted canary/blue-green targets
	CanaryAutoPromote  bool              `json:"canary_auto_promote,omitempty"`  // Enable automated promotion
	CanaryPromoteStep  int               `json:"canary_promote_step,omitempty"`  // Increment step
	CanaryPromoteSec   int               `json:"canary_promote_sec,omitempty"`   // Promotion interval
	CanaryMaxErrorRate float64           `json:"canary_max_error_rate,omitempty"` // Rollback threshold
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
	AccessLog          bool              `json:"access_log,omitempty"`          // Enable structured JSONL access logging
	AccessLogPath      string            `json:"access_log_path,omitempty"`     // Path to access log file (default: ./logs/access.jsonl)
	CacheTTLSeconds    int               `json:"cache_ttl_seconds,omitempty"`   // Response cache TTL in seconds (0 = disabled)
	CacheMethods       []string          `json:"cache_methods,omitempty"`       // HTTP methods to cache (default: ["GET"])
	ClientCertPath     string            `json:"client_cert_path,omitempty"`    // Path to client TLS cert
	ClientKeyPath      string            `json:"client_key_path,omitempty"`     // Path to client TLS key
	RootCAPath         string            `json:"root_ca_path,omitempty"`        // Path to backend root CA cert
	MaxConcurrentRequests int            `json:"max_concurrent_requests,omitempty"` // Max concurrent requests to backend
	MaxQueueSize       int               `json:"max_queue_size,omitempty"`      // Max requests allowed to queue
	QueueTimeoutMs     int               `json:"queue_timeout_ms,omitempty"`    // Timeout for queueing in milliseconds
	GoMiddleware       string            `json:"go_middleware,omitempty"`       // Name of native Go middleware plugin
	RequireAPIKey      bool              `json:"require_api_key,omitempty"`     // Require client API key
	AllowedTenants     []string          `json:"allowed_tenants,omitempty"`     // Tenants allowed on this route
	RequestTransform   map[string]string `json:"request_transform,omitempty"`   // Declarative request JSON transformations
	ResponseTransform  map[string]string `json:"response_transform,omitempty"`  // Declarative response JSON transformations
	GraphQLFederation  map[string]string `json:"graphql_federation,omitempty"`  // GraphQL Query-to-backend routing mappings
	MCPEnabled         bool              `json:"mcp_enabled,omitempty"`         // Enable MCP tool call parsing and tracking
	LLMRouting         *LLMRoutingConfig `json:"llm_routing,omitempty"`         // LLM primary and fallback cost-routing configuration
	WASMSplit          *WASMSplitConfig  `json:"wasm_split,omitempty"`          // A/B test split for WASM middlewares
	MaxBodySize        int64             `json:"max_body_size,omitempty"`       // Max request body size in bytes
}

type MetricsTracker struct {
	mu            sync.RWMutex
	totalRequests uint64
	totalErrors   uint64
	lastRequests  uint64
	lastErrors    uint64
	reqRate       float64
	errRate       float64
}

func (m *MetricsTracker) IncRequest() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totalRequests++
}

func (m *MetricsTracker) IncError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totalErrors++
}

func (m *MetricsTracker) Tick() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reqRate = float64(m.totalRequests - m.lastRequests)
	m.errRate = float64(m.totalErrors - m.lastErrors)
	m.lastRequests = m.totalRequests
	m.lastErrors = m.totalErrors
}

func (m *MetricsTracker) Snapshot() (uint64, uint64, float64, float64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.totalRequests, m.totalErrors, m.reqRate, m.errRate
}

type rateLimiter struct {
	mu      sync.Mutex
	history []time.Time
}

type BackpressureLimiter struct {
	sem     chan struct{}
	queue   chan struct{}
	timeout time.Duration
}

func NewBackpressureLimiter(maxConcurrent, maxQueue, timeoutMs int) *BackpressureLimiter {
	if maxConcurrent <= 0 {
		return nil
	}
	timeout := 5000 * time.Millisecond
	if timeoutMs > 0 {
		timeout = time.Duration(timeoutMs) * time.Millisecond
	}
	return &BackpressureLimiter{
		sem:     make(chan struct{}, maxConcurrent),
		queue:   make(chan struct{}, maxQueue),
		timeout: timeout,
	}
}

func (l *BackpressureLimiter) Acquire(ctx context.Context) (func(), error) {
	// Try to acquire slot immediately
	select {
	case l.sem <- struct{}{}:
		return func() { <-l.sem }, nil
	default:
	}

	// If no slot, try to enqueue
	select {
	case l.queue <- struct{}{}:
		// Enqueued, wait for slot, timeout, or context cancellation
		defer func() { <-l.queue }()

		timer := time.NewTimer(l.timeout)
		defer timer.Stop()

		select {
		case l.sem <- struct{}{}:
			return func() { <-l.sem }, nil
		case <-timer.C:
			return nil, fmt.Errorf("queue timeout")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	default:
		// Queue full
		return nil, fmt.Errorf("queue full")
	}
}

type GatewayHandler struct {
	routes         []Route
	routesMu       sync.RWMutex
	wasm           *wasm.MiddlewareManager
	authToken      string
	ratLimiters    map[string]*rateLimiter   // key: clientIP + routePrefix
	limiterMu      sync.Mutex
	rrIndices      map[string]int            // route prefix -> current index
	activeConns    map[string]int            // target URL -> active conn count
	balancerMu     sync.Mutex
	semanticCaches map[string]*SemanticCache // route prefix -> cache
	accessLoggers  map[string]*AccessLogger  // route prefix -> logger
	responseCaches map[string]*ResponseCache // route prefix -> cache
	metricsTracker *MetricsTracker
	transports     map[string]http.RoundTripper // route prefix -> custom mTLS transport
	transportsMu   sync.RWMutex
	limiters       map[string]*BackpressureLimiter // route prefix -> backpressure limiter
	limitersMu     sync.RWMutex
	apiKeys        map[string]APIKey
	apiKeysMu      sync.RWMutex
	aiBilling      *AIBillingTracker

	// PS.3: Backpressure Routing
	targetLoad     map[string]int
	targetLoadMu   sync.RWMutex

	// SEC.15: Dynamic IAM Policy
	policyVersion    int
	policyVersionMu  sync.RWMutex
	revokedSessions  map[string]time.Time
	revokedSessionsMu sync.RWMutex

	// OPS.12: Automated Canary Deployment Engine
	canaryStats   map[string]*canaryStatsRecord // key: canary target URL
	canaryStatsMu sync.Mutex

	// OPS.14: Enterprise Control Plane
	tenantPolicies   map[string]TenantPolicy // key: TenantID
	tenantPoliciesMu sync.RWMutex
}

type TenantPolicy struct {
	TenantID        string   `json:"tenant_id"`
	AllowedClusters []string `json:"allowed_clusters"`
	AllowedRegions  []string `json:"allowed_regions"`
	RateLimitRPM    int      `json:"rate_limit_rpm"`
}

func createMTLSTransport(clientCertPath, clientKeyPath, rootCAPath string) (http.RoundTripper, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if clientCertPath != "" && clientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client key pair: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if rootCAPath != "" {
		caCert, err := os.ReadFile(rootCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read root CA file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		Proxy:           http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return transport, nil
}

func NewGatewayHandler(routes []Route, wasm *wasm.MiddlewareManager, authToken string) *GatewayHandler {
	semanticCaches := make(map[string]*SemanticCache)
	accessLoggers := make(map[string]*AccessLogger)
	responseCaches := make(map[string]*ResponseCache)
	transports := make(map[string]http.RoundTripper)
	limiters := make(map[string]*BackpressureLimiter)

	for _, route := range routes {
		if route.SemanticCache {
			semanticCaches[route.Prefix] = NewSemanticCache(0.85)
		}
		if route.AccessLog {
			logPath := route.AccessLogPath
			if logPath == "" {
				logPath = "./logs/access.jsonl"
			}
			logger, err := NewAccessLogger(logPath)
			if err != nil {
				log.Printf("Gateway: failed to create access logger for %s: %v", route.Prefix, err)
			} else {
				accessLoggers[route.Prefix] = logger
			}
		}
		if route.CacheTTLSeconds > 0 {
			responseCaches[route.Prefix] = NewResponseCache(time.Duration(route.CacheTTLSeconds) * time.Second)
		}
		if route.ClientCertPath != "" || route.RootCAPath != "" {
			tr, err := createMTLSTransport(route.ClientCertPath, route.ClientKeyPath, route.RootCAPath)
			if err != nil {
				log.Printf("Gateway: failed to create mTLS transport for %s: %v", route.Prefix, err)
			} else {
				transports[route.Prefix] = tr
			}
		}
		if route.MaxConcurrentRequests > 0 {
			limiters[route.Prefix] = NewBackpressureLimiter(route.MaxConcurrentRequests, route.MaxQueueSize, route.QueueTimeoutMs)
		}
	}

	tracker := &MetricsTracker{}
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		for range ticker.C {
			tracker.Tick()
		}
	}()

	h := &GatewayHandler{
		routes:          routes,
		wasm:            wasm,
		authToken:       authToken,
		ratLimiters:     make(map[string]*rateLimiter),
		rrIndices:       make(map[string]int),
		activeConns:     make(map[string]int),
		semanticCaches:  semanticCaches,
		accessLoggers:   accessLoggers,
		responseCaches:  responseCaches,
		metricsTracker:  tracker,
		transports:      transports,
		limiters:        limiters,
		apiKeys:         make(map[string]APIKey),
		aiBilling:       NewAIBillingTracker(),
		targetLoad:      make(map[string]int),
		revokedSessions: make(map[string]time.Time),
		canaryStats:     make(map[string]*canaryStatsRecord),
		tenantPolicies:  make(map[string]TenantPolicy),
	}
	go h.startCanaryPromotionLoop()
	return h
}

// GetAIBillingMetrics returns billing metrics for the admin API.
func (h *GatewayHandler) GetAIBillingMetrics() map[string]interface{} {
	return h.aiBilling.GetMetrics()
}

// SetAIBudget configures a spending limit for a tenant.
func (h *GatewayHandler) SetAIBudget(tenantID string, maxCostPerDay float64, maxTokensPerMinute int) {
	h.aiBilling.SetBudget(tenantID, &BudgetConfig{
		MaxCostPerDay:      maxCostPerDay,
		MaxTokensPerMinute: maxTokensPerMinute,
		AlertThreshold:     80.0,
	})
}

func (h *GatewayHandler) SetAPIKeys(keys []APIKey) {
	h.apiKeysMu.Lock()
	defer h.apiKeysMu.Unlock()
	h.apiKeys = make(map[string]APIKey)
	for _, k := range keys {
		h.apiKeys[k.Key] = k
	}
}

func (h *GatewayHandler) UpdateRoutes(newRoutes []Route) {
	h.routesMu.Lock()
	defer h.routesMu.Unlock()
	h.routes = newRoutes

	h.balancerMu.Lock()
	defer h.balancerMu.Unlock()

	h.transportsMu.Lock()
	defer h.transportsMu.Unlock()

	h.limitersMu.Lock()
	defer h.limitersMu.Unlock()

	for _, route := range newRoutes {
		if route.SemanticCache {
			if _, exists := h.semanticCaches[route.Prefix]; !exists {
				h.semanticCaches[route.Prefix] = NewSemanticCache(0.85)
			}
		}
		if route.CacheTTLSeconds > 0 {
			if _, exists := h.responseCaches[route.Prefix]; !exists {
				h.responseCaches[route.Prefix] = NewResponseCache(time.Duration(route.CacheTTLSeconds) * time.Second)
			}
		}
		if route.AccessLog {
			if _, exists := h.accessLoggers[route.Prefix]; !exists {
				logPath := route.AccessLogPath
				if logPath == "" {
					logPath = "./logs/access.jsonl"
				}
				logger, err := NewAccessLogger(logPath)
				if err != nil {
					log.Printf("Gateway: failed to create access logger for %s: %v", route.Prefix, err)
				} else {
					h.accessLoggers[route.Prefix] = logger
				}
			}
		}
		if route.ClientCertPath != "" || route.RootCAPath != "" {
			if _, exists := h.transports[route.Prefix]; !exists {
				tr, err := createMTLSTransport(route.ClientCertPath, route.ClientKeyPath, route.RootCAPath)
				if err != nil {
					log.Printf("Gateway: failed to create mTLS transport for %s: %v", route.Prefix, err)
				} else {
					h.transports[route.Prefix] = tr
				}
			}
		}
		if route.MaxConcurrentRequests > 0 {
			if _, exists := h.limiters[route.Prefix]; !exists {
				h.limiters[route.Prefix] = NewBackpressureLimiter(route.MaxConcurrentRequests, route.MaxQueueSize, route.QueueTimeoutMs)
			}
		}
	}
}

func (h *GatewayHandler) RegisterRoute(route Route) {
	h.routesMu.Lock()
	defer h.routesMu.Unlock()

	found := false
	for i, r := range h.routes {
		if r.Prefix == route.Prefix {
			h.routes[i] = route
			found = true
			break
		}
	}
	if !found {
		h.routes = append(h.routes, route)
	}

	h.balancerMu.Lock()
	defer h.balancerMu.Unlock()

	h.transportsMu.Lock()
	defer h.transportsMu.Unlock()

	h.limitersMu.Lock()
	defer h.limitersMu.Unlock()

	if route.SemanticCache {
		if _, exists := h.semanticCaches[route.Prefix]; !exists {
			h.semanticCaches[route.Prefix] = NewSemanticCache(0.85)
		}
	}
	if route.CacheTTLSeconds > 0 {
		if _, exists := h.responseCaches[route.Prefix]; !exists {
			h.responseCaches[route.Prefix] = NewResponseCache(time.Duration(route.CacheTTLSeconds) * time.Second)
		}
	}
	if route.AccessLog {
		if _, exists := h.accessLoggers[route.Prefix]; !exists {
			logPath := route.AccessLogPath
			if logPath == "" {
				logPath = "./logs/access.jsonl"
			}
			logger, err := NewAccessLogger(logPath)
			if err != nil {
				log.Printf("Gateway: failed to create access logger for %s: %v", route.Prefix, err)
			} else {
				h.accessLoggers[route.Prefix] = logger
			}
		}
	}
	if route.ClientCertPath != "" || route.RootCAPath != "" {
		if _, exists := h.transports[route.Prefix]; !exists {
			tr, err := createMTLSTransport(route.ClientCertPath, route.ClientKeyPath, route.RootCAPath)
			if err != nil {
				log.Printf("Gateway: failed to create mTLS transport for %s: %v", route.Prefix, err)
			} else {
				h.transports[route.Prefix] = tr
			}
		}
	}
	if route.MaxConcurrentRequests > 0 {
		if _, exists := h.limiters[route.Prefix]; !exists {
			h.limiters[route.Prefix] = NewBackpressureLimiter(route.MaxConcurrentRequests, route.MaxQueueSize, route.QueueTimeoutMs)
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

type GatewayMetricsSnapshot struct {
	TotalRequests     uint64         `json:"total_requests"`
	TotalErrors       uint64         `json:"total_errors"`
	RequestRate       float64        `json:"request_rate"`
	ErrorRate         float64        `json:"error_rate"`
	ActiveConnections map[string]int `json:"active_connections"`
	Timestamp         int64          `json:"timestamp"`
}

func (h *GatewayHandler) GetMetricsSnapshot() GatewayMetricsSnapshot {
	totalReq, totalErr, reqRate, errRate := h.metricsTracker.Snapshot()
	return GatewayMetricsSnapshot{
		TotalRequests:     totalReq,
		TotalErrors:       totalErr,
		RequestRate:       reqRate,
		ErrorRate:         errRate,
		ActiveConnections: h.GetActiveConnections(),
		Timestamp:         time.Now().Unix(),
	}
}

// Close shuts down all background resources (access loggers, cache eviction goroutines).
func (h *GatewayHandler) Close() {
	for _, logger := range h.accessLoggers {
		logger.Close()
	}
	for _, cache := range h.responseCaches {
		cache.Stop()
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
	lim, exists := h.ratLimiters[key]
	if !exists {
		lim = &rateLimiter{}
		h.ratLimiters[key] = lim
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
	start := time.Now()
	h.metricsTracker.IncRequest()

	if r.URL.Path == "/api/tenants/policies" {
		switch r.Method {
		case http.MethodGet:
			h.tenantPoliciesMu.RLock()
			defer h.tenantPoliciesMu.RUnlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(h.tenantPolicies)
			return
		case http.MethodPost:
			var policy TenantPolicy
			if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if policy.TenantID == "" {
				http.Error(w, "tenant_id required", http.StatusBadRequest)
				return
			}
			h.tenantPoliciesMu.Lock()
			h.tenantPolicies[policy.TenantID] = policy
			h.tenantPoliciesMu.Unlock()
			w.WriteHeader(http.StatusCreated)
			return
		}
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID != "" {
		h.tenantPoliciesMu.RLock()
		policy, exists := h.tenantPolicies[tenantID]
		h.tenantPoliciesMu.RUnlock()
		if exists {
			currentCluster := os.Getenv("SERV_CLUSTER")
			if currentCluster == "" {
				currentCluster = "default"
			}
			if len(policy.AllowedClusters) > 0 {
				allowed := false
				for _, c := range policy.AllowedClusters {
					if c == currentCluster || c == "*" {
						allowed = true
						break
					}
				}
				if !allowed {
					WriteJSONError(w, r, "Tenant policy violation: Cluster restricted", "ERR_TENANT_POLICY_VIOLATION", http.StatusForbidden)
					return
				}
			}

			currentRegion := os.Getenv("SERV_REGION")
			if currentRegion == "" {
				currentRegion = "us-east"
			}
			if len(policy.AllowedRegions) > 0 {
				allowed := false
				for _, reg := range policy.AllowedRegions {
					if reg == currentRegion || reg == "*" {
						allowed = true
						break
					}
				}
				if !allowed {
					WriteJSONError(w, r, "Tenant policy violation: Region restricted", "ERR_TENANT_POLICY_VIOLATION", http.StatusForbidden)
					return
				}
			}
		}
	}

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
			if _, ok := h.ValidateJWTWithPolicy(token, []byte(jwtSec)); ok {
				authenticated = true

				h.policyVersionMu.RLock()
				curVer := h.policyVersion
				h.policyVersionMu.RUnlock()

				parts := strings.Split(token, ".")
				if len(parts) == 3 {
					payloadBytes, err := base64UrlDecode(parts[1])
					if err == nil {
						var claims struct {
							PolicyVer int `json:"policy_ver"`
						}
						if json.Unmarshal(payloadBytes, &claims) == nil {
							if claims.PolicyVer < curVer {
								w.Header().Set("X-Token-Refresh", "true")
							}
						}
					}
				}
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
		h.metricsTracker.IncError()
		return
	}

	// Limit request body size based on route configuration
	limit := matchedRoute.MaxBodySize
	if limit <= 0 {
		limit = 10 * 1024 * 1024 // Default to 10MB limit if not specified
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)

	// Multi-tenant API Key Check
	if matchedRoute.RequireAPIKey {
		apiKeyVal := r.Header.Get("X-API-Key")
		if apiKeyVal == "" {
			WriteJSONError(w, r, "Unauthorized: Missing API Key", "ERR_MISSING_API_KEY", http.StatusUnauthorized)
			return
		}

		h.apiKeysMu.RLock()
		keyInfo, keyExists := h.apiKeys[apiKeyVal]
		h.apiKeysMu.RUnlock()

		if !keyExists {
			WriteJSONError(w, r, "Unauthorized: Invalid API Key", "ERR_INVALID_API_KEY", http.StatusUnauthorized)
			return
		}

		// Check if route is in AllowedRoutes
		if len(keyInfo.AllowedRoutes) > 0 {
			allowed := false
			for _, routePattern := range keyInfo.AllowedRoutes {
				if strings.HasPrefix(r.URL.Path, routePattern) {
					allowed = true
					break
				}
			}
			if !allowed {
				WriteJSONError(w, r, "Forbidden: API Key not allowed on this path", "ERR_FORBIDDEN_ROUTE", http.StatusForbidden)
				return
			}
		}

		// Check if tenant is allowed on this route
		if len(matchedRoute.AllowedTenants) > 0 {
			tenantAllowed := false
			for _, t := range matchedRoute.AllowedTenants {
				if t == keyInfo.Tenant {
					tenantAllowed = true
					break
				}
			}
			if !tenantAllowed {
				WriteJSONError(w, r, "Forbidden: Tenant access denied", "ERR_TENANT_ACCESS_DENIED", http.StatusForbidden)
				return
			}
		}

		// Apply key-specific rate limiting
		if keyInfo.RateLimitRPM > 0 {
			if h.isRateLimited("apikey:"+apiKeyVal, matchedRoute.Prefix, keyInfo.RateLimitRPM) {
				WriteJSONError(w, r, "Too Many Requests: API Key rate limit exceeded", "ERR_RATE_LIMIT_EXCEEDED", http.StatusTooManyRequests)
				return
			}
		}

		// Inject tenant into request context
		r = r.WithContext(context.WithValue(r.Context(), "tenant", keyInfo.Tenant))
	}

	// MCP (Model Context Protocol) handler
	if matchedRoute.MCPEnabled && r.Method == http.MethodPost {
		bodyBytes, err := io.ReadAll(r.Body)
		if err == nil {
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			var jsonRpc struct {
				Jsonrpc string `json:"jsonrpc"`
				Method  string `json:"method"`
				Id      interface{} `json:"id"`
				Params  struct {
					Name string `json:"name"`
				} `json:"params"`
			}
			if json.Unmarshal(bodyBytes, &jsonRpc) == nil && jsonRpc.Method == "tools/call" {
				toolName := jsonRpc.Params.Name
				agentID := r.Header.Get("X-Agent-ID")
				if agentID == "" {
					agentID = "default-agent"
				}

				log.Printf("MCP Gateway: Routing tool call '%s' for agent '%s'", toolName, agentID)

				if h.isRateLimited("mcp-agent:"+agentID, matchedRoute.Prefix, 5) {
					errResp := map[string]interface{}{
						"jsonrpc": "2.0",
						"id":      jsonRpc.Id,
						"error": map[string]interface{}{
							"code":    -32001,
							"message": "Agent rate limit exceeded for tool calls",
						},
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusTooManyRequests)
					json.NewEncoder(w).Encode(errResp)
					return
				}
				w.Header().Set("X-MCP-Tool", toolName)
				w.Header().Set("X-MCP-Agent", agentID)
			}
		}
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

	// Backpressure & Concurrency Limiting
	h.limitersMu.RLock()
	limiter, hasLimiter := h.limiters[matchedRoute.Prefix]
	h.limitersMu.RUnlock()
	if hasLimiter && limiter != nil {
		release, err := limiter.Acquire(r.Context())
		if err != nil {
			w.Header().Set("Retry-After", "5")
			if err.Error() == "queue full" {
				WriteJSONError(w, r, "Too Many Requests: backpressure queue full", "ERR_QUEUE_FULL", http.StatusTooManyRequests)
			} else {
				WriteJSONError(w, r, "Service Unavailable: queue timeout", "ERR_BACKPRESSURE_TIMEOUT", http.StatusServiceUnavailable)
			}
			return
		}
		defer release()
	}

	// GraphQL Federation Proxy Check
	if len(matchedRoute.GraphQLFederation) > 0 && r.Method == http.MethodPost {
		h.handleGraphQLFederation(w, r, &matchedRoute)
		return
	}

	// Distributed Tracing: Extract or start trace context span
	traceparent := r.Header.Get("traceparent")
	span := otel.StartSpan(fmt.Sprintf("%s %s", r.Method, r.URL.Path), traceparent)
	
	// Inject trace context headers
	var traceID string
	if span != nil {
		traceparent = fmt.Sprintf("00-%s-%s-01", span.TraceID, span.SpanID)
		r.Header.Set("traceparent", traceparent)
		traceID = span.TraceID

		// Capture request details for replay
		span.Attributes = make(map[string]interface{})
		span.Attributes["http.request.header.content-type"] = r.Header.Get("Content-Type")
		if r.Body != nil && (r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" || r.ContentLength > 0) {
			bodyBytes, err := io.ReadAll(r.Body)
			if err == nil {
				r.Body.Close()
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				span.Attributes["http.request.body"] = string(bodyBytes)
			}
		}
	}

	// Response Cache — check for cache hit before proxying
	var cacheKey string
	var routeCache *ResponseCache
	if matchedRoute.CacheTTLSeconds > 0 && IsCacheableMethod(r.Method, matchedRoute.CacheMethods) {
		routeCache = h.responseCaches[matchedRoute.Prefix]
		if routeCache != nil {
			cacheKey = CacheKey(r.Method, r.URL.Path, r.URL.RawQuery)
			if entry, hit := routeCache.Get(cacheKey); hit {
				// Serve from cache
				for k, vs := range entry.Headers {
					for _, v := range vs {
						w.Header().Add(k, v)
					}
				}
				w.Header().Set("X-Cache", "HIT")
				w.WriteHeader(entry.StatusCode)
				w.Write(entry.Body)
				otel.EndSpan(span, nil, map[string]interface{}{
					"http.route": matchedRoute.Prefix,
					"cache.hit":  true,
				})
				// Access log for cache hits
				if logger, ok := h.accessLoggers[matchedRoute.Prefix]; ok {
					logger.Log(LogEntry{
						Timestamp:    start.UTC().Format(time.RFC3339),
						Method:       r.Method,
						Path:         r.URL.Path,
						Route:        matchedRoute.Prefix,
						ClientIP:     clientIP,
						Status:       entry.StatusCode,
						LatencyMs:    time.Since(start).Milliseconds(),
						RequestSize:  r.ContentLength,
						ResponseSize: len(entry.Body),
						UserAgent:    r.Header.Get("User-Agent"),
						TraceID:      traceID,
						Target:       "cache",
					})
				}
				return
			}
		}
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
	wasmMiddleware := h.selectWASMMiddleware(&matchedRoute)
	if wasmMiddleware != "" {
		var inputBytes []byte
		isPolicy := strings.Contains(strings.ToLower(wasmMiddleware), "policy")

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

		wasmSpan := otel.StartSpan(fmt.Sprintf("WASM Middleware %s", wasmMiddleware), traceparent)
		outputBytes, err := h.wasm.Run(r.Context(), wasmMiddleware, inputBytes)
		otel.EndSpan(wasmSpan, err, map[string]interface{}{})

		if err != nil {
			otel.EndSpan(span, err, map[string]interface{}{})
			WriteJSONError(w, r, "Internal Server Error: WASM Middleware execution failed", "ERR_WASM_MIDDLEWARE_FAILED", http.StatusInternalServerError)
			h.metricsTracker.IncError()
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

	// Go Plugin Request Middleware execution if registered
	if matchedRoute.GoMiddleware != "" {
		if p, ok := GetPlugin(matchedRoute.GoMiddleware); ok {
			pluginResp, pErr := p.OnRequest(r)
			if pErr != nil {
				otel.EndSpan(span, pErr, map[string]interface{}{})
				WriteJSONError(w, r, "Internal Server Error: Go Plugin execution failed", "ERR_GO_PLUGIN_FAILED", http.StatusInternalServerError)
				h.metricsTracker.IncError()
				return
			}
			if pluginResp != nil {
				defer pluginResp.Body.Close()
				for k, vs := range pluginResp.Header {
					for _, v := range vs {
						w.Header().Add(k, v)
					}
				}
				w.WriteHeader(pluginResp.StatusCode)
				io.Copy(w, pluginResp.Body)
				otel.EndSpan(span, nil, map[string]interface{}{
					"http.route":             matchedRoute.Prefix,
					"go_plugin.shortcircuit": true,
				})
				return
			}
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
			if resp.StatusCode >= 500 {
				h.metricsTracker.IncError()
			}
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
		h.metricsTracker.IncError()
		return
	}

	// Cost-Aware LLM Routing check
	if matchedRoute.LLMRouting != nil {
		h.transportsMu.RLock()
		customTransport, hasTransport := h.transports[matchedRoute.Prefix]
		h.transportsMu.RUnlock()

		baseTransport := http.DefaultTransport
		if hasTransport {
			baseTransport = customTransport
		}

		llmConf := matchedRoute.LLMRouting
		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body.Close()

		// 1. Primary request to cheaper model
		primaryURL, _ := url.Parse(llmConf.Primary.URL)
		req, _ := http.NewRequestWithContext(r.Context(), r.Method, primaryURL.String(), bytes.NewReader(bodyBytes))
		for k, vs := range r.Header {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		if llmConf.Primary.Model != "" {
			req.Header.Set("X-LLM-Model", llmConf.Primary.Model)
		}

		client := &http.Client{Transport: baseTransport}
		resp, err := client.Do(req)

		var respBody []byte
		shouldFallback := false
		if err != nil {
			shouldFallback = true
		} else {
			respBody, _ = io.ReadAll(resp.Body)
			resp.Body.Close()

			if llmConf.ConfidenceHeader != "" {
				confStr := resp.Header.Get(llmConf.ConfidenceHeader)
				var confVal float64
				fmt.Sscanf(confStr, "%f", &confVal)
				if confVal < llmConf.MinConfidence {
					shouldFallback = true
				}
			}
			if resp.StatusCode >= 500 {
				shouldFallback = true
			}
		}

		if shouldFallback {
			// 2. Fallback request to premium model
			fallbackURL, _ := url.Parse(llmConf.Fallback.URL)
			reqFb, _ := http.NewRequestWithContext(r.Context(), r.Method, fallbackURL.String(), bytes.NewReader(bodyBytes))
			for k, vs := range r.Header {
				for _, v := range vs {
					reqFb.Header.Add(k, v)
				}
			}
			if llmConf.Fallback.Model != "" {
				reqFb.Header.Set("X-LLM-Model", llmConf.Fallback.Model)
			}
			respFb, errFb := client.Do(reqFb)
			if errFb != nil {
				WriteJSONError(w, r, "Bad Gateway: Fallback failed", "ERR_BAD_GATEWAY_LLM", http.StatusBadGateway)
				h.metricsTracker.IncError()
				return
			}
			defer respFb.Body.Close()
			respBody, _ = io.ReadAll(respFb.Body)

			for k, vs := range respFb.Header {
				w.Header().Del(k)
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			w.Header().Set("X-LLM-Fallback", "true")
			w.WriteHeader(respFb.StatusCode)
			w.Write(respBody)

			otel.EndSpan(span, nil, map[string]interface{}{
				"http.route":         matchedRoute.Prefix,
				"llm.fallback":       true,
				"llm.fallback_model": llmConf.Fallback.Model,
			})
			return
		}

		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.Header().Set("X-LLM-Fallback", "false")
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)

		otel.EndSpan(span, nil, map[string]interface{}{
			"http.route":        matchedRoute.Prefix,
			"llm.fallback":      false,
			"llm.primary_model": llmConf.Primary.Model,
		})
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

	// Declarative Request JSON Transformation
	if len(matchedRoute.RequestTransform) > 0 {
		bodyBytes, err := io.ReadAll(r.Body)
		if err == nil {
			r.Body.Close()
			if transformedBody, err := transformJSON(bodyBytes, matchedRoute.RequestTransform); err == nil {
				r.Body = io.NopCloser(bytes.NewReader(transformedBody))
				r.ContentLength = int64(len(transformedBody))
			} else {
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}
		}
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

	// Determine if we need to capture the response body (for caching or access logging)
	needCapture := routeCache != nil && cacheKey != ""
	rec := NewStatusRecordingResponseWriter(w, needCapture)

	// Add canary target header for observability
	if len(matchedRoute.TargetsWeighted) > 0 {
		rec.Header().Set("X-Canary-Target", selectedTarget)
	}

	h.transportsMu.RLock()
	customTransport, hasTransport := h.transports[matchedRoute.Prefix]
	h.transportsMu.RUnlock()

	baseTransport := http.DefaultTransport
	if hasTransport {
		baseTransport = customTransport
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = &RetryingTransport{base: baseTransport}

	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		h.targetLoadMu.Lock()
		h.targetLoad[selectedTarget] = 100 // Maximum penalty
		h.targetLoadMu.Unlock()
		WriteJSONError(rw, req, "Bad Gateway: "+err.Error(), "ERR_BAD_GATEWAY", http.StatusBadGateway)
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		if loadStr := resp.Header.Get("X-Backpressure"); loadStr != "" {
			var load int
			if _, err := fmt.Sscanf(loadStr, "%d", &load); err == nil {
				h.targetLoadMu.Lock()
				h.targetLoad[selectedTarget] = load
				h.targetLoadMu.Unlock()
			}
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		resp.Body.Close()

		// Run native Go Plugin Response Middleware if registered
		if matchedRoute.GoMiddleware != "" {
			if p, ok := GetPlugin(matchedRoute.GoMiddleware); ok {
				tempResp := &http.Response{
					StatusCode: resp.StatusCode,
					Header:     resp.Header,
					Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
				}
				pErr := p.OnResponse(resp.Request, rec, tempResp)
				if pErr != nil {
					return fmt.Errorf("go plugin OnResponse failed: %w", pErr)
				}
				bodyBytes, _ = io.ReadAll(tempResp.Body)
				tempResp.Body.Close()
			}
		}

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

		// Declarative Response JSON Transformation
		if len(matchedRoute.ResponseTransform) > 0 {
			if transformedBody, err := transformJSON(bodyBytes, matchedRoute.ResponseTransform); err == nil {
				bodyBytes = transformedBody
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

	if needCapture {
		w.Header().Set("X-Cache", "MISS")
	}

	proxy.ServeHTTP(rec, r)

	if len(matchedRoute.TargetsWeighted) > 1 && selectedTarget == matchedRoute.TargetsWeighted[1].URL {
		h.canaryStatsMu.Lock()
		stats, ok := h.canaryStats[selectedTarget]
		if !ok {
			stats = &canaryStatsRecord{}
			h.canaryStats[selectedTarget] = stats
		}
		stats.TotalCalls++
		if rec.StatusCode >= 500 {
			stats.ErrorCalls++
		}
		h.canaryStatsMu.Unlock()
	}

	if rec.StatusCode >= 500 {
		h.metricsTracker.IncError()
	}

	// Store response in cache if applicable
	if needCapture && rec.StatusCode >= 200 && rec.StatusCode < 300 {
		routeCache.Set(cacheKey, rec.Body(), rec.StatusCode, rec.CapturedHeaders())
	}

	// Access logging
	if logger, ok := h.accessLoggers[matchedRoute.Prefix]; ok {
		logger.Log(BuildLogEntry(r, rec, matchedRoute.Prefix, selectedTarget, traceID, start, ""))
	}

	otel.EndSpan(span, nil, map[string]interface{}{
		"http.route":   matchedRoute.Prefix,
		"proxy.target": selectedTarget,
	})
}

func (h *GatewayHandler) selectTarget(route *Route) string {
	// Weighted targets take highest priority (canary/blue-green)
	if len(route.TargetsWeighted) > 0 {
		totalWeight := 0
		for _, wt := range route.TargetsWeighted {
			totalWeight += wt.Weight
		}
		if totalWeight > 0 {
			r := rand.Intn(totalWeight)
			accum := 0
			for _, wt := range route.TargetsWeighted {
				accum += wt.Weight
				if r < accum {
					return wt.URL
				}
			}
			return route.TargetsWeighted[0].URL
		}
	}

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

	if route.LoadBalancer == "backpressure" {
		minLoad := -1
		var selected string
		for _, target := range route.Targets {
			h.targetLoadMu.RLock()
			load := h.targetLoad[target]
			h.targetLoadMu.RUnlock()

			if minLoad == -1 || load < minLoad {
				minLoad = load
				selected = target
			}
		}
		if selected != "" {
			return selected
		}
	}

	// Default: Round Robin
	idx := h.rrIndices[route.Prefix]
	selected := route.Targets[idx%len(route.Targets)]
	h.rrIndices[route.Prefix] = (idx + 1) % len(route.Targets)
	return selected
}

func (h *GatewayHandler) selectWASMMiddleware(route *Route) string {
	if route.WASMSplit == nil || len(route.WASMSplit.Targets) == 0 {
		return route.Middleware
	}
	totalWeight := 0
	for _, target := range route.WASMSplit.Targets {
		totalWeight += target.Weight
	}
	if totalWeight <= 0 {
		return route.Middleware
	}
	val := rand.Intn(totalWeight)
	accum := 0
	for _, target := range route.WASMSplit.Targets {
		accum += target.Weight
		if val < accum {
			return target.MiddlewareName
		}
	}
	return route.WASMSplit.Targets[0].MiddlewareName
}

func (h *GatewayHandler) SelectWASMMiddlewareForTest(route *Route) string {
	return h.selectWASMMiddleware(route)
}


func (h *GatewayHandler) handleGraphQLFederation(w http.ResponseWriter, r *http.Request, route *Route) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		WriteJSONError(w, r, "Bad request: failed to read body", "ERR_BAD_REQUEST_BODY", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	var reqBody struct {
		Query         string                 `json:"query"`
		Variables     map[string]interface{} `json:"variables"`
		OperationName string                 `json:"operationName"`
	}
	if err := json.Unmarshal(bodyBytes, &reqBody); err != nil {
		WriteJSONError(w, r, "Bad request: invalid JSON payload", "ERR_INVALID_JSON", http.StatusBadRequest)
		return
	}

	// Basic AST field parser for simplicity (extract top-level fields inside query { ... })
	fields := extractGraphQLQueryFields(reqBody.Query)
	if len(fields) == 0 {
		WriteJSONError(w, r, "Bad request: no query fields detected", "ERR_BAD_QUERY", http.StatusBadRequest)
		return
	}

	type subResult struct {
		field string
		data  interface{}
		err   error
	}

	resultsChan := make(chan subResult, len(fields))
	var wg sync.WaitGroup

	for _, field := range fields {
		targetBackend, exists := route.GraphQLFederation[field]
		if !exists {
			// Fallback to default target
			targetBackend = route.Target
		}

		if targetBackend == "" {
			continue
		}

		wg.Add(1)
		go func(f, target string) {
			defer wg.Done()
			
			// Build field-specific single query: query { <field> { ... } }
			subQuery := fmt.Sprintf("query { %s }", rebuildQueryForField(reqBody.Query, f))
			subReqPayload := map[string]interface{}{
				"query": subQuery,
			}
			if reqBody.Variables != nil {
				subReqPayload["variables"] = reqBody.Variables
			}
			subBytes, _ := json.Marshal(subReqPayload)

			httpReq, err := http.NewRequestWithContext(r.Context(), "POST", target, bytes.NewReader(subBytes))
			if err != nil {
				resultsChan <- subResult{field: f, err: err}
				return
			}
			httpReq.Header.Set("Content-Type", "application/json")
			if auth := r.Header.Get("Authorization"); auth != "" {
				httpReq.Header.Set("Authorization", auth)
			}

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(httpReq)
			if err != nil {
				resultsChan <- subResult{field: f, err: err}
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				rb, _ := io.ReadAll(resp.Body)
				resultsChan <- subResult{field: f, err: fmt.Errorf("backend status %d: %s", resp.StatusCode, string(rb))}
				return
			}

			var respData struct {
				Data   map[string]interface{} `json:"data"`
				Errors []interface{}          `json:"errors"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
				resultsChan <- subResult{field: f, err: err}
				return
			}

			if len(respData.Errors) > 0 {
				resultsChan <- subResult{field: f, err: fmt.Errorf("backend errors: %v", respData.Errors)}
				return
			}

			resultsChan <- subResult{field: f, data: respData.Data[f]}
		}(field, targetBackend)
	}

	wg.Wait()
	close(resultsChan)

	mergedData := make(map[string]interface{})
	var errors []string

	for res := range resultsChan {
		if res.err != nil {
			errors = append(errors, fmt.Sprintf("field %q: %v", res.field, res.err))
		} else {
			mergedData[res.field] = res.data
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	respPayload := map[string]interface{}{
		"data": mergedData,
	}
	if len(errors) > 0 {
		respPayload["errors"] = errors
	}
	_ = json.NewEncoder(w).Encode(respPayload)
}

func extractGraphQLQueryFields(query string) []string {
	// Simple string parsing to extract top-level fields inside query { ... }
	normalized := strings.ReplaceAll(query, "\n", " ")
	normalized = strings.ReplaceAll(normalized, "\t", " ")
	normalized = strings.ReplaceAll(normalized, ",", " ")
	
	// Strip query prefix
	idx := strings.Index(normalized, "{")
	if idx == -1 {
		return nil
	}
	normalized = normalized[idx+1:]
	
	// Read until matching }
	var fields []string
	depth := 0
	currentField := ""
	
	for i := 0; i < len(normalized); i++ {
		char := normalized[i]
		if char == '{' {
			depth++
			if depth == 1 {
				// Completed reading top-level field name
				f := strings.TrimSpace(currentField)
				if f != "" {
					// Split by whitespace to get last word if any aliases exist
					parts := strings.Fields(f)
					if len(parts) > 0 {
						fields = append(fields, parts[len(parts)-1])
					}
				}
				currentField = ""
			}
		} else if char == '}' {
			depth--
			if depth < 0 {
				break
			}
		} else {
			if depth == 0 {
				currentField += string(char)
			}
		}
	}
	return fields
}

func rebuildQueryForField(originalQuery, field string) string {
	// Find the field and its matching braces block
	normalized := originalQuery
	idx := strings.Index(normalized, field)
	if idx == -1 {
		return ""
	}
	
	// Read from field start until matching closing brace
	block := normalized[idx:]
	braceIdx := strings.Index(block, "{")
	if braceIdx == -1 {
		return field
	}
	
	depth := 0
	endIdx := -1
	for i := braceIdx; i < len(block); i++ {
		if block[i] == '{' {
			depth++
		} else if block[i] == '}' {
			depth--
			if depth == 0 {
				endIdx = i
				break
			}
		}
	}
	if endIdx == -1 {
		return block
	}
	return block[:endIdx+1]
}

// InvalidateCache removes entries matching the prefix from a route's response cache.
func (h *GatewayHandler) InvalidateCache(routePrefix, keyPrefix string) int {
	if cache, ok := h.responseCaches[routePrefix]; ok {
		return cache.Invalidate(keyPrefix)
	}
	// If no specific route, clear all caches matching the route prefix
	total := 0
	for rp, cache := range h.responseCaches {
		if strings.HasPrefix(rp, routePrefix) || routePrefix == "" {
			total += cache.Invalidate("")
		}
	}
	return total
}

// GetResponseCaches returns the response cache map for admin inspection.
func (h *GatewayHandler) GetResponseCaches() map[string]*ResponseCache {
	return h.responseCaches
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

func ValidateJWT(tokenStr string, secret []byte) (string, bool) {
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

func (h *GatewayHandler) ValidateJWTWithPolicy(tokenStr string, secret []byte) (string, bool) {
	username, ok := ValidateJWT(tokenStr, secret)
	if !ok {
		return "", false
	}

	parts := strings.Split(tokenStr, ".")
	if len(parts) == 3 {
		payloadBytes, err := base64UrlDecode(parts[1])
		if err == nil {
			var claims struct {
				Iat      int64 `json:"iat"`
				PolicyVer int   `json:"policy_ver"`
			}
			if json.Unmarshal(payloadBytes, &claims) == nil {
				h.revokedSessionsMu.RLock()
				revTime, exists := h.revokedSessions[username]
				h.revokedSessionsMu.RUnlock()

				if exists && claims.Iat > 0 && time.Unix(claims.Iat, 0).Before(revTime) {
					return "", false // Explicitly revoked
				}
			}
		}
	}

	return username, true
}

func (h *GatewayHandler) RevokeUserSession(username string) {
	h.revokedSessionsMu.Lock()
	h.revokedSessions[username] = time.Now()
	h.revokedSessionsMu.Unlock()
}

func (h *GatewayHandler) IncrementPolicyVersion() {
	h.policyVersionMu.Lock()
	h.policyVersion++
	h.policyVersionMu.Unlock()
}

func base64UrlDecode(s string) ([]byte, error) {
	if l := len(s) % 4; l > 0 {
		s += strings.Repeat("=", 4-l)
	}
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	return base64.StdEncoding.DecodeString(s)
}

func (h *GatewayHandler) serveOpenAPIDocs(w http.ResponseWriter, r *http.Request) {
	_ = r
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
						switch p {
						case "required":
							req = true
						case "int", "integer":
							pType = "integer"
						case "float", "number":
							pType = "number"
						case "bool", "boolean":
							pType = "boolean"
						case "string":
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

func transformJSON(body []byte, mapping map[string]string) ([]byte, error) {
	if len(body) == 0 || len(mapping) == 0 {
		return body, nil
	}

	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	transformed := transformValue(data, mapping)

	out, err := json.Marshal(transformed)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return out, nil
}

func transformValue(val interface{}, mapping map[string]string) interface{} {
	switch v := val.(type) {
	case map[string]interface{}:
		res := make(map[string]interface{})
		for key, value := range v {
			newKey := key
			if mapped, ok := mapping[key]; ok {
				newKey = mapped
			}
			res[newKey] = transformValue(value, mapping)
		}
		return res
	case []interface{}:
		res := make([]interface{}, len(v))
		for i, value := range v {
			res[i] = transformValue(value, mapping)
		}
		return res
	default:
		return val
	}
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

type canaryStatsRecord struct {
	TotalCalls int64
	ErrorCalls int64
}

func (h *GatewayHandler) startCanaryPromotionLoop() {
	ticker := time.NewTicker(200 * time.Millisecond) // Fast ticker for responsive testing
	lastPromoted := make(map[string]time.Time)

	for range ticker.C {
		h.routesMu.Lock()
		for i, route := range h.routes {
			if !route.CanaryAutoPromote || len(route.TargetsWeighted) < 2 {
				continue
			}

			stable := &h.routes[i].TargetsWeighted[0]
			canary := &h.routes[i].TargetsWeighted[1]

			if canary.Weight >= 100 {
				h.routes[i].CanaryAutoPromote = false
				continue
			}

			h.canaryStatsMu.Lock()
			stats, exists := h.canaryStats[canary.URL]
			var total, errors int64
			if exists {
				total = stats.TotalCalls
				errors = stats.ErrorCalls
			}
			h.canaryStatsMu.Unlock()

			maxErrRate := route.CanaryMaxErrorRate
			if maxErrRate <= 0 {
				maxErrRate = 0.01
			}
			if total >= 3 && float64(errors)/float64(total) > maxErrRate {
				log.Printf("[CANARY ENGINE] WARNING: High error rate (%.2f%%) detected on canary target %s. Rolling back to stable!", float64(errors)/float64(total)*100, canary.URL)
				stable.Weight = 100
				canary.Weight = 0
				h.routes[i].CanaryAutoPromote = false

				h.canaryStatsMu.Lock()
				delete(h.canaryStats, canary.URL)
				h.canaryStatsMu.Unlock()
				continue
			}

			interval := time.Duration(route.CanaryPromoteSec) * time.Second
			if interval <= 0 {
				interval = 1 * time.Second // Fast promote defaults for testing
			}
			lastTime, ok := lastPromoted[route.Prefix]
			if !ok {
				lastPromoted[route.Prefix] = time.Now()
				continue
			}

			if time.Since(lastTime) >= interval {
				step := route.CanaryPromoteStep
				if step <= 0 {
					step = 10
				}
				canary.Weight += step
				if canary.Weight > 100 {
					canary.Weight = 100
				}
				stable.Weight = 100 - canary.Weight
				log.Printf("[CANARY ENGINE] Promoting canary %s weight to %d%% (stable %d%%)", canary.URL, canary.Weight, stable.Weight)
				lastPromoted[route.Prefix] = time.Now()

				h.canaryStatsMu.Lock()
				if stats != nil {
					stats.TotalCalls = 0
					stats.ErrorCalls = 0
				}
				h.canaryStatsMu.Unlock()
			}
		}
		h.routesMu.Unlock()
	}
}
