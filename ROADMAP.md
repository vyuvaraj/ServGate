# ServGate Roadmap

This document outlines the planned evolutionary stages of **ServGate** to evolve from a lightweight local proxy into a secure, distributed, WASM-programmable API Gateway.

---

## Core Design Philosophy: Standalone-First (Zero Lock-in)
- **Zero-Dependency Core**: `ServGate` is compiled as a single native binary. It can be run and configured locally using standard JSON files without requiring external databases, brokers, or storage engines.
- **Optional Serv-verse Synergy**: Seamlessly integrates with the wider ecosystem (`ServQueue`, `ServStore`, `ServRegistry`, and `ServConsole`) to offer advanced tracing, marketplaces, and centralized configuration, but keeps all integrations entirely optional.

---

## Phase 1: Core Reverse Proxy & WASM (Completed)
- [x] **Path Routing & Forwarding**: HTTP reverse proxying with route prefix stripping logic.
- [x] **Declarative Configuration**: Route mappings initialized via a local `config.json` schema.
- [x] **Dynamic WASM Middleware**: Admin endpoint to compile and load WASM request filters.
- [x] **OpenTelemetry Tracing**: Trace context propagation (`traceparent`) and JSON-based OTLP span exports.
- [x] **Security Token Auth**: Bearer token authorization checks for routed APIs.

---

## Phase 2: Performance Optimizations & Shared Memory (Completed)
- [x] **WASM Module Caching**: Reuse compiled Wazero modules across requests to eliminate compilation latency.
- [x] **Direct memory passing**: Pass request headers and body buffers directly into guest WASM linear memory to eliminate pipe virtualization overhead.
- [x] **WASM Response Filters**: Support executing WASM transforms on downstream responses before returning them to clients.

---

## Phase 3: Pluggable Protocols & Multiplexing (gRPC & WebSocket) (Completed)
- [x] **gRPC-Web Gateway Transpiler**: Accept HTTP/REST JSON requests and transpile them to binary gRPC calls targeting backend microservices using compiled protobuf definitions.
- [x] **WebSocket Proxying**: Support full-duplex WebSocket connection proxying and tunnel routing.
- [x] **Load Balancing Routing**: Round-robin and least-connections load balancing across multiple backend server targets.

---

## Phase 4: Production Security & Resilience (Completed)
- [x] **Native TLS/HTTPS Termination**: Serve API gateway endpoints over secure TLS sockets.
- [x] **Rate Limiting**: Limit client requests using sliding-window rate limit counters.
- [x] **Circuit Breakers & Retries**: Automatically fail fast or retry backend connections when targets exhibit high latency or error counts.

---

## Phase 5: Ecosystem & Console Integration
- [x] **ServConsole Administration**: Optional dashboard sync to manage routes, view active connections, and swap WASM middleware modules dynamically.
- [x] **Distributed config backend**: Store routes in a ServStore bucket (`serv-config`) instead of local `config.json` for multi-replica deployments with eventual consistency.
- [x] **ServConsole OIDC-aware config sync**: Sign config write operations with shared JWT before persisting to distributed backend.
- [x] **Distributed Span Mapping**: Trace request lifecycles starting at the gateway, through queues (`ServQueue`), and into storage (`ServStore`) in a unified trace view using a shared OTLP collector.

---

## Phase 6: Traffic Replay & Developer Tooling (Completed)
- [x] **Traffic Replay & Validation**: Implement a dry-run utility (`servgate replay`) to replay production traffic logs against new middleware versions before deployment.
- [x] **One-Command Middleware Marketplace**: Install public or private WASM modules via `servgate install <name>` (resolving from `ServRegistry`).
- [x] **Native Serv Language Compilation**: Direct compiler toolchain support in `Serv-lang` to build middleware (`serv build --target wasm`).

---

## Phase 7: Advanced Policies & AI Capabilities
- [x] **AI-Native Gateway Features**: Built-in semantic caching, prompt guard, and PII redaction middlewares.
- [x] **Policy as Code**: Support compiling human-readable access policies directly to executable WASM policies.
- [x] **ServGate → ServQueue Webhook Bridge**: Register routes that publish directly to ServQueue topics on incoming HTTP events. Connects gateway and broker tiers.

---

## Phase 8: Operational Hardening & Cross-Ecosystem Quality (Proposed — Q3 2026)

| # | Item | Effort | Description | Status |
|---|------|--------|-------------|--------|
| 8.1 | **Standardized `/healthz` and `/readyz` endpoints** | Small | Expose health and readiness probes for Kubernetes liveness/readiness checks and ServConsole health aggregation. | [x] |
| 8.2 | **Graceful shutdown on SIGTERM** | Small | Drain in-flight proxy requests and flush OTel spans before exit. Required for zero-downtime k8s rolling updates. | [x] |
| 8.3 | **Standardized error response contract** | Small | Return `{"error": "msg", "code": "ERR_CODE", "trace_id": "..."}` on all admin/proxy errors — consistent with ecosystem convention. | [x] |
| 8.4 | **API versioning (`/v1/` prefix)** | Small | Version the admin API (`/api/v1/admin/...`) before breaking changes accumulate. | [x] |
| 8.5 | **Rate limiting on admin endpoints** | Small | Protect admin/middleware upload routes against abuse — currently unthrottled. | [x] |
| 8.6 | **CI/CD pipeline (GitHub Actions)** | Small | Automated build, test, and format checks on every PR. Currently missing — only Serv-lang has CI. | [x] |
| 8.7 | **WebSocket-based real-time metrics feed** | Medium | Push live connection counts, request rates, and error rates to ServConsole via WebSocket (instead of polling). | [x] |
| 8.8 | **Config hot-reload without restart** | Medium | Watch `config.json` (or ServStore bucket) for changes and apply route updates without restarting the gateway process. | [x] |

---

## Phase 9: Next-Level API Gateway (Proposed — Q4 2026+)

These items take ServGate from a capable reverse proxy to a **category-defining programmable API platform** — competing with Kong, Envoy, and AWS API Gateway.

| # | Item | Effort | Description | Status |
|---|------|--------|-------------|--------|
| 9.1 | **OpenAPI auto-discovery** | Medium | Auto-generate an OpenAPI 3.1 spec from all registered routes — including request/response schemas inferred from Serv-lang type declarations. Serve at `/api/docs`. | [x] |
| 9.2 | **Developer portal (API playground)** | Large | Embedded interactive API explorer (Swagger UI-style) served from the gateway. Developers can try endpoints directly with auth token injection. | [x] |
| 9.3 | **Request/response transformation rules** | Medium | Declarative JSON-path transformations applied to request body or response before forwarding — no WASM needed for simple field mapping/filtering. | [x] |
| 9.4 | **Multi-tenant API key management** | Large | Issue, rotate, and revoke API keys per tenant. Per-key rate limits, usage analytics, and key-scoped route access. Full lifecycle via admin API. | [x] |
| 9.5 | **Canary/blue-green traffic splitting** | Medium | Route a percentage of traffic to a canary backend: `"targets_weighted": [{"url": "v2", "weight": 10}, {"url": "v1", "weight": 90}]`. Gradual rollouts without a service mesh. | [x] |
| 9.6 | **Request validation (JSON Schema)** | Medium | Attach JSON Schema to routes — reject malformed requests at the gateway before they hit backends. Return structured validation errors. | [x] |
| 9.7 | **Response caching (HTTP cache layer)** | Medium | Configurable HTTP response cache with TTL, cache-key rules, and invalidation API. Reduces backend load for idempotent GET routes. | [x] |
| 9.8 | **GraphQL federation proxy** | Large | Route GraphQL queries to multiple Serv backends, merge schemas, and execute federated resolvers. Position ServGate as a GraphQL supergraph router. | [x] |
| 9.9 | **Request logging & audit trail** | Medium | Structured JSONL log of every request/response (method, path, latency, status, trace_id) with configurable per-route toggle. | [x] |
| 9.10 | **Plugin SDK (Go interface)** | Medium | Define a Go interface for plugins: `type Middleware interface { OnRequest(ctx) Response }`. Allows community to build compiled middleware without WASM overhead. | [x] |
| 9.11 | **IP allowlisting/blocklisting** | Small | Per-route or global IP-based access control. CIDR range support. Auto-block on repeated 4xx/5xx from same source. | [x] |
| 9.12 | **Mutual TLS (mTLS) for backends** | Medium | Support client certificate authentication when forwarding to backend services — required for zero-trust service-to-service communication. | [x] |
| 9.13 | **Request queuing & backpressure** | Medium | When backends are overloaded, queue requests in-memory (bounded) and apply backpressure via `429`/`503` with `Retry-After` — prevents cascade failures. | [x] |

---

## Phase 10: Differentiating Factors — What No Other Gateway Offers (Strategic)

These create a **moat** around ServGate — capabilities that Kong, Envoy, AWS API Gateway, and Traefik cannot replicate without fundamental architecture changes.

| # | Item | Effort | Description | Why Nobody Else Can Do This |
|---|------|--------|-------------|----------------------------|
| 10.1 | **MCP (Model Context Protocol) native gateway** | Large | ✅ Done — First-class support for AI agent traffic: route MCP tool calls, apply per-agent rate limiting, track token usage per agent, and provide agent-specific API key scoping. | AI-native from day one. Competitors bolt MCP on as afterthought. |
| 10.2 | **Compiler-aware route registration** | Small | ✅ Done — Dynamic route announcement via /api/v1/routes/register endpoint. Serv-lang services self-announce routes at startup. | Tight compiler→gateway integration. Impossible when gateway and language are separate products. |
| 10.3 | **WASM middleware hot-swap without request drops** | Medium | ✅ Done — Upload new WASM middleware while serving live traffic — existing in-flight requests finish with old logic, new requests use new logic. Zero-downtime middleware deploys. | WASM module isolation + request-level binding. Envoy needs full pod restart for filter changes. |
| 10.4 | **Semantic API caching (AI-aware)** | Medium | Cache semantically similar AI requests — "summarize this document" and "give me a summary of this doc" hit the same cache entry via embedding similarity, not URL matching. Already partially implemented. | Requires AI understanding at the gateway layer. Traditional gateways cache by exact URL/header match only. |
| 10.5 | **Cost-aware LLM routing** | Medium | ✅ Done — Route AI requests to cheaper model GPT-4o-mini first, escalate to premium model GPT-4 if response confidence is below threshold. | Purpose-built for AI backend routing. Generic gateways have no concept of model cost/quality tradeoff. |
| 10.6 | **Inline request transformation via WASM** | Small | Mutate request/response bodies in sandboxed WASM without sidecar overhead. The WASM filter runs inside the gateway process — no network hop to a transformation service. Already done — but unique in the market. | Pure-Go WASM runtime (wazero) = no CGO, no Lua, no external process. Sub-millisecond transform latency. |
| 10.7 | **Policy-as-code with `.policy` → WASM compilation** | Medium | Write human-readable access policies, compile to WASM, execute at wire speed. No Rego interpreter, no sidecar OPA process. Policy IS the binary. | Language-level compilation of policies. OPA/Rego is interpreted. ServGate compiles policies to native speed. |
| 10.8 | **ServQueue webhook bridge (event gateway)** | Small | A single route declaration can simultaneously proxy to a backend AND publish to a message queue topic. The gateway becomes an event sourcing entry point — not just a proxy. Already done. | Combined proxy + event sourcing in one hop. Other gateways need a separate webhook relay service. |
| 10.9 | **Per-route WASM A/B testing** | Medium | ✅ Done — Attach two WASM middleware versions to a route with configured traffic split weight. | WASM sandboxing enables safe side-by-side execution of untrusted code in the same process. |
| 10.10 | **Automatic PII detection & redaction** | Small | Built-in regex + NER-based PII scanner that redacts sensitive data from request/response logs before they hit the observability layer. Already partially implemented. | AI-native gateway understands data sensitivity. Traditional gateways log everything or nothing. |

> See [UNIFIED_ROADMAP.md](../UNIFIED_ROADMAP.md) for the full ecosystem priority matrix and architectural recommendations.
