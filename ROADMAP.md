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
- [ ] **ServConsole Administration**: Optional dashboard sync to manage routes, view active connections, and swap WASM middleware modules dynamically.
- [ ] **Distributed Span Mapping**: Trace request lifecycles starting at the gateway, through queues (`ServQueue`), and into storage (`ServStore`) in a unified trace view (optional).

---

## Phase 6: Traffic Replay & Developer Tooling (Completed)
- [x] **Traffic Replay & Validation**: Implement a dry-run utility (`servgate replay`) to replay production traffic logs against new middleware versions before deployment.
- [x] **One-Command Middleware Marketplace**: Install public or private WASM modules via `servgate install <name>` (resolving from `ServRegistry`).
- [x] **Native Serv Language Compilation**: Direct compiler toolchain support in `Serv-lang` to build middleware (`serv build --target wasm`).

---

## Phase 7: Advanced Policies & AI Capabilities
- [x] **AI-Native Gateway Features**: Built-in semantic caching, prompt guard, and PII redaction middlewares.
- [ ] **Policy as Code**: Support compiling human-readable access policies directly to executable WASM policies.
