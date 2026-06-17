# ServGate Roadmap

This document outlines the planned evolutionary stages of **ServGate** to evolve from a lightweight local proxy into a secure, distributed, WASM-programmable API Gateway.

---

## Phase 1: Core Reverse Proxy & WASM (Completed)
- [x] **Path Routing & Forwarding**: HTTP reverse proxying with route prefix stripping logic.
- [x] **Declarative Configuration**: Route mappings initialized via a local `config.json` schema.
- [x] **Dynamic WASM Middleware**: Admin endpoint to compile and load WASM request filters.
- [x] **OpenTelemetry Tracing**: Trace context propagation (`traceparent`) and JSON-based OTLP span exports.
- [x] **Security Token Auth**: Bearer token authorization checks for routed APIs.

---

## Phase 2: Performance Optimizations & Shared Memory
- [x] **WASM Module Caching**: Reuse compiled Wazero modules across requests to eliminate compilation latency.
- [x] **Direct memory passing**: Pass request headers and body buffers directly into guest WASM linear memory to eliminate pipe virtualization overhead.
- [x] **WASM Response Filters**: Support executing WASM transforms on downstream responses before returning them to clients.

---

## Phase 3: Pluggable Protocols & Multiplexing (gRPC & WebSocket)
- [ ] **gRPC-Web Gateway Transpiler**: Accept HTTP/REST JSON requests and transpile them to binary gRPC calls targeting backend microservices using compiled protobuf definitions.
- [ ] **WebSocket Proxying**: Support full-duplex WebSocket connection proxying and tunnel routing.
- [ ] **Load Balancing Routing**: Round-robin and least-connections load balancing across multiple backend server targets.

---

## Phase 4: Production Security & Resilience
- [x] **Native TLS/HTTPS Termination**: Serve API gateway endpoints over secure TLS sockets.
- [x] **Rate Limiting**: Limit client requests using sliding-window rate limit counters.
- [x] **Circuit Breakers & Retries**: Automatically fail fast or retry backend connections when targets exhibit high latency or error counts.

---

## Phase 5: Ecosystem & Console Integration
- [ ] **ServConsole Administration**: Manage routes, view active connections, and swap WASM middleware modules dynamically via the unified dashboard interface.
- [ ] **Distributed Span Mapping**: Track request lifecycles starting at the gateway, through queues (`ServQueue`), and into storage (`ServStore`) in a unified trace view.
