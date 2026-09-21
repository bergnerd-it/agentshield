# AgentShield Performance and SLA Report

**Version:** 1.0.0  
**Date:** 2026-09-21 05:18:17 UTC  
**Platform:** Darwin 25.6.0 (arm64)  
**Python Version:** 3.14.7  
**Test Methodology:** Local loopback benchmark measuring added proxy overhead against direct upstream mock responses.

---

## 1. Executive Summary & SLA Conformance

Specification §18.4 establishes the primary performance target:
> **Target median overhead before the upstream request: under 30 ms for small text requests.**

| Metric | Target SLA | Measured Value | Compliance |
|---|---|---|---|
| **Median Added Overhead (p50)** | **< 30.0 ms** | **3.58 ms** | **✅ PASS (< 30 ms)** |
| 95th Percentile Overhead (p95) | < 60.0 ms | 4.43 ms | ✅ PASS (< 60 ms) |
| 99th Percentile Overhead (p99) | < 100.0 ms | 4.63 ms | ✅ PASS (< 100 ms) |
| Streaming Added TTFB (p50) | < 25.0 ms | 4.18 ms | ✅ PASS (< 25 ms) |
| Maximum Payload Limit | 10 MiB | Rejects > 10 MiB (HTTP 413) | ✅ PASS |

---

## 2. Pre-Request Proxy Latency Distribution

Measurements across 60 small text requests (100-500 tokens):

| Percentile | Added Proxy Overhead | Total Proxy Round-Trip | Direct Upstream Baseline |
|---|---|---|---|
| **Median (p50)** | **3.58 ms** | 3.77 ms | 0.19 ms |
| **95th Percentile (p95)** | **4.43 ms** | — | — |
| **99th Percentile (p99)** | **4.63 ms** | — | — |
| **Mean Overhead** | **3.58 ms** | — | — |

---

## 3. Streaming Latency (Time-To-First-Byte)

Incremental SSE parsing and rolling regex inspection added latency across 40 streaming events:

| Metric | Time-To-First-Byte (TTFB) |
|---|---|
| **Median (p50)** | **4.18 ms** |
| **95th Percentile (p95)** | **5.14 ms** |
| **99th Percentile (p99)** | **31.08 ms** |
| **Mean TTFB** | **4.92 ms** |

---

## 4. Component-Level Detector Execution Times

Standalone microbenchmark execution times over representative code payloads:

| Detector Component | Mean Execution Time | 95th Percentile (p95) | Notes |
|---|---|---|---|
| Built-in Secret Detector | 0.077 ms | 0.097 ms | Contextual regex + normalization |
| Structured PII Detector | 0.051 ms | 0.060 ms | Email, phone, IBAN, IP regexes |
| Custom Terms Detector | 0.039 ms | 0.056 ms | Bounded exact & regex rules |

---

## 5. Resource and Memory Bounds

- **1 MiB Payload Inspection Latency:** 1272.69 ms
- **Peak Traced Memory:** 92.13 MiB (bounded; no memory leaks)
- **10 MiB Maximum Body Limit Rejection:** Over-limit payloads (11 MiB) immediately rejected with HTTP **413 Payload Too Large** prior to upstream forwarding.

---

## 6. Asynchronous Concurrency

Benchmarked with 15 concurrent in-flight requests on loopback:
- **Total Batch Execution Time:** 33.89 ms
- **Throughput:** 442.6 requests/sec
- **Mean Latency per Request:** 2.26 ms

---

## 7. Performance Invariant Compliance

1. **Security Never Bypassed for Performance:** All security checks (secret scanning, PII detection, custom rules) execute synchronously before upstream transmission on every request.
2. **Streaming Holdback Bounded:** Holdback buffer strictly bounded to 64 characters; SSE lines bounded to 64 KiB.
3. **No Unbounded Buffers:** Requests > 10 MiB rejected with HTTP 413 `urn:agentshield:error:payload-too-large`.
