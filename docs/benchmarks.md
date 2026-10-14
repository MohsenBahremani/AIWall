# Proxy overhead benchmarks

Measured on a local mock upstream (zero simulated provider latency) so numbers isolate AIWall processing cost. Run on your own hardware before quoting externally.

## How to reproduce

```bash
cd AIWall
python scripts/benchmark.py --requests 200 --concurrency 1 --warmup 20
python scripts/benchmark.py --requests 200 --concurrency 8 --warmup 20
python scripts/benchmark.py --json bench-results.json
```

Scenarios:

| Scenario | What it measures |
|---|---|
| `baseline` | Direct `POST /v1/chat/completions` to mock upstream (no AIWall) |
| `proxy-only` | AIWall with empty `policies: []` |
| `scanning` | AIWall + `input.contains_secret` block policy |
| `guardrails` | AIWall + agent shell/file guardrails enabled |

## Results (2026-08-27, Linux, Python 3.12, SQLite audit log)

### Serial load (concurrency = 1)

| Scenario | p50 | p95 | vs baseline | Throughput |
|---|---:|---:|---:|---:|
| baseline | 2.2 ms | 3.2 ms | — | ~420 req/s |
| proxy-only | 13.4 ms | 18.9 ms | **+11 ms** | ~69 req/s |
| scanning | 13.0 ms | 18.9 ms | **+11 ms** | ~72 req/s |
| guardrails | 13.0 ms | 17.0 ms | **+11 ms** | ~72 req/s |

### Concurrent load (concurrency = 8)

| Scenario | p50 | p95 | vs baseline | Throughput |
|---|---:|---:|---:|---:|
| baseline | 21 ms | 62 ms | — | ~280 req/s |
| proxy-only | 91 ms | 127 ms | **+70 ms** | ~84 req/s |
| scanning | 92 ms | 127 ms | **+71 ms** | ~85 req/s |
| guardrails | 88 ms | 133 ms | **+67 ms** | ~85 req/s |

## Takeaways

- **Policy cost is small.** Secret scanning and guardrails add less than 1 ms p50 vs proxy-only at serial load. The baseline proxy path dominates.
- **~11 ms p50 at concurrency 1** is reasonable for a homelab or dev-machine gateway (audit write + policy eval + httpx hop).
- **Throughput capped around 85 req/s** under concurrent load in this August run. That pattern pointed to synchronous SQLite audit commits on the asyncio event loop, not regex scanning. The 2026-10-13 remeasure below is the current number.
- **Do not quote the +70 ms concurrent number as "AIWall latency."** It reflects local SQLite contention under parallel requests, not provider RTT. Real deployments with remote providers (50–500 ms RTT) will see AIWall as a small fraction of total time at low QPS.

## What to tell operators / partners

| Audience | Honest line |
|---|---|
| Homelab / solo dev | "About 10 ms added per request on localhost; negligible vs OpenAI/Ollama RTT." |
| Small team (low QPS) | "Fine for tens of concurrent users if the gateway runs on a dedicated core." |
| High-QPS router vendor | "About 130–140 req/s on this homelab box with queued SQLite writes. Not router-class; Postgres is still Phase 9." |

## Results (2026-10-13, same harness, queued audit writes)

Proxy audit commits now run on a background writer using a direct SQLite insert, so the request handler does not wait on SQLAlchemy. `logging.store: none` skips the audit file for lab runs.

### Concurrent load (concurrency = 8, 200 requests)

| Scenario | p50 | p95 | vs baseline | Throughput |
|---|---:|---:|---:|---:|
| baseline | 20 ms | 55 ms | — | ~318 req/s |
| proxy-only | 48 ms | 147 ms | **+28 ms** | ~127 req/s |
| scanning | 51 ms | 105 ms | **+31 ms** | ~140 req/s |
| guardrails | 53 ms | 83 ms | **+33 ms** | ~143 req/s |

`logging.store: none` on the proxy-only scenario, same concurrency: p50 47 ms, ~141 req/s. That is the same band as queued SQLite. Use `none` when a lab run should not create an audit file, not as a faster production setting.

Serial load stayed in the same range as the August run (about 15 ms p50 for proxy-only at concurrency 1).

## Planned improvements (not measured here)

- Postgres backend (Phase 9) for multi-tenant throughput
