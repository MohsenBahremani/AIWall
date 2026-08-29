#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Measure AIWall proxy overhead against a local mock upstream.

Runs the mock provider, AIWall, and the load generator as separate processes so
none of them contend for the same interpreter. Reports per-scenario latency
percentiles and the delta against a direct-to-upstream baseline.

Usage::

    python scripts/benchmark.py
    python scripts/benchmark.py --requests 500 --concurrency 16
    python scripts/benchmark.py --scenarios baseline,proxy-only,scanning
    python scripts/benchmark.py --json results.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"

PROMPT = (
    "Summarize the following deployment note in two sentences. "
    "The service runs behind a reverse proxy, uses a connection pool of 20, "
    "and rotates credentials weekly via the secrets manager."
)

BASELINE = "baseline"

SCENARIO_YAML: dict[str, str] = {
    "proxy-only": "policies: []",
    "scanning": """policies:
  - name: block-secrets
    when: input.contains_secret
    action: block""",
    "guardrails": """policies: []
agent_guardrails:
  enabled: true
  approval_timeout_seconds: 60
  shell:
    warn_above: 40
    block_above: 70
    require_approval_above: 90""",
}

SCENARIO_ORDER = [BASELINE, "proxy-only", "scanning", "guardrails"]

SCENARIO_LABELS = {
    BASELINE: "Direct to upstream (no AIWall)",
    "proxy-only": "AIWall, no policies",
    "scanning": "AIWall + secret scanning",
    "guardrails": "AIWall + agent guardrails",
}


# --------------------------------------------------------------------------
# Mock upstream
# --------------------------------------------------------------------------


def build_mock_upstream(delay_ms: float) -> FastAPI:
    """An OpenAI-compatible provider that answers instantly (or after a delay)."""
    api = FastAPI()
    delay_seconds = delay_ms / 1000.0

    completion = {
        "id": "chatcmpl-bench",
        "object": "chat.completion",
        "model": "gpt-4o-mini",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "Benchmark response."},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 48, "completion_tokens": 6, "total_tokens": 54},
    }

    @api.get("/v1/models")
    async def models() -> dict[str, object]:
        return {"object": "list", "data": [{"id": "gpt-4o-mini", "object": "model"}]}

    @api.post("/v1/chat/completions")
    async def chat(request: Request):
        payload = await request.json()
        if delay_seconds:
            await asyncio.sleep(delay_seconds)
        if not payload.get("stream"):
            return JSONResponse(completion)

        async def event_stream():
            for token in ("Bench", "mark", " response."):
                chunk = {
                    "id": "chatcmpl-bench",
                    "object": "chat.completion.chunk",
                    "choices": [{"index": 0, "delta": {"content": token}}],
                }
                yield f"data: {json.dumps(chunk)}\n\n".encode()
            yield b"data: [DONE]\n\n"

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    return api


def serve_upstream(port: int, delay_ms: float) -> None:
    import uvicorn

    uvicorn.run(
        build_mock_upstream(delay_ms),
        host="127.0.0.1",
        port=port,
        log_level="error",
        access_log=False,
    )


# --------------------------------------------------------------------------
# Process helpers
# --------------------------------------------------------------------------


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def wait_for_http(url: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    async with httpx.AsyncClient(timeout=2.0) as client:
        while time.monotonic() < deadline:
            try:
                response = await client.get(url)
                if response.status_code < 500:
                    return
            except httpx.RequestError:
                pass
            await asyncio.sleep(0.1)
    raise RuntimeError(f"timed out waiting for {url}")


def write_config(directory: Path, scenario: str, upstream_port: int) -> Path:
    config_path = directory / "aiwall.yaml"
    db_path = directory / "bench.db"
    body = SCENARIO_YAML[scenario]
    config_path.write_text(
        f"""server:
  host: 127.0.0.1
  port: 8080
providers:
  - name: bench
    type: openai-compatible
    base_url: http://127.0.0.1:{upstream_port}/v1
    api_key_env: AIWALL_BENCH_KEY
    models: ["gpt-*"]
{body}
logging:
  store: sqlite:///{db_path.as_posix()}
  log_raw_prompts: false
""",
        encoding="utf-8",
    )
    (directory / "prices.yaml").write_text(
        """models:
  bench:
    gpt-4o-mini:
      input_per_million: 0.15
      output_per_million: 0.60
""",
        encoding="utf-8",
    )
    return config_path


def start_aiwall(config_path: Path, port: int) -> subprocess.Popen[bytes]:
    env = dict(os.environ)
    env["AIWALL_CONFIG"] = str(config_path)
    env["AIWALL_BENCH_KEY"] = "bench-upstream-key"
    env["AIWALL_SKIP_DOTENV"] = "1"
    env["PYTHONPATH"] = f"{BACKEND}{os.pathsep}{env.get('PYTHONPATH', '')}".rstrip(os.pathsep)
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "error",
            "--no-access-log",
        ],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def start_upstream(port: int, delay_ms: float) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--serve-upstream", str(port),
         "--upstream-delay", str(delay_ms)],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def stop(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


# --------------------------------------------------------------------------
# Load generation
# --------------------------------------------------------------------------


@dataclass
class Result:
    scenario: str
    latencies_ms: list[float] = field(default_factory=list)
    ttfb_ms: list[float] = field(default_factory=list)
    errors: int = 0
    wall_seconds: float = 0.0

    @property
    def throughput(self) -> float:
        return len(self.latencies_ms) / self.wall_seconds if self.wall_seconds else 0.0


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


def payload(stream: bool) -> dict[str, object]:
    return {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": PROMPT}],
        "stream": stream,
    }


async def run_load(
    base_url: str,
    *,
    requests: int,
    concurrency: int,
    warmup: int,
    scenario: str,
    stream: bool,
) -> Result:
    result = Result(scenario=scenario)
    limits = httpx.Limits(max_connections=concurrency * 2, max_keepalive_connections=concurrency * 2)
    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(base_url=base_url, timeout=60.0, limits=limits) as client:
        for _ in range(warmup):
            try:
                await client.post("/v1/chat/completions", json=payload(False))
            except httpx.RequestError:
                pass

        async def one() -> None:
            async with semaphore:
                started = time.perf_counter()
                try:
                    if stream:
                        first: float | None = None
                        async with client.stream(
                            "POST", "/v1/chat/completions", json=payload(True)
                        ) as response:
                            async for _chunk in response.aiter_bytes():
                                if first is None:
                                    first = time.perf_counter()
                            if response.status_code >= 400:
                                result.errors += 1
                                return
                        if first is not None:
                            result.ttfb_ms.append((first - started) * 1000.0)
                    else:
                        response = await client.post("/v1/chat/completions", json=payload(False))
                        if response.status_code >= 400:
                            result.errors += 1
                            return
                except httpx.RequestError:
                    result.errors += 1
                    return
                result.latencies_ms.append((time.perf_counter() - started) * 1000.0)

        wall_start = time.perf_counter()
        await asyncio.gather(*(one() for _ in range(requests)))
        result.wall_seconds = time.perf_counter() - wall_start

    return result


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------


async def measure_scenario(
    scenario: str,
    *,
    upstream_port: int,
    requests: int,
    concurrency: int,
    warmup: int,
    stream: bool,
) -> Result:
    if scenario == BASELINE:
        return await run_load(
            f"http://127.0.0.1:{upstream_port}",
            requests=requests,
            concurrency=concurrency,
            warmup=warmup,
            scenario=scenario,
            stream=stream,
        )

    with tempfile.TemporaryDirectory(prefix=f"aiwall-bench-{scenario}-") as tmp:
        directory = Path(tmp)
        config_path = write_config(directory, scenario, upstream_port)
        port = free_port()
        process = start_aiwall(config_path, port)
        try:
            await wait_for_http(f"http://127.0.0.1:{port}/healthz")
            return await run_load(
                f"http://127.0.0.1:{port}",
                requests=requests,
                concurrency=concurrency,
                warmup=warmup,
                scenario=scenario,
                stream=stream,
            )
        finally:
            stop(process)


def render(results: list[Result], stream: bool) -> str:
    baseline = next((r for r in results if r.scenario == BASELINE), None)
    base_p50 = percentile(baseline.latencies_ms, 0.50) if baseline else 0.0

    lines = [
        "",
        "latency in milliseconds",
        f"{'scenario':<26} {'n':>5} {'p50':>8} {'p95':>8} {'p99':>8} {'req/s':>7} {'p50 vs base':>12}",
        "-" * 82,
    ]
    for result in results:
        p50 = percentile(result.latencies_ms, 0.50)
        delta = f"{p50 - base_p50:+.2f}" if baseline and result.scenario != BASELINE else "-"
        lines.append(
            f"{result.scenario:<26} {len(result.latencies_ms):>5} "
            f"{p50:>8.2f} {percentile(result.latencies_ms, 0.95):>8.2f} "
            f"{percentile(result.latencies_ms, 0.99):>8.2f} "
            f"{result.throughput:>7.0f} {delta:>12}"
        )
    if stream:
        lines += [
            "",
            "time to first SSE byte in milliseconds",
            f"{'scenario':<26} {'p50':>8} {'p95':>8}",
            "-" * 44,
        ]
        for result in results:
            lines.append(
                f"{result.scenario:<26} {percentile(result.ttfb_ms, 0.50):>8.2f} "
                f"{percentile(result.ttfb_ms, 0.95):>8.2f}"
            )
    errors = sum(r.errors for r in results)
    if errors:
        lines.append(f"\nerrors: {errors}")
    lines.append("")
    return "\n".join(lines)


async def main_async(args: argparse.Namespace) -> int:
    scenarios = [s.strip() for s in args.scenarios.split(",") if s.strip()]
    unknown = [s for s in scenarios if s != BASELINE and s not in SCENARIO_YAML]
    if unknown:
        print(f"unknown scenarios: {', '.join(unknown)}", file=sys.stderr)
        return 2

    upstream_port = free_port()
    upstream = start_upstream(upstream_port, args.upstream_delay)
    results: list[Result] = []
    try:
        await wait_for_http(f"http://127.0.0.1:{upstream_port}/v1/models")
        print(
            f"mock upstream on :{upstream_port} (delay {args.upstream_delay} ms) — "
            f"{args.requests} requests x {args.concurrency} concurrent"
        )
        for scenario in scenarios:
            print(f"  running {scenario} …", flush=True)
            results.append(
                await measure_scenario(
                    scenario,
                    upstream_port=upstream_port,
                    requests=args.requests,
                    concurrency=args.concurrency,
                    warmup=args.warmup,
                    stream=args.stream,
                )
            )
    finally:
        stop(upstream)

    print(render(results, args.stream))

    if args.json:
        payload_out = {
            "requests": args.requests,
            "concurrency": args.concurrency,
            "upstream_delay_ms": args.upstream_delay,
            "stream": args.stream,
            "scenarios": [
                {
                    "scenario": r.scenario,
                    "label": SCENARIO_LABELS.get(r.scenario, r.scenario),
                    "completed": len(r.latencies_ms),
                    "errors": r.errors,
                    "p50_ms": round(percentile(r.latencies_ms, 0.50), 3),
                    "p95_ms": round(percentile(r.latencies_ms, 0.95), 3),
                    "p99_ms": round(percentile(r.latencies_ms, 0.99), 3),
                    "mean_ms": round(statistics.fmean(r.latencies_ms), 3)
                    if r.latencies_ms
                    else 0.0,
                    "throughput_rps": round(r.throughput, 1),
                }
                for r in results
            ],
        }
        Path(args.json).write_text(json.dumps(payload_out, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {args.json}")

    return 1 if any(r.errors for r in results) else 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve-upstream", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--requests", type=int, default=300)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument(
        "--upstream-delay",
        type=float,
        default=0.0,
        help="Simulated provider latency in ms (0 isolates AIWall overhead)",
    )
    parser.add_argument("--scenarios", default=",".join(SCENARIO_ORDER))
    parser.add_argument("--stream", action="store_true", help="Measure SSE time-to-first-byte")
    parser.add_argument("--json", help="Write machine-readable results to this path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.serve_upstream:
        serve_upstream(args.serve_upstream, args.upstream_delay)
        return 0
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
