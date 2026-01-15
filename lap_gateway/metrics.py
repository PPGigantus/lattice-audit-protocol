"""Prometheus metrics for LAP Gateway (optional).

This module is designed to be safe even if prometheus_client is not installed.
If prometheus_client is missing, all functions become no-ops.

Metrics goals:
- low-cardinality labels (avoid user/tool params)
- internal observability for decisions, denials, replay, budgets, rate limits
"""
from __future__ import annotations

import os
import time
from typing import Callable, Optional

PROM_AVAILABLE = False
try:
    from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST  # type: ignore
    PROM_AVAILABLE = True
except Exception:  # pragma: no cover
    Counter = Histogram = Gauge = None  # type: ignore
    generate_latest = None  # type: ignore
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4"


def _env_bool(name: str, default: bool = True) -> bool:
    v = (os.getenv(name, "") or "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "on")


# ---------------------------
# Core metric objects
# ---------------------------
if PROM_AVAILABLE:
    HTTP_REQUESTS_TOTAL = Counter(
        "lap_http_requests_total",
        "Total HTTP requests received",
        ["method", "route", "status"],
    )
    HTTP_REQUEST_LATENCY_SECONDS = Histogram(
        "lap_http_request_latency_seconds",
        "HTTP request latency in seconds",
        ["method", "route"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
    )
    DECISIONS_TOTAL = Counter(
        "lap_decisions_total",
        "Total policy decisions",
        ["tier", "outcome"],
    )
    INVOCATIONS_TOTAL = Counter(
        "lap_tool_invocations_total",
        "Total tool invocations attempted",
        ["tool", "outcome", "tier"],
    )
    RATE_LIMIT_REJECT_TOTAL = Counter(
        "lap_rate_limit_reject_total",
        "Total rate-limit rejections",
        ["endpoint"],
    )
    REPLAY_REJECT_TOTAL = Counter(
        "lap_replay_reject_total",
        "Total replay/counter/nonce rejections",
        ["reason"],
    )
    LOCKDOWN_ACTIVE = Gauge(
        "lap_lockdown_active",
        "1 if gateway is in lockdown / fail-closed mode",
    )
else:  # pragma: no cover
    HTTP_REQUESTS_TOTAL = HTTP_REQUEST_LATENCY_SECONDS = DECISIONS_TOTAL = None
    INVOCATIONS_TOTAL = RATE_LIMIT_REJECT_TOTAL = REPLAY_REJECT_TOTAL = LOCKDOWN_ACTIVE = None


def record_decision(tier: str, outcome: str) -> None:
    if PROM_AVAILABLE and DECISIONS_TOTAL is not None:
        DECISIONS_TOTAL.labels(tier=str(tier), outcome=str(outcome)).inc()


def record_invocation(tool: str, outcome: str, tier: str) -> None:
    if PROM_AVAILABLE and INVOCATIONS_TOTAL is not None:
        INVOCATIONS_TOTAL.labels(tool=str(tool), outcome=str(outcome), tier=str(tier)).inc()


def record_rate_limited(endpoint: str) -> None:
    if PROM_AVAILABLE and RATE_LIMIT_REJECT_TOTAL is not None:
        RATE_LIMIT_REJECT_TOTAL.labels(endpoint=str(endpoint)).inc()


def record_replay_reject(reason: str) -> None:
    if PROM_AVAILABLE and REPLAY_REJECT_TOTAL is not None:
        REPLAY_REJECT_TOTAL.labels(reason=str(reason)).inc()


def set_lockdown_active(active: bool) -> None:
    if PROM_AVAILABLE and LOCKDOWN_ACTIVE is not None:
        LOCKDOWN_ACTIVE.set(1.0 if active else 0.0)


def instrument_fastapi(app, authorize: Optional[Callable] = None) -> None:
    """Attach /metrics endpoint and request middleware to a FastAPI app.

    authorize: callable(request) -> bool. If provided and returns False, /metrics returns 403.
    """
    if not PROM_AVAILABLE:
        return
    if not _env_bool("LAP_METRICS_ENABLED", True):
        return

    # Middleware for HTTP request metrics
    @app.middleware("http")
    async def _metrics_middleware(request, call_next):
        start = time.time()
        try:
            response = await call_next(request)
            return response
        finally:
            try:
                route = getattr(request, "scope", {}).get("route") if hasattr(request, "scope") else None
                route_path = None
                if route is not None and hasattr(route, "path"):
                    route_path = route.path
                if not route_path:
                    route_path = request.url.path
                method = request.method
                status = getattr(locals().get("response", None), "status_code", 500)
                HTTP_REQUESTS_TOTAL.labels(method=method, route=route_path, status=str(status)).inc()
                HTTP_REQUEST_LATENCY_SECONDS.labels(method=method, route=route_path).observe(time.time() - start)
            except Exception:
                # metrics must never break the app
                pass

    @app.get("/metrics")
    async def metrics_endpoint(request):  # type: ignore
        if authorize is not None:
            try:
                ok = authorize(request)
            except Exception:
                ok = False
            if not ok:
                # avoid leaking existence details
                return app.response_class(status_code=403, content="FORBIDDEN")  # type: ignore
        data = generate_latest()  # type: ignore
        return app.response_class(content=data, media_type=CONTENT_TYPE_LATEST)  # type: ignore
