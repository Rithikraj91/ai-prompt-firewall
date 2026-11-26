import os
import re
import time
from collections import deque
from urllib.parse import urlparse
from fastapi import HTTPException, Request

# 1. Secrets Redaction Patterns (prevents leaking keys into SQLite / SSE logs)
SECRET_PATTERNS = [
    (re.compile(r"\b(sk-[A-Za-z0-9_-]{16,})\b"), "[REDACTED_OPENAI_KEY]"),
    (re.compile(r"\b(gsk_[A-Za-z0-9_-]{16,})\b"), "[REDACTED_GROQ_KEY]"),
    (re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9._-]{16,}"), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"\b(CANARY_[A-Za-z0-9_-]{8,})\b"), "[REDACTED_CANARY]"),
]


def redact_secrets(text: str) -> str:
    if not text:
        return text
    cleaned = text
    for pattern, mask in SECRET_PATTERNS:
        cleaned = pattern.sub(mask, cleaned)
    return cleaned


# 2. Gateway Policy Configuration
def get_gateway_policy() -> dict:
    raw_keys = os.getenv("ATTROXX_API_KEYS", "").strip()
    configured_keys = [k.strip() for k in raw_keys.split(",") if k.strip()]
    failure_mode = os.getenv("ATTROXX_FAILURE_MODE", "fail_closed").strip().lower()
    if failure_mode not in {"fail_closed", "fail_open"}:
        failure_mode = "fail_closed"

    rpm = int(os.getenv("ATTROXX_RATE_LIMIT_RPM", "120"))
    allowed_hosts = [
        h.strip().lower()
        for h in os.getenv(
            "ATTROXX_ALLOWED_UPSTREAMS",
            "api.groq.com,api.openai.com,localhost,127.0.0.1",
        ).split(",")
        if h.strip()
    ]

    return {
        "auth_enforced": len(configured_keys) > 0,
        "active_key_count": len(configured_keys),
        "failure_mode": failure_mode,
        "rate_limit_rpm": rpm,
        "allowed_upstreams": allowed_hosts,
    }


# 3. Upstream SSRF / Allowlist Validation
def validate_upstream_url(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    policy = get_gateway_policy()
    if host in {"localhost", "127.0.0.1"}:
        return parsed.scheme in {"http", "https"}
    return parsed.scheme == "https" and host in policy["allowed_upstreams"]


# 4. API Key Authentication
def verify_gateway_auth(request: Request) -> str:
    raw_keys = os.getenv("ATTROXX_API_KEYS", "").strip()
    configured_keys = [k.strip() for k in raw_keys.split(",") if k.strip()]

    # Allow local dev console when ATTROXX_API_KEYS is unset
    if not configured_keys:
        return "local-dev-client"

    auth_header = request.headers.get("Authorization", "")
    api_key = ""
    if auth_header.lower().startswith("bearer "):
        api_key = auth_header[7:].strip()
    elif request.headers.get("X-API-Key"):
        api_key = request.headers.get("X-API-Key", "").strip()

    if not api_key or api_key not in configured_keys:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: missing or invalid ATTROXX gateway API key.",
        )
    return f"key:{api_key[:6]}..."


# 5. Sliding-Window Rate Limiter (per API key / client IP)
_REQUEST_LOG: dict[str, deque[float]] = {}


def enforce_rate_limit(request: Request, client_id: str) -> dict:
    rpm = int(os.getenv("ATTROXX_RATE_LIMIT_RPM", "120"))
    now = time.monotonic()
    window = 60.0

    ip = request.client.host if request.client else "unknown"
    bucket_key = f"{client_id}:{ip}"
    timestamps = _REQUEST_LOG.setdefault(bucket_key, deque())

    while timestamps and (now - timestamps[0]) > window:
        timestamps.popleft()

    if len(timestamps) >= rpm:
        retry_after = max(1, int(window - (now - timestamps[0])))
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({rpm} req/min). Retry in {retry_after}s.",
            headers={"Retry-After": str(retry_after)},
        )

    timestamps.append(now)
    return {
        "limit": rpm,
        "remaining": max(0, rpm - len(timestamps)),
    }
