import asyncio
import io
import json
import os
from contextlib import asynccontextmanager

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from app.layers.rag_scanner import inspect_rag_document

from app.database import get_recent_logs, init_db, log_event
from app.layers.L2_classifier import load_onnx_classifier
from app.layers.egress import (
    generate_canary_token,
    inject_canary_into_messages,
    scan_egress_output,
)
from app.pipeline import run_security_pipeline
from app.security import (
    enforce_rate_limit,
    get_gateway_policy,
    redact_secrets,
    validate_upstream_url,
    verify_gateway_auth,
)

load_dotenv()

TARGET_LLM_URL = os.getenv("TARGET_LLM_URL", "https://api.groq.com/openai/v1/chat/completions")
TARGET_LLM_API_KEY = os.getenv("TARGET_LLM_API_KEY", "")
TARGET_MODEL = os.getenv("TARGET_MODEL", "openai/gpt-oss-20b")

event_subscribers: list[asyncio.Queue] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    load_onnx_classifier()
    yield


app = FastAPI(title="ATTROXX Runtime AI Firewall", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str | None = None
    messages: list[ChatMessage]
    source: str = "playground"
    force_judge: bool = False


async def broadcast_event(event: dict):
    for queue in list(event_subscribers):
        await queue.put(event)


def sanitize_telemetry(inspection: dict) -> dict:
    """Redacts API keys/tokens before persisting to SQLite or streaming over SSE."""
    clean = dict(inspection)
    if "raw_prompt" in clean:
        clean["raw_prompt"] = redact_secrets(clean["raw_prompt"])
    if "normalized_prompt" in clean:
        clean["normalized_prompt"] = redact_secrets(clean["normalized_prompt"])
    return clean


@app.get("/health")
async def health_check():
    policy = get_gateway_policy()
    return {
        "status": "online",
        "proxy": "ATTROXX v2.0",
        "policy": policy,
        "upstream_valid": validate_upstream_url(TARGET_LLM_URL),
    }


@app.get("/v1/gateway-policy")
async def gateway_policy_endpoint():
    return get_gateway_policy()


@app.get("/v1/benchmarks")
async def get_benchmark_results():
    bench_file = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "latest_results.json")
    if not os.path.exists(bench_file):
        return {"available": False}
    with open(bench_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    data["available"] = True
    return data


@app.post("/v1/chat/completions")
async def proxy_chat_completions(req: ChatCompletionRequest, request: Request):
    client_id = verify_gateway_auth(request)
    rl = enforce_rate_limit(request, client_id)
    policy = get_gateway_policy()

    user_messages = [m.content for m in req.messages if m.role == "user"]
    latest_prompt = user_messages[-1] if user_messages else ""

    try:
        inspection = await run_security_pipeline(latest_prompt, force_judge=req.force_judge)
    except Exception as exc:
        if policy["failure_mode"] == "fail_closed":
            raise HTTPException(
                status_code=503,
                detail=f"ATTROXX Fail-Closed Policy: inspection pipeline unavailable ({type(exc).__name__})",
            )
        inspection = {
            "raw_prompt": latest_prompt,
            "normalized_prompt": latest_prompt,
            "verdict": "ALLOWED",
            "risk_score": 0.0,
            "blocked_layer": None,
            "category": "Fail-Open Bypass",
            "total_latency_ms": 0.1,
            "stages": [],
        }

    inspection["source"] = req.source
    clean_inspection = sanitize_telemetry(inspection)

    if inspection["verdict"] == "BLOCKED":
        saved_event = await log_event(clean_inspection)
        await broadcast_event(saved_event)
        return JSONResponse(
            status_code=403,
            headers={"X-RateLimit-Remaining": str(rl["remaining"])},
            content={
                "error": {
                    "message": f"Prompt blocked by {inspection['blocked_layer']} ({inspection['category']})",
                    "type": "prompt_injection_detected",
                },
                "security_telemetry": saved_event,
            },
        )

    canary = generate_canary_token()
    protected_messages = inject_canary_into_messages(
        [m.model_dump() for m in req.messages], canary
    )

    data = None
    if TARGET_LLM_API_KEY:
        if not validate_upstream_url(TARGET_LLM_URL):
            raise HTTPException(
                status_code=502,
                detail="Blocked upstream connection: TARGET_LLM_URL is not in ATTROXX_ALLOWED_UPSTREAMS.",
            )
        headers = {
            "Authorization": f"Bearer {TARGET_LLM_API_KEY}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": req.model or TARGET_MODEL,
            "messages": protected_messages,
        }
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                llm_res = await client.post(TARGET_LLM_URL, headers=headers, json=payload)
                if llm_res.status_code == 200:
                    data = llm_res.json()
        except Exception:
            data = None

    if data is None:
        data = {
            "id": "chatcmpl-attroxx-demo",
            "object": "chat.completion",
            "model": req.model or TARGET_MODEL,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"[ATTROXX Gateway Verified Safe] Prompt passed all 4 security layers with canary token {canary[:8]}... sealed. (Configure a valid TARGET_LLM_API_KEY in backend/.env for live upstream model generation.)",
                    },
                    "finish_reason": "stop",
                }
            ],
        }

    assistant_reply = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    egress_check = scan_egress_output(assistant_reply, canary)

    if egress_check["blocked"]:
        clean_inspection["verdict"] = "BLOCKED"
        clean_inspection["risk_score"] = 1.0
        clean_inspection["blocked_layer"] = "Egress Guard (Canary/Leak)"
        clean_inspection["category"] = "Data / Prompt Exfiltration"
        if clean_inspection.get("stages"):
            clean_inspection["stages"][-1] = {
                "name": "L3: Judge & Egress Guard",
                "status": "BLOCK",
                "latency_ms": 0.2,
                "detail": egress_check["reason"],
            }
        saved_event = await log_event(clean_inspection)
        await broadcast_event(saved_event)
        return JSONResponse(
            status_code=403,
            headers={"X-RateLimit-Remaining": str(rl["remaining"])},
            content={
                "error": {
                    "message": egress_check["reason"],
                    "type": "egress_security_violation",
                },
                "security_telemetry": saved_event,
            },
        )

    saved_event = await log_event(clean_inspection)
    await broadcast_event(saved_event)
    data["security_telemetry"] = saved_event
    return JSONResponse(
        status_code=200,
        headers={"X-RateLimit-Remaining": str(rl["remaining"])},
        content=data,
    )


@app.post("/v1/scan-document")
async def scan_rag_document(request: Request, file: UploadFile = File(...)):
    """Scans PDF metadata & overlapping text chunks for Indirect RAG Prompt Injections."""
    client_id = verify_gateway_auth(request)
    enforce_rate_limit(request, client_id)

    raw_bytes = await file.read()
    filename = file.filename or "uploaded_doc"

    scan_result = await inspect_rag_document(raw_bytes, filename)
    if scan_result.get("extraction_error"):
        raise HTTPException(
            status_code=scan_result.get("status_code", 400),
            detail=scan_result["extraction_error"],
        )

    inspection = scan_result["inspection"]
    clean_inspection = sanitize_telemetry(inspection)
    saved_event = await log_event(clean_inspection)
    await broadcast_event(saved_event)

    if inspection["verdict"] == "BLOCKED":
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": f"Indirect injection detected inside '{filename}' by {inspection['blocked_layer']}",
                    "type": "indirect_rag_injection",
                },
                "chunks_scanned": scan_result["chunks_scanned"],
                "page_count": scan_result["page_count"],
                "extracted_preview": redact_secrets(scan_result["extracted_preview"]),
                "security_telemetry": saved_event,
            },
        )

    return {
        "status": "SAFE_FOR_RAG",
        "filename": filename,
        "chunks_scanned": scan_result["chunks_scanned"],
        "page_count": scan_result["page_count"],
        "extracted_preview": redact_secrets(scan_result["extracted_preview"]),
        "security_telemetry": saved_event,
    }


@app.get("/v1/audit-logs")
async def fetch_audit_logs(limit: int = 50):
    return await get_recent_logs(limit=limit)


@app.get("/v1/events/stream")
async def stream_security_events():
    queue: asyncio.Queue = asyncio.Queue()
    event_subscribers.append(queue)

    async def event_generator():
        try:
            while True:
                event = await queue.get()
                yield f"data: {json.dumps(event)}\n\n"
        except asyncio.CancelledError:
            event_subscribers.remove(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
