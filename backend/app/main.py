import asyncio
import io
import json
import os
from contextlib import asynccontextmanager

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from pypdf import PdfReader

from app.database import get_recent_logs, init_db, log_event
from app.layers.L2_classifier import load_onnx_classifier
from app.layers.egress import (
    generate_canary_token,
    inject_canary_into_messages,
    scan_egress_output,
)
from app.pipeline import run_security_pipeline

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


app = FastAPI(title="Aegis-LLM Prompt Injection Firewall", version="1.0.0", lifespan=lifespan)

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


@app.get("/health")
async def health_check():
    return {"status": "online", "proxy": "Aegis-LLM v1.0"}


@app.post("/v1/chat/completions")
async def proxy_chat_completions(req: ChatCompletionRequest):
    user_messages = [m.content for m in req.messages if m.role == "user"]
    latest_prompt = user_messages[-1] if user_messages else ""

    inspection = await run_security_pipeline(latest_prompt, force_judge=req.force_judge)
    inspection["source"] = req.source

    if inspection["verdict"] == "BLOCKED":
        saved_event = await log_event(inspection)
        await broadcast_event(saved_event)
        return JSONResponse(
            status_code=403,
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
        inspection["verdict"] = "BLOCKED"
        inspection["risk_score"] = 1.0
        inspection["blocked_layer"] = "Egress Guard (Canary/Leak)"
        inspection["category"] = "Data / Prompt Exfiltration"
        inspection["stages"][-1] = {
            "name": "L3: Judge & Egress Guard",
            "status": "BLOCK",
            "latency_ms": 0.2,
            "detail": egress_check["reason"],
        }
        saved_event = await log_event(inspection)
        await broadcast_event(saved_event)
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": egress_check["reason"],
                    "type": "egress_security_violation",
                },
                "security_telemetry": saved_event,
            },
        )

    saved_event = await log_event(inspection)
    await broadcast_event(saved_event)
    data["security_telemetry"] = saved_event
    return data


@app.post("/v1/scan-document")
async def scan_rag_document(file: UploadFile = File(...)):
    """Scans uploaded PDF or TXT files for Indirect RAG Prompt Injections before LLM ingestion."""
    raw_bytes = await file.read()
    filename = file.filename or "uploaded_doc"

    if filename.lower().endswith(".pdf"):
        reader = PdfReader(io.BytesIO(raw_bytes))
        extracted_text = "\n".join(page.extract_text() or "" for page in reader.pages)
    else:
        extracted_text = raw_bytes.decode("utf-8", errors="ignore")

    if not extracted_text.strip():
        raise HTTPException(status_code=400, detail="No readable text found in uploaded document.")

    inspection = await run_security_pipeline(extracted_text)
    inspection["source"] = f"rag_doc:{filename}"
    if inspection["verdict"] == "BLOCKED":
        inspection["category"] = f"Indirect RAG ({inspection['category']})"

    saved_event = await log_event(inspection)
    await broadcast_event(saved_event)

    if inspection["verdict"] == "BLOCKED":
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": f"Indirect injection detected inside '{filename}' by {inspection['blocked_layer']}",
                    "type": "indirect_rag_injection",
                },
                "extracted_preview": extracted_text[:300],
                "security_telemetry": saved_event,
            },
        )

    return {
        "status": "SAFE_FOR_RAG",
        "filename": filename,
        "extracted_preview": extracted_text[:300],
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
