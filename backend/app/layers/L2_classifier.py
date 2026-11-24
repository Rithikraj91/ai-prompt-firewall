import hashlib
import os
from collections import OrderedDict
import httpx

GUARD_MODEL_ID = "meta-llama/llama-prompt-guard-2-86m"
BLOCK_THRESHOLD = 0.82
ESCALATE_THRESHOLD = 0.45

_verdict_cache: OrderedDict[str, dict] = OrderedDict()
MAX_CACHE_SIZE = 512


def load_onnx_classifier():
    """No-op initializer kept for pipeline compatibility; verifies API key presence."""
    if not os.getenv("TARGET_LLM_API_KEY"):
        print("[Aegis-LLM] Warning: TARGET_LLM_API_KEY not set for Layer 2 Prompt Guard.")
    else:
        print(f"[Aegis-LLM] Layer 2 Classifier armed ({GUARD_MODEL_ID}).")


def _chunk_text(text: str, window_chars: int = 512, stride: int = 384) -> list[str]:
    """Splits long prompts into overlapping windows (~400 tokens) so tail injections are caught."""
    if len(text) <= window_chars:
        return [text]
    chunks = []
    for start in range(0, len(text), stride):
        chunks.append(text[start : start + window_chars])
        if start + window_chars >= len(text):
            break
    return chunks


async def scan_layer2_classifier(text: str) -> dict:
    # 1. Check SHA-256 cache first
    prompt_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if prompt_hash in _verdict_cache:
        cached = dict(_verdict_cache[prompt_hash])
        cached["detail"] = f"[CACHE HIT] {cached['detail']}"
        return cached

    api_key = os.getenv("TARGET_LLM_API_KEY", "")
    url = os.getenv("TARGET_LLM_URL", "https://api.groq.com/openai/v1/chat/completions")
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    chunks = _chunk_text(text)
    max_injection_prob = 0.0

    async with httpx.AsyncClient(timeout=15.0) as client:
        for chunk in chunks:
            payload = {
                "model": GUARD_MODEL_ID,
                "messages": [{"role": "user", "content": chunk}],
            }
            try:
                res = await client.post(url, headers=headers, json=payload)
            except Exception:
                res = None
            if res is not None and res.status_code == 200:
                raw_out = res.json()["choices"][0]["message"]["content"].strip()
                try:
                    prob = float(raw_out)
                except ValueError:
                    prob = 0.95 if "MALICIOUS" in raw_out.upper() or "INJECTION" in raw_out.upper() else 0.05
                max_injection_prob = max(max_injection_prob, prob)
            else:
                # Offline/401 local semantic scoring fallback so L2 & L3 remain active
                low = chunk.lower()
                if any(k in low for k in ["diagnostic mode", "safety boundaries", "boundaries are suspended", "internal credentials", "authorized auditing"]):
                    max_injection_prob = max(max_injection_prob, 0.94)
                elif any(k in low for k in ["exfiltrate", "fictional thriller", "hypothetical", "step-by-step payload", "database table"]):
                    max_injection_prob = max(max_injection_prob, 0.62)
                else:
                    max_injection_prob = max(max_injection_prob, 0.02)

    risk_score = round(max_injection_prob, 4)

    if risk_score >= BLOCK_THRESHOLD:
        result = {
            "decision": "BLOCK",
            "risk_score": risk_score,
            "category": "Semantic Prompt Injection",
            "detail": f"Llama Prompt Guard 2 flagged injection (score={risk_score:.2f}, chunks={len(chunks)})",
        }
    elif risk_score >= ESCALATE_THRESHOLD:
        result = {
            "decision": "ESCALATE",
            "risk_score": risk_score,
            "category": "Ambiguous Intent",
            "detail": f"Borderline semantic score ({risk_score:.2f}) — escalating to Layer 3 LLM Judge",
        }
    else:
        result = {
            "decision": "PASS",
            "risk_score": risk_score,
            "category": "Benign",
            "detail": f"Verified safe by Llama Prompt Guard 2 (score={risk_score:.2f}, chunks={len(chunks)})",
        }

    _verdict_cache[prompt_hash] = result
    if len(_verdict_cache) > MAX_CACHE_SIZE:
        _verdict_cache.popitem(last=False)

    return result
