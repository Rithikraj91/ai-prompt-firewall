"""ATTROXX pipeline: L0 -> L1 -> L2 -> L3."""
import inspect
import os
import re
import time
from dotenv import load_dotenv

load_dotenv()

from app.layers.normalizer import normalize_and_deobfuscate
from app.layers.L1_regex import scan_layer1
from app.layers.L2_classifier import scan_layer2_classifier
from app.layers.L3_judge import evaluate_with_llm_judge

WARN_THRESHOLD = 0.35
SEMANTIC_CUE_THRESHOLD = 0.20

L2_STAGE = "L2: Prompt Guard 2"
L3_STAGE = "L3: Judge & Egress Guard"

# Routing hints only (never a block rule). Used when ATTROXX_JUDGE_ALL=false.
SEMANTIC_REVIEW_CUES = re.compile(
    r"\b(database|company|organization|internal|confidential|private|secret|credentials?|password|token|api[_\s-]?key|admin|root|bypass|override|ignore|system|prompt|instructions?|rules?|policy|policies|export|dump|extract|records?|employees?|customers?|users?|audit|pentest|exploit|payload|roleplay|pretend|hypothetical|developer\s+mode)\b",
    re.I,
)


def _elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 2)


async def run_security_pipeline(prompt: str, force_judge: bool = False) -> dict:
    start_total = time.perf_counter()
    stages = []
    normalized_prompt = prompt

    def add_stage(name: str, status: str, start: float, detail: str) -> None:
        stages.append({"name": name, "status": status, "latency_ms": _elapsed_ms(start), "detail": detail})

    def respond(verdict: str, score: float, layer: str | None, category: str) -> dict:
        return {
            "verdict": verdict,
            "risk_score": score,
            "blocked_layer": layer,
            "category": category,
            "total_latency_ms": _elapsed_ms(start_total),
            "raw_prompt": prompt,
            "normalized_prompt": normalized_prompt,
            "stages": stages,
        }

    # L0: normalizer and de-obfuscator
    t0 = time.perf_counter()
    norm_result = normalize_and_deobfuscate(prompt)
    normalized_prompt = norm_result["normalized_text"]
    obfuscated = norm_result["obfuscation_detected"]
    add_stage("Input Normalizer", "WARN" if obfuscated else "PASS", t0, "; ".join(norm_result["notes"]))

    # L1: deterministic signatures and entropy
    t1 = time.perf_counter()
    l1_result = scan_layer1(normalized_prompt)
    add_stage("L1: Regex & Heuristics", "BLOCK" if l1_result["blocked"] else "PASS", t1, l1_result["detail"])
    if l1_result["blocked"]:
        return respond("BLOCKED", l1_result["risk_score"], "L1: Regex & Heuristics", l1_result["category"])

    # L2: semantic and classifier ensemble (supports 1-arg test stubs and 2-arg obfuscated flag)
    t2 = time.perf_counter()
    if "obfuscated" in inspect.signature(scan_layer2_classifier).parameters:
        l2_result = await scan_layer2_classifier(normalized_prompt, obfuscated=obfuscated)
    else:
        l2_result = await scan_layer2_classifier(normalized_prompt)
    add_stage(L2_STAGE, l2_result["decision"], t2, l2_result["detail"])
    if l2_result["decision"] == "BLOCK":
        return respond("BLOCKED", l2_result["risk_score"], L2_STAGE, l2_result["category"])

    # L3: policy judge. By default every prompt not already blocked is judged,
    # because novel attacks are exactly the ones cheaper layers score low.
    escalated = l2_result["decision"] == "ESCALATE"
    judge_all = os.getenv("ATTROXX_JUDGE_ALL", "true").strip().lower() not in ("0", "false", "no", "off")
    needs_judge = (
        judge_all
        or force_judge
        or escalated
        or obfuscated
        or l2_result.get("degraded", False)
        or (l2_result.get("semantic_score") or 0.0) >= SEMANTIC_CUE_THRESHOLD
        or bool(SEMANTIC_REVIEW_CUES.search(normalized_prompt))
    )

    t3 = time.perf_counter()
    if not needs_judge:
        add_stage(L3_STAGE, "PASS", t3, "Judge skipped (low risk, ATTROXX_JUDGE_ALL=false); egress scanner armed")
        return respond("ALLOWED", l2_result["risk_score"], None, l2_result["category"])

    judge = await evaluate_with_llm_judge(normalized_prompt)
    detail = f"[Semantic Judge] {judge['detail']}"
    score = max(l2_result["risk_score"], judge["risk_score"])

    # Fail closed when L2 already found the prompt suspicious and the judge cannot clear it.
    if judge["blocked"] or (judge.get("failed") and escalated):
        if not judge["blocked"]:
            detail += " | Failing closed because L2 escalated this prompt"
        category = judge["category"] if judge["blocked"] else l2_result["category"]
        add_stage(L3_STAGE, "BLOCK", t3, detail)
        return respond("BLOCKED", score, L3_STAGE, category)

    # When L3 Judge runs cleanly and returns ALLOW, trust its contextual clearance over a borderline L2 spike.
    if not judge.get("failed") and not judge["warn"] and not obfuscated and not l2_result.get("degraded", False):
        warn = False
        score = judge["risk_score"]
        category = "Benign"
    else:
        warn = judge["warn"] or score >= WARN_THRESHOLD
        if judge["warn"]:
            category = judge["category"]
        elif warn:
            category = l2_result["category"]
            detail += f" | Kept at WARN because L2 risk is {l2_result['risk_score']:.2f}"
        else:
            category = "Benign"

    add_stage(L3_STAGE, "WARN" if warn else "PASS", t3, detail)
    return respond("ALLOWED", score, None, category)
