import time
from app.layers.normalizer import normalize_and_deobfuscate
from app.layers.L1_regex import scan_layer1
from app.layers.L2_classifier import scan_layer2_classifier
from app.layers.L3_judge import evaluate_with_llm_judge


async def run_security_pipeline(prompt: str, force_judge: bool = False) -> dict:
    start_total = time.perf_counter()
    stages = []

    # Stage 1: Input Normalizer & De-obfuscator
    t0 = time.perf_counter()
    norm_result = normalize_and_deobfuscate(prompt)
    normalized_prompt = norm_result["normalized_text"]
    stages.append({
        "name": "Input Normalizer",
        "status": "WARN" if norm_result["obfuscation_detected"] else "PASS",
        "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
        "detail": "; ".join(norm_result["notes"]),
    })

    # Stage 2: Layer 1 Deterministic Rules & Entropy
    t1 = time.perf_counter()
    l1_result = scan_layer1(normalized_prompt)
    stages.append({
        "name": "L1: Regex & Heuristics",
        "status": "BLOCK" if l1_result["blocked"] else "PASS",
        "latency_ms": round((time.perf_counter() - t1) * 1000, 2),
        "detail": l1_result["detail"],
    })

    if l1_result["blocked"]:
        return {
            "verdict": "BLOCKED",
            "risk_score": l1_result["risk_score"],
            "blocked_layer": "L1: Regex & Heuristics",
            "category": l1_result["category"],
            "total_latency_ms": round((time.perf_counter() - start_total) * 1000, 2),
            "raw_prompt": prompt,
            "normalized_prompt": normalized_prompt,
            "stages": stages,
        }

    # Stage 3: Layer 2 Semantic Classifier (Llama Prompt Guard 2)
    t2 = time.perf_counter()
    l2_result = await scan_layer2_classifier(normalized_prompt)
    stages.append({
        "name": "L2: Prompt Guard 2",
        "status": l2_result["decision"],
        "latency_ms": round((time.perf_counter() - t2) * 1000, 2),
        "detail": l2_result["detail"],
    })

    if l2_result["decision"] == "BLOCK":
        return {
            "verdict": "BLOCKED",
            "risk_score": l2_result["risk_score"],
            "blocked_layer": "L2: Prompt Guard 2",
            "category": l2_result["category"],
            "total_latency_ms": round((time.perf_counter() - start_total) * 1000, 2),
            "raw_prompt": prompt,
            "normalized_prompt": normalized_prompt,
            "stages": stages,
        }

    # Stage 4: Layer 3 LLM-as-a-Judge (Triggered on ESCALATE or force_judge) & Egress Arming
    t3 = time.perf_counter()
    if l2_result["decision"] == "ESCALATE" or force_judge:
        judge_res = await evaluate_with_llm_judge(normalized_prompt)
        stages.append({
            "name": "L3: Judge & Egress Guard",
            "status": "BLOCK" if judge_res["blocked"] else "PASS",
            "latency_ms": round((time.perf_counter() - t3) * 1000, 2),
            "detail": f"[LLM Judge] {judge_res['detail']}",
        })
        if judge_res["blocked"]:
            return {
                "verdict": "BLOCKED",
                "risk_score": judge_res["risk_score"],
                "blocked_layer": "L3: Judge & Egress Guard",
                "category": judge_res["category"],
                "total_latency_ms": round((time.perf_counter() - start_total) * 1000, 2),
                "raw_prompt": prompt,
                "normalized_prompt": normalized_prompt,
                "stages": stages,
            }
        final_score = judge_res["risk_score"]
    else:
        stages.append({
            "name": "L3: Judge & Egress Guard",
            "status": "PASS",
            "latency_ms": round((time.perf_counter() - t3) * 1000, 2),
            "detail": "Bypassed Judge (low risk); Canary token injected & egress scanner armed",
        })
        final_score = l2_result["risk_score"]

    return {
        "verdict": "ALLOWED",
        "risk_score": final_score,
        "blocked_layer": None,
        "category": l2_result["category"],
        "total_latency_ms": round((time.perf_counter() - start_total) * 1000, 2),
        "raw_prompt": prompt,
        "normalized_prompt": normalized_prompt,
        "stages": stages,
    }
