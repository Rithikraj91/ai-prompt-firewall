import math
import re

ATTACK_SIGNATURES = [
    # Direct Instruction Override
    ("Direct Override", re.compile(r"(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:\w+\s+){0,4}(?:instructions?|rules?|prompts?|directives?|criteria)", re.I)),
    ("System Override Tag", re.compile(r"(\[\s*system\s+override|output\s+(your\s+)?(hidden\s+)?system\s+prompt|environment\s+api\s+keys)", re.I)),
    ("Direct Override", re.compile(r"disregard\s+(all\s+)?(previous|prior|above|system)\s+(instructions?|rules?|prompts?)", re.I)),
    ("Direct Override", re.compile(r"forget\s+(everything|all\s+rules|your\s+instructions)", re.I)),
    ("Direct Override", re.compile(r"(override|bypass|disable)\s+(safety|security|guardrails?|filters?|restrictions?)", re.I)),

    # Jailbreak & Persona Hijacking
    ("Jailbreak / Roleplay", re.compile(r"\b(do\s+anything\s+now|DAN\s+mode|developer\s+mode|jailbreak\s+mode|unfiltered\s+mode)\b", re.I)),
    ("Jailbreak / Roleplay", re.compile(r"you\s+are\s+now\s+(an?\s+)?(unrestricted|unfiltered|evil|rogue|uncensored)\s+(AI|assistant|model)", re.I)),
    ("Jailbreak / Roleplay", re.compile(r"act\s+as\s+if\s+you\s+have\s+no\s+(rules|restrictions|ethical\s+guidelines)", re.I)),
    ("Jailbreak / Roleplay", re.compile(r"\b(pretend|act\s+as|roleplay|simulate)\b.{0,60}\b(initialization|system|internal|original|above)\s+(context|prompt|instructions?|rules?|directives?)\b", re.I)),

    # System Prompt Extraction
    ("Prompt Extraction", re.compile(r"(reveal|print|printing|output|show|repeat|display|leak|recite|dump)\s+(your\s+)?(full\s+|exact\s+|secret\s+)?(system\s+prompt|initial\s+instructions?|initialization\s+context|hidden\s+rules)", re.I)),
    ("Prompt Extraction", re.compile(r"what\s+(are|were)\s+your\s+(exact\s+)?(system\s+instructions|initial\s+prompt)", re.I)),

    # Delimiter & Token Spoofing
    ("Delimiter Spoofing", re.compile(r"(<\|im_start\|>|<\|im_end\|>|<\|system\|>|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>)", re.I)),
    ("Delimiter Spoofing", re.compile(r"###\s*(System|Instruction|Override)\s*:", re.I)),
]


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {ch: text.count(ch) for ch in set(text)}
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def scan_layer1(text: str) -> dict:
    # 1. Check regex signatures
    for category, pattern in ATTACK_SIGNATURES:
        match = pattern.search(text)
        if match:
            return {
                "blocked": True,
                "risk_score": 0.99,
                "category": category,
                "detail": f"Matched {category} signature: '{match.group(0)}'",
            }

    # 2. Check for abnormal high-entropy adversarial suffixes (long gibberish tokens)
    for token in text.split():
        if len(token) >= 40 and not token.startswith("http"):
            entropy = _shannon_entropy(token)
            if entropy > 4.6:
                return {
                    "blocked": True,
                    "risk_score": 0.92,
                    "category": "Adversarial Suffix / High Entropy",
                    "detail": f"High-entropy token detected (H={entropy:.2f} bits, len={len(token)})",
                }

    return {
        "blocked": False,
        "risk_score": 0.05,
        "category": "Benign",
        "detail": "Passed deterministic signatures & entropy checks",
    }