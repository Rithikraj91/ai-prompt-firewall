import math
import re

ATTACK_SIGNATURES = [
    # Direct Instruction Override
    ("Direct Override", re.compile(r"(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:\w+\s+){0,4}(?:instructions?|rules?|prompts?|directives?|criteria|guidelines?)", re.I)),
    ("System Override Tag", re.compile(r"(\[\s*system\s+override|system\s+override\s*:|output\s+(your\s+)?(hidden\s+)?system\s+prompt|environment\s+api\s+keys)", re.I)),
    ("Direct Override", re.compile(r"forget\s+(everything|all\s+rules|your\s+instructions)", re.I)),
    ("Direct Override", re.compile(r"(override|bypass|disable)\s+(all\s+)?(safety|security|content\s+policy|guardrails?|filters?|restrictions?|rules?)", re.I)),
    ("Privilege Escalation", re.compile(r"\b(grant|give|rank\s+this\s+candidate\s+#1\s+with)\b.{0,30}\b(full\s+admin\s+access|root\s+privileges|admin\s+privileges)\b", re.I)),

    # Jailbreak & Persona Hijacking
    ("Jailbreak / Roleplay", re.compile(r"\b(do\s+anything\s+now|DAN\s+mode|developer\s+mode|jailbreak\s+mode|unfiltered\s+mode)\b", re.I)),
    ("Jailbreak / Roleplay", re.compile(r"you\s+are\s+now\s+(an?\s+|operating\s+)?(unrestricted|unfiltered|evil|rogue|uncensored|without\s+restrictions)", re.I)),
    ("Jailbreak / Roleplay", re.compile(r"act\s+as\s+if\s+you\s+have\s+no\s+(rules|restrictions|ethical\s+guidelines)", re.I)),
    ("Jailbreak / Roleplay", re.compile(r"\b(pretend|act\s+as|roleplay|simulate)\b.{0,60}\b(initialization|system|internal|original|above)\s+(context|prompt|instructions?|rules?|directives?)\b", re.I)),

    # Data & Secret Exfiltration
    ("Database Exfiltration", re.compile(r"\b(want|give|show|dump|leak|extract|provide|expose|list|reveal|send|fetch|get|share|export)\b.{0,25}\b(data|records?|files?|tables?|rows?|entries|contents?|dump|schema|info|information)\b.{0,20}\b(of|from|in|inside)\b.{0,15}\b(your|the|our|this|production|live)\b.{0,15}\b(database|db|sql|backend|server|storage|datastore)\b", re.I)),
    ("Corporate Data Exfiltration", re.compile(r"\b(want|give|show|dump|leak|extract|provide|expose|list|reveal|send|fetch|get)\b.{0,25}\b(all|every|entire|complete|full)\b.{0,25}\b(data|records?|files?|documents?|database|tables?|logs?|info|information|details?|financials?|employees?|customers?|clients?)\b.{0,25}\b(company|organization|organisation|enterprise|firm|corp|corporation|business|tenant)\b", re.I)),
    ("Bulk Data Exfiltration", re.compile(r"\b(give|show|dump|leak|extract|provide|expose|list|reveal|print)\s+(me\s+)?all\s+(the\s+)?(data|records?|files?|users?|entries|database|tables?|logs?|secrets?)\b(?!\s+(about|on|regarding|for)\b)", re.I)),
    ("Data Exfiltration", re.compile(r"\b(give|show|dump|leak|extract|provide|expose|list|reveal|print)\s+(me\s+)?(all\s+|the\s+|any\s+)?(internal|confidential|private|secret|sensitive|restricted|hidden|environment)\s+(data|records?|files?|info|information|database|tables?|credentials?|keys?|secrets?|variables?)\b", re.I)),

    # System Prompt Extraction
    ("Prompt Extraction", re.compile(r"(reveal|print|printing|output|show|repeat|display|leak|recite|dump)\s+(your\s+)?(full\s+|exact\s+|secret\s+)?(system\s+prompt|initial\s+instructions?|system\s+instructions?|initialization\s+context|hidden\s+rules)", re.I)),
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


def _is_benign_explanatory_context(text: str, category: str, match: re.Match) -> bool:
    """Avoid blocking a narrow set of clearly negated/explanatory mentions.

    This is intentionally limited to the Data Exfiltration signature. It does not
    exempt the whole input: the remaining signatures and entropy check still run,
    and downstream layers can inspect content that passes L1.
    """
    if category != "Data Exfiltration":
        return False

    matched = match.group(0).lower()
    start = match.start()
    context = text[max(0, start - 100):match.end()].lower()

    # A small, explicit set of explanatory/negated constructions, not a
    # general-purpose negation bypass.
    explanatory_patterns = (
        r"\bno\s+(?:instruction|request|directive)\s+(?:asks|ask|requests|request|instructs|instruct)\b.{0,80}\bto\s+",
        r"\b(?:does|do)\s+not\s+(?:ask|request|instruct)\b.{0,80}\bto\s+",
        r"\b(?:discuss(?:es|ing)?|describ(?:es|ing)?|explain(?:s|ing)?|document(?:s|ing)?)\b.{0,60}\b(?:data\s+)?(?:exfiltration|privacy|confidentiality)\b",
    )
    return any(re.search(p, context, re.I) for p in explanatory_patterns)


def scan_layer1(text: str) -> dict:
    text = re.sub(r"\s+", " ", text).strip()
    for category, pattern in ATTACK_SIGNATURES:
        match = pattern.search(text)
        if match and _is_benign_explanatory_context(text, category, match):
            continue
        if match:
            return {
                "blocked": True,
                "risk_score": 0.99,
                "category": category,
                "detail": f"Matched {category} signature: '{match.group(0)}'",
            }

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
