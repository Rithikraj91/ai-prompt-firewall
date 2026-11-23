# 🛡️ ATTROXX — Runtime AI Prompt Firewall & SOC Telemetry Gateway

**ATTROXX** is an OpenAI-compatible runtime security gateway and real-time Security Operations Center (SOC) dashboard built to defend Large Language Models (LLMs) and Retrieval-Augmented Generation (RAG) pipelines against **OWASP Top 10 for LLM** threats—including direct/indirect prompt injection, jailbreaks, Unicode/Base64 smuggling, and system prompt exfiltration.

---

## 🏗️ 4-Tier Defense-in-Depth Architecture

Every request to `/v1/chat/completions` or `/v1/scan/document` passes through a latency-budgeted multi-stage inspection pipeline before reaching the upstream LLM:

```text
User Prompt / RAG Document
        │
        ▼
┌──────────────────────────────────────────────────────────┐
│ Tier 0: Input Normalizer & De-obfuscator                 │
│ • NFKC Unicode homoglyph folding & zero-width stripping  │
│ • Recursive Base64 & Hex payload extraction              │
└───────────────────────────┬──────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────┐
│ Tier 1: Deterministic Regex & Shannon Entropy (< 0.5 ms) │
│ • Direct overrides, roleplay/DAN jailbreaks, delimiters  │
│ • High-entropy adversarial suffix detection (H > 4.6)    │
└──────────────┬───────────────────────────┬───────────────┘
          [BLOCKED]                   [PASSED / UNCERTAIN]
               │                           │
               │                           ▼
               │  ┌────────────────────────────────────────┐
               │  │ Tier 2: Neural Classifier              │
               │  │ • Llama Prompt Guard 2 (86M)           │
               │  │ • Sliding-window chunking & LRU cache  │
               │  └───────────────┬───────────────┬────────┘
               │             [BLOCKED]     [ESCALATE >= 0.45]
               │                  │               │
               │                  │               ▼
               │                  │  ┌─────────────────────┐
               │                  │  │ Tier 3: LLM Judge & │
               │                  │  │ Egress Canary Guard │
               │                  │  │ • Semantic intent   │
               │                  │  │ • Canary leak scan  │
               │                  │  └──────────┬──────────┘
               ▼                  ▼               ▼
       ┌───────────────────────────────────────────────────┐
       │ SQLite Audit Store + Live SSE Telemetry Stream    │
       │ -> Real-Time Next.js SOC Command Center Dashboard │
       └───────────────────────────────────────────────────┘