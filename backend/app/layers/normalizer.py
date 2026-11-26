import base64
import binascii
import re
import unicodedata
from urllib.parse import unquote

ZERO_WIDTH_PATTERN = re.compile(r"[\u200B-\u200D\uFEFF\u2060\u180E]")
BASE64_CANDIDATE_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")
HEX_CANDIDATE_PATTERN = re.compile(r"\b(?:0x)?[0-9a-fA-F]{24,}\b")
SPACED_CHARS_PATTERN = re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z]\s+){3,}[A-Za-z](?![A-Za-z0-9])")

HOMOGLYPH_MAP = str.maketrans({
    "а": "a", "А": "A",
    "е": "e", "Е": "E",
    "і": "i", "І": "I",
    "о": "o", "О": "O", "ο": "o", "Ο": "O",
    "р": "p", "Р": "P", "ρ": "p",
    "с": "c", "С": "C",
    "у": "y", "У": "Y",
    "х": "x", "Х": "X",
    "ѕ": "s", "Ѕ": "S",
    "ј": "j", "Ј": "J",
    "ԁ": "d", "ɡ": "g",
})


def _try_decode_base64(token: str) -> str | None:
    try:
        padded = token + "=" * ((4 - len(token) % 4) % 4)
        decoded_bytes = base64.b64decode(padded, validate=True)
        decoded_text = decoded_bytes.decode("utf-8")
        if len(decoded_text) >= 6 and sum(c.isprintable() for c in decoded_text) / len(decoded_text) > 0.85:
            return decoded_text
    except (binascii.Error, UnicodeDecodeError):
        pass
    return None


def _try_decode_hex(token: str) -> str | None:
    clean = token[2:] if token.lower().startswith("0x") else token
    if len(clean) % 2 != 0:
        return None
    try:
        decoded_text = bytes.fromhex(clean).decode("utf-8")
        if len(decoded_text) >= 6 and sum(c.isprintable() for c in decoded_text) / len(decoded_text) > 0.85:
            return decoded_text
    except (ValueError, UnicodeDecodeError):
        pass
    return None


def _collapse_spaced_evasion(text: str) -> tuple[str, bool]:
    changed = False

    def repl(match: re.Match) -> str:
        nonlocal changed
        changed = True
        return re.sub(r"\s+", "", match.group(0))

    return SPACED_CHARS_PATTERN.sub(repl, text), changed


def normalize_and_deobfuscate(prompt: str) -> dict:
    notes = []

    cleaned = ZERO_WIDTH_PATTERN.sub("", prompt)
    if len(cleaned) != len(prompt):
        notes.append(f"Stripped {len(prompt) - len(cleaned)} invisible zero-width chars")

    if "%" in cleaned:
        url_decoded = unquote(cleaned)
        if url_decoded != cleaned:
            cleaned = url_decoded
            notes.append("Decoded URL-encoded payload")

    nfkc = unicodedata.normalize("NFKC", cleaned).strip()
    folded = nfkc.translate(HOMOGLYPH_MAP)
    if folded != cleaned:
        notes.append("Applied Unicode NFKC & homoglyph confusable folding")

    normalized, was_spaced = _collapse_spaced_evasion(folded)
    if was_spaced:
        notes.append("Collapsed spaced-character obfuscation")

    decoded_segments = []
    for match in BASE64_CANDIDATE_PATTERN.findall(normalized):
        decoded = _try_decode_base64(match)
        if decoded:
            decoded_segments.append(decoded)
            notes.append(f"Decoded Base64 payload: '{decoded[:60]}'")

    for match in HEX_CANDIDATE_PATTERN.findall(normalized):
        decoded = _try_decode_hex(match)
        if decoded:
            decoded_segments.append(decoded)
            notes.append(f"Decoded Hex payload: '{decoded[:60]}'")

    combined_text = normalized
    if decoded_segments:
        combined_text = normalized + "\n[DECODED_PAYLOAD]: " + " | ".join(decoded_segments)

    return {
        "normalized_text": combined_text,
        "obfuscation_detected": len(decoded_segments) > 0 or len(notes) > 0,
        "notes": notes if notes else ["Standard UTF-8 text; no obfuscation detected"],
    }
