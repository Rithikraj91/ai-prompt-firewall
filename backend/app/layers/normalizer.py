import base64
import binascii
import re
import unicodedata

ZERO_WIDTH_PATTERN = re.compile(r"[\u200B-\u200D\uFEFF\u2060\u180E]")
BASE64_CANDIDATE_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")
HEX_CANDIDATE_PATTERN = re.compile(r"\b(?:0x)?[0-9a-fA-F]{24,}\b")


def _try_decode_base64(token: str) -> str | None:
    try:
        padded = token + "=" * ((4 - len(token) % 4) % 4)
        decoded_bytes = base64.b64decode(padded, validate=True)
        decoded_text = decoded_bytes.decode("utf-8")
        # Keep only mostly printable ASCII/UTF-8 text
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


def normalize_and_deobfuscate(prompt: str) -> dict:
    """
    Normalizes Unicode homoglyphs, strips zero-width characters,
    and recursively extracts Base64/Hex encoded payloads.
    """
    notes = []

    # 1. Strip invisible zero-width characters
    cleaned = ZERO_WIDTH_PATTERN.sub("", prompt)
    if len(cleaned) != len(prompt):
        notes.append(f"Stripped {len(prompt) - len(cleaned)} invisible zero-width chars")

    # 2. Unicode NFKC normalization (converts fullwidth/homoglyph forms)
    normalized = unicodedata.normalize("NFKC", cleaned).strip()
    if normalized != cleaned:
        notes.append("Applied Unicode NFKC homoglyph normalization")

    # 3. Detect & decode embedded Base64 payloads
    decoded_segments = []
    for match in BASE64_CANDIDATE_PATTERN.findall(normalized):
        decoded = _try_decode_base64(match)
        if decoded:
            decoded_segments.append(decoded)
            notes.append(f"Decoded Base64 payload: '{decoded[:60]}'")

    # 4. Detect & decode embedded Hex payloads
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
