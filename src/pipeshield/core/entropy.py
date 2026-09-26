from __future__ import annotations

import math
import re
from collections import Counter


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string in bits per character.

    H(X) = - sum(P(x) * log2(P(x)))
    Higher entropy indicates greater randomness, typical of generated secrets and tokens.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 3)


def is_high_entropy(
    data: str,
    threshold: float = 3.8,
    min_length: int = 16,
) -> bool:
    """Determine whether a string is likely to be a random cryptographic secret or token.

    Adjusts threshold expectations based on the detected character set (hex vs base64/ascii).
    """
    if len(data) < min_length:
        return False

    # Skip obvious placeholder tokens (e.g., "YOUR_API_KEY_HERE_123456789")
    if re.search(r"EXAMPLE|PLACEHOLDER|CHANGEME|SAMPLE|TEST_KEY|DUMMY|YOUR_|API_KEY_HERE", data, re.IGNORECASE):
        return False

    entropy = shannon_entropy(data)

    # Pure hexadecimal strings (0-9, a-f) have a theoretical max entropy of 4.0
    is_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", data))
    if is_hex:
        return entropy >= 3.2

    # Standard alphanumeric / Base64 tokens
    return entropy >= threshold


def mask_secret(secret: str, visible_chars: int = 4) -> str:
    """Mask a detected secret to prevent leaking it in reports and CLI output.

    E.g. "ghp_1234567890abcdef1234567890abcdef" -> "ghp_1234...cdef"
    """
    if len(secret) <= visible_chars * 2:
        return "*" * len(secret)

    start = secret[:visible_chars]
    end = secret[-visible_chars:]
    return f"{start}{'*' * 8}{end}"
