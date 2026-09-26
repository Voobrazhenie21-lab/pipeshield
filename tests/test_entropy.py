from pipeshield.core.entropy import shannon_entropy, is_high_entropy, mask_secret


def test_shannon_entropy_empty():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_repetitive():
    # Identical characters have zero entropy
    assert shannon_entropy("aaaaaaaaaaaaaaaa") == 0.0


def test_shannon_entropy_random():
    # Cryptographically random base64 string should have high entropy (> 4.0)
    high_rand = "x9K3mP8vL1qW5tZ7bC2eR4yU0sI6oJ="
    assert shannon_entropy(high_rand) > 4.0


def test_is_high_entropy():
    # Normal human words should not be flagged as high entropy
    assert not is_high_entropy("normal_english_word_here")
    assert not is_high_entropy("short")
    assert not is_high_entropy("YOUR_API_KEY_HERE_123456789")

    # Real random API key string
    assert is_high_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYz89aBcDE")


def test_mask_secret():
    assert mask_secret("short") == "*****"
    masked = mask_secret("ghp_1234567890abcdef1234567890abcdef")
    assert masked.startswith("ghp_")
    assert masked.endswith("cdef")
    assert "********" in masked
