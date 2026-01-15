import pytest

from lap_gateway.crypto import canonical_json_dumps
from lap_gateway.errors import LAPError, LAP_E_CANON_INT_TOO_LARGE, LAP_E_CANON_DEPTH, LAP_E_CANON_KEY_COLLISION


def test_canonical_json_v2_normalizes_unicode_nfc():
    # "e" + combining acute accent should normalize to a single composed "é"
    s_decomposed = "e\u0301"
    canon = canonical_json_dumps({"s": s_decomposed}, version="v2")
    assert canon == '{"s":"é"}'


def test_canonical_json_v2_preserves_large_integers_exactly():
    # Larger than signed int64, but still representable as an exact JSON integer string
    big = 12345678901234567890
    canon = canonical_json_dumps({"n": big}, version="v2")
    assert canon == f'{{"n":{big}}}'


def test_canonical_json_v2_rejects_pathological_bignums_by_digit_length():
    # Prevent DoS via extremely large integer strings
    huge = int("9" * 200)  # 200 digits
    with pytest.raises(LAPError) as ei:
        canonical_json_dumps({"n": huge}, version="v2")
    assert ei.value.code == LAP_E_CANON_INT_TOO_LARGE


def test_canonical_json_v2_rejects_excessive_nesting():
    x = "leaf"
    # Create depth 70 nesting, exceeding default max_depth=64
    for _ in range(70):
        x = [x]
    with pytest.raises(LAPError) as ei:
        canonical_json_dumps(x, version="v2")
    assert ei.value.code == LAP_E_CANON_DEPTH


def test_canonical_json_v2_rejects_key_collisions_after_unicode_normalization():
    # Two visually different keys that normalize to the same NFC form:
    #   "é" and "e" + combining acute.
    obj = {"é": 1, "e\u0301": 2}
    with pytest.raises(LAPError) as ei:
        canonical_json_dumps(obj, version="v2")
    assert ei.value.code == LAP_E_CANON_KEY_COLLISION
