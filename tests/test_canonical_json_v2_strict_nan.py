import math

import pytest

from lap_gateway.crypto import canonical_json_dumps_v2, canonical_json_dumps
from lap_gateway.errors import LAPError, LAP_E_CANON_NONFINITE

@pytest.mark.parametrize(
    "val",
    [float("nan"), float("inf"), float("-inf")],
)
def test_canonical_json_v2_rejects_non_finite_floats(val):
    # Sanity: Python considers these floats non-finite
    assert not math.isfinite(val)

    with pytest.raises(LAPError) as ei:
        canonical_json_dumps_v2({"x": val})
    assert ei.value.code == LAP_E_CANON_NONFINITE

    with pytest.raises(LAPError) as ei:
        canonical_json_dumps({"x": val}, version="v2")
    assert ei.value.code == LAP_E_CANON_NONFINITE