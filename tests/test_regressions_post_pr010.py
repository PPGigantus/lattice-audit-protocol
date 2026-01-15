from lap_gateway.crypto import TrustedKeyStore, Ed25519KeyPair
from lap_gateway.receipts import ToolInvocationReceipt


def test_receipt_verify_no_denied_at_attribute_error():
    # Regression: ToolInvocationReceipt.verify previously referenced a non-existent
    # attribute (denied_at_utc) in a fallback chain. It should never crash.
    kp = Ed25519KeyPair.generate(key_id="gateway_test_key")
    store = TrustedKeyStore()
    store.add_public_key(kp.key_id, kp.public_key_hex())

    receipt = ToolInvocationReceipt(
        receipt_id="r1",
        action_id="a1",
        evidence_hash="e" * 64,
        decision_hash="d" * 64,
        token_jti="t1",
        tool_name="tool",
        operation="op",
        params_hash="p" * 64,
        result_hash="r" * 64,
        response_hash="s" * 64,
        result_status="success",
        invoked_at_utc="2026-01-13T00:00:00Z",
        completed_at_utc="",  # intentionally blank
        duration_ms=0,
        prev_receipt_hash="",
        signature=b"",
        key_id=kp.key_id,
    )
    receipt.signature = kp.sign(receipt.compute_signature_payload())

    assert receipt.verify(store) is True
