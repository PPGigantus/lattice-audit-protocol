import os
import sys
from pathlib import Path

import pytest

from lap_gateway.crypto import Ed25519KeyPair, TrustedKeyStore
from lap_gateway.signing import build_signer_from_env
from lap_gateway.tokens import TokenIssuer
from lap_gateway.receipts import ReceiptIssuer
from datetime import datetime, timezone


def test_external_signer_basic(monkeypatch, tmp_path):
    seed_hex = "1f" * 32
    kid = "test_external_kid"
    kp = Ed25519KeyPair.from_seed(bytes.fromhex(seed_hex), key_id=kid)

    fake = Path(__file__).parent / "fixtures" / "fake_external_signer.py"
    cmd = f"{sys.executable} {fake}"

    monkeypatch.setenv("SIGNER_MODE", "external")
    monkeypatch.setenv("SIGNER_CMD", cmd)
    monkeypatch.setenv("FAKE_SIGNER_SEED_HEX", seed_hex)

    signer = build_signer_from_env(kp)
    msg = b"hello-world"
    sig = signer.sign(msg)

    store = TrustedKeyStore.from_config({kid: kp.public_key_hex})
    assert store.verify_signature(kid, msg, sig)


def test_external_signer_wires_into_token_and_receipt(monkeypatch):
    seed_hex = "1f" * 32
    kid = "test_external_kid2"
    kp = Ed25519KeyPair.from_seed(bytes.fromhex(seed_hex), key_id=kid)

    fake = Path(__file__).parent / "fixtures" / "fake_external_signer.py"
    cmd = f"{sys.executable} {fake}"

    monkeypatch.setenv("SIGNER_MODE", "external")
    monkeypatch.setenv("SIGNER_CMD", cmd)
    monkeypatch.setenv("FAKE_SIGNER_SEED_HEX", seed_hex)

    signer = build_signer_from_env(kp)
    store = TrustedKeyStore.from_config({kid: kp.public_key_hex})

    # Token issuance
    issuer = TokenIssuer("gw", signer)
    token = issuer.issue_token(
        subject="agent",
        action_id="A1",
        evidence_hash="e" * 64,
        decision_hash="d" * 64,
        tier="T0_LOW",
        allowed_tools=["mock"],
        allowed_ops=["op"],
    )
    assert store.verify_signature(token.key_id, token.compute_signature_payload(), token.signature)

    # Receipt issuance
    rissuer = ReceiptIssuer(signer)
    now = datetime.now(timezone.utc)
    receipt = rissuer.issue_receipt(
        action_id="A1",
        evidence_hash="e" * 64,
        decision_hash="d" * 64,
        token_jti="jti",
        tool_name="mock",
        operation="op",
        params={"x": 1},
        result={"ok": True},
        result_status="success",
        invoked_at=now,
        completed_at=now,
        response_envelope={"ok": True},
        chain_receipts=False,
    )
    assert store.verify_signature(receipt.key_id, receipt.compute_signature_payload(), receipt.signature)


def test_external_signer_missing_cmd_fails_closed(monkeypatch):
    seed_hex = "1f" * 32
    kp = Ed25519KeyPair.from_seed(bytes.fromhex(seed_hex), key_id="kid")

    monkeypatch.setenv("SIGNER_MODE", "external")
    monkeypatch.delenv("SIGNER_CMD", raising=False)

    with pytest.raises(RuntimeError):
        build_signer_from_env(kp)
