package lap

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
)

// VerifyToken verifies the Ed25519 signature on a capability token.
func VerifyToken(token map[string]any, trustedKeys map[string]string) error {
	keyID, _ := token["key_id"].(string)
	pubHex, ok := trustedKeys[keyID]
	if !ok || pubHex == "" {
		return Errf("TOKEN_UNTRUSTED_KEY", "untrusted key_id: %s", keyID)
	}
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		if err != nil {
			return Wrap("TOKEN_PUBLIC_KEY_DECODE", err, "invalid public key for key_id: "+keyID)
		}
		return Errf("TOKEN_PUBLIC_KEY_INVALID", "invalid public key for key_id: %s", keyID)
	}

	// Budget must be JSON-dumped with Python default spacing & sort_keys=True
	budgetObj := token["budget"]
	budgetStr, err := PyJSONDumpsSortKeys(budgetObj)
	if err != nil {
		return Wrap("TOKEN_BUDGET_DUMPS", err, "failed to serialize budget")
	}

	allowedTools := joinSortedStr(token, "allowed_tools")
	allowedOps := joinSortedStr(token, "allowed_ops")

	components := []string{
		mustStr(token, "jti"),
		mustStr(token, "sub"),
		mustStr(token, "iss"),
		mustStr(token, "action_id"),
		mustStr(token, "evidence_hash"),
		mustStr(token, "decision_hash"),
		mustStr(token, "tier"),
		allowedTools,
		allowedOps,
		budgetStr,
		mustStr(token, "iat"),
		mustStr(token, "exp"),
		optStr(token, "params_hash"),
		optStr(token, "sid"),
		PyBoolString(optBool(token, "nonce_required")),
		PyBoolString(optBool(token, "counter_required")),
	}

	payload := SafeHashEncode(components)

	sigB64 := mustStr(token, "signature")
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return Wrap("TOKEN_SIGNATURE_BASE64", err, "invalid base64 signature")
	}
	if len(sig) != ed25519.SignatureSize {
		return Errf("TOKEN_SIGNATURE_LENGTH", "invalid signature length")
	}

	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return Errf("TOKEN_SIGNATURE_INVALID", "token signature invalid")
	}
	return nil
}
