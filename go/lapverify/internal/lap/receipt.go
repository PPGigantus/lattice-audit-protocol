package lap

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// VerifyReceipt verifies receipt signature and recomputes receipt_hash.
// Returns computed receipt hash.
func VerifyReceipt(receipt map[string]any, trustedKeys map[string]string, receiptProfile string) (string, error) {
	keyID, _ := receipt["key_id"].(string)
	pubHex, ok := trustedKeys[keyID]
	if !ok || pubHex == "" {
		return "", Errf("RECEIPT_UNTRUSTED_KEY", "untrusted key_id: %s", keyID)
	}
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		if err != nil {
			return "", Wrap("RECEIPT_PUBLIC_KEY_DECODE", err, "invalid public key for key_id: "+keyID)
		}
		return "", Errf("RECEIPT_PUBLIC_KEY_INVALID", "invalid public key for key_id: %s", keyID)
	}

	components := []string{
		mustStr(receipt, "receipt_id"),
		mustStr(receipt, "action_id"),
		mustStr(receipt, "evidence_hash"),
		mustStr(receipt, "decision_hash"),
		mustStr(receipt, "token_jti"),
		mustStr(receipt, "tool_name"),
		mustStr(receipt, "operation"),
		mustStr(receipt, "params_hash"),
	}

	// Optional/required decision_binding (receipt_profile=v2)
	db := optStr(receipt, "decision_binding")
	if strings.TrimSpace(receiptProfile) == "" {
		receiptProfile = "v1"
	}
	if receiptProfile == "v2" {
		if strings.TrimSpace(db) == "" {
			return "", Errf("RECEIPT_DECISION_BINDING_MISSING", "decision_binding missing (receipt_profile=v2)")
		}
		expected := SHA256Hex(SafeHashEncode([]string{
			mustStr(receipt, "decision_hash"),
			mustStr(receipt, "token_jti"),
			mustStr(receipt, "action_id"),
			mustStr(receipt, "tool_name"),
			mustStr(receipt, "params_hash"),
		}))
		if db != expected {
			return "", Errf("RECEIPT_DECISION_BINDING_MISMATCH", "decision_binding mismatch")
		}
	}
	if strings.TrimSpace(db) != "" {
		components = append(components, db)
	}

	components = append(components,
		mustStr(receipt, "result_hash"),
		optStr(receipt, "response_hash"),
		mustStr(receipt, "result_status"),
		mustStr(receipt, "invoked_at_utc"),
		mustStr(receipt, "completed_at_utc"),
		fmt.Sprintf("%v", receipt["duration_ms"]),
		optStr(receipt, "prev_receipt_hash"),
	)

	payload := SafeHashEncode(components)

	sigB64 := mustStr(receipt, "signature")
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return "", Wrap("RECEIPT_SIGNATURE_BASE64", err, "invalid base64 signature")
	}
	if len(sig) != ed25519.SignatureSize {
		return "", Errf("RECEIPT_SIGNATURE_LENGTH", "invalid signature length")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return "", Errf("RECEIPT_SIGNATURE_INVALID", "receipt signature invalid")
	}

	computed := SHA256Hex(payload)
	embedded := optStr(receipt, "receipt_hash")
	if embedded != "" && embedded != computed {
		return "", Errf("RECEIPT_HASH_MISMATCH", "receipt_hash mismatch")
	}
	return computed, nil
}
