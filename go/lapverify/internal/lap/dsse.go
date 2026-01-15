package lap

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
)

// VerifyEnvelope verifies a DSSE-style envelope signature against trusted keys.
// Returns nil if at least one signature verifies.
func VerifyEnvelope(env map[string]any, trustedKeys map[string]string) error {
	pt, ok := env["payloadType"].(string)
	if !ok || pt == "" {
		return Errf("DSSE_PAYLOAD_TYPE_MISSING", "envelope.payloadType missing")
	}
	payloadB64, ok := env["payload"].(string)
	if !ok || payloadB64 == "" {
		return Errf("DSSE_PAYLOAD_MISSING", "envelope.payload missing")
	}
	sigsAny, ok := env["signatures"].([]any)
	if !ok || len(sigsAny) == 0 {
		return Errf("DSSE_SIGNATURES_MISSING", "envelope.signatures missing")
	}

	msg := SafeHashEncode([]string{pt, payloadB64})

	for _, e := range sigsAny {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		keyID, _ := m["keyid"].(string)
		sigB64, _ := m["sig"].(string)
		if keyID == "" || sigB64 == "" {
			continue
		}
		pubHex, ok := trustedKeys[keyID]
		if !ok || pubHex == "" {
			continue
		}
		pub, err := hex.DecodeString(pubHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil || len(sig) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
			return nil
		}
	}

	return Errf("DSSE_NO_VALID_SIGNATURE", "no valid envelope signatures")
}
