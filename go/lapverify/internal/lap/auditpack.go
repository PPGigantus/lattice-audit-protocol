package lap

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type PackReader interface {
	ReadFile(name string) ([]byte, error)
	HasFile(name string) bool
	Close() error
}

type DirReader struct{ Root string }

func (d DirReader) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(d.Root, name))
}
func (d DirReader) HasFile(name string) bool {
	_, err := os.Stat(filepath.Join(d.Root, name))
	return err == nil
}
func (d DirReader) Close() error { return nil }

type ZipReader struct {
	z *zip.ReadCloser
}

func OpenZip(path string) (*ZipReader, error) {
	z, err := zip.OpenReader(path)
	if err != nil {
		return nil, Wrap("PACK_ZIP_OPEN_FAILED", err, "failed to open zip")
	}
	return &ZipReader{z: z}, nil
}
func (zr *ZipReader) Close() error { return zr.z.Close() }

func (zr *ZipReader) HasFile(name string) bool {
	for _, f := range zr.z.File {
		if f.Name == name {
			return true
		}
	}
	return false
}

func (zr *ZipReader) ReadFile(name string) ([]byte, error) {
	for _, f := range zr.z.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				return nil, Wrap("PACK_ZIP_FILE_OPEN", err, "failed to open file in zip: "+name)
			}
			defer rc.Close()
			b, err := io.ReadAll(rc)
			if err != nil {
				return nil, Wrap("PACK_ZIP_FILE_READ", err, "failed to read file in zip: "+name)
			}
			return b, nil
		}
	}
	return nil, os.ErrNotExist
}

// VerifyAuditPack verifies a pack directory or .zip matching verify.py behavior.
func VerifyAuditPack(path string, requireInvocations bool) error {
	var r PackReader
	fi, err := os.Stat(path)
	if err != nil {
		return Wrap("PACK_STAT_FAILED", err, "failed to stat pack path")
	}
	if fi.IsDir() {
		r = DirReader{Root: path}
	} else {
		zr, err := OpenZip(path)
		if err != nil {
			return err
		}
		r = zr
	}
	defer r.Close()

	manifestB, err := r.ReadFile("manifest.json")
	if err != nil {
		return Wrap("PACK_MANIFEST_READ", err, "manifest.json missing or unreadable")
	}
	mv, err := ParseJSON(manifestB)
	if err != nil {
		return Contextf(err, "manifest.json")
	}
	manifest, ok := mv.(map[string]any)
	if !ok {
		return Errf("PACK_MANIFEST_TYPE", "manifest.json must be object")
	}
	actionID := mustStr(manifest, "action_id")
	evidenceHash := mustStr(manifest, "evidence_hash")
	decisionHash := mustStr(manifest, "decision_hash")
	if strings.TrimSpace(actionID) == "" {
		return Errf("PACK_MANIFEST_MISSING_FIELD", "manifest.json missing action_id")
	}
	if strings.TrimSpace(evidenceHash) == "" {
		return Errf("PACK_MANIFEST_MISSING_FIELD", "manifest.json missing evidence_hash")
	}
	if strings.TrimSpace(decisionHash) == "" {
		return Errf("PACK_MANIFEST_MISSING_FIELD", "manifest.json missing decision_hash")
	}

	canonVersion := optStr(manifest, "canonical_json_version")
	if strings.TrimSpace(canonVersion) == "" {
		canonVersion = "v2"
	}

	receiptProfile := optStr(manifest, "receipt_profile")
	if strings.TrimSpace(receiptProfile) == "" {
		receiptProfile = "v1"
	}

	// trusted keys optional
	trusted := map[string]string{}
	if r.HasFile("trusted_keys.json") {
		tb, err := r.ReadFile("trusted_keys.json")
		if err != nil {
			return Wrap("PACK_TRUSTED_KEYS_READ", err, "trusted_keys.json unreadable")
		}
		tv, err := ParseJSON(tb)
		if err != nil {
			return Contextf(err, "trusted_keys.json")
		}
		if m, ok := tv.(map[string]any); ok {
			for k, v := range m {
				if s, ok := v.(string); ok {
					trusted[k] = s
				}
			}
		} else {
			return Errf("PACK_TRUSTED_KEYS_TYPE", "trusted_keys.json must be object")
		}
	}

	// 1 evidence
	evB, err := r.ReadFile("evidence.json")
	if err != nil {
		return Wrap("PACK_EVIDENCE_READ", err, "evidence.json missing or unreadable")
	}
	evObj, err := ParseJSON(evB)
	if err != nil {
		return Contextf(err, "evidence.json")
	}
	canon, err := CanonicalJSONVersion(evObj, canonVersion)
	if err != nil {
		return Contextf(err, "evidence.json canonical")
	}
	actualEvidence := SHA256Hex(canon)
	if actualEvidence != evidenceHash {
		return Errf("PACK_EVIDENCE_HASH_MISMATCH", "evidence_hash mismatch: expected %s got %s", evidenceHash, actualEvidence)
	}

	// 2 decision
	decB, err := r.ReadFile("decision.json")
	if err != nil {
		return Wrap("PACK_DECISION_READ", err, "decision.json missing or unreadable")
	}
	decObjAny, err := ParseJSON(decB)
	if err != nil {
		return Contextf(err, "decision.json")
	}
	decObj, ok := decObjAny.(map[string]any)
	if !ok {
		return Errf("PACK_DECISION_TYPE", "decision.json must be object")
	}
	components := []string{actionID, evidenceHash, optStr(decObj, "outcome"), optStr(decObj, "tier"), optStr(decObj, "reason")}
	actualDecision := SHA256Hex(SafeHashEncode(components))
	if actualDecision != decisionHash {
		return Errf("PACK_DECISION_HASH_MISMATCH", "decision_hash mismatch: expected %s got %s", decisionHash, actualDecision)
	}

	// 3 token (optional)
	var tokenJTI string
	if r.HasFile("token.json") {
		tb, err := r.ReadFile("token.json")
		if err != nil {
			return Wrap("PACK_TOKEN_READ", err, "token.json unreadable")
		}
		tAny, err := ParseJSON(tb)
		if err != nil {
			return Contextf(err, "token.json")
		}
		tok, ok := tAny.(map[string]any)
		if !ok {
			return Errf("PACK_TOKEN_TYPE", "token.json must be object")
		}
		tokenJTI = optStr(tok, "jti")
		if err := VerifyToken(tok, trusted); err != nil {
			return Contextf(err, "token.json")
		}
	}

	// 4 receipts (optional)
	if r.HasFile("receipts.json") {
		rb, err := r.ReadFile("receipts.json")
		if err != nil {
			return Wrap("PACK_RECEIPTS_READ", err, "receipts.json unreadable")
		}
		rAny, err := ParseJSON(rb)
		if err != nil {
			return Contextf(err, "receipts.json")
		}
		recList, ok := rAny.([]any)
		if !ok {
			return Errf("PACK_RECEIPTS_TYPE", "receipts.json must be list")
		}

		// Optional invocations list (for commitment verification)
		invMap := map[string]map[string]any{}
		hasInv := false
		if r.HasFile("invocations.json") {
			hasInv = true
			ib, err := r.ReadFile("invocations.json")
			if err != nil {
				return Wrap("PACK_INVOCATIONS_READ", err, "invocations.json unreadable")
			}
			iAny, err := ParseJSON(ib)
			if err != nil {
				return Contextf(err, "invocations.json")
			}
			rows, ok := iAny.([]any)
			if !ok {
				return Errf("PACK_INVOCATIONS_TYPE", "invocations.json must be list")
			}
			for _, rowAny := range rows {
				if row, ok := rowAny.(map[string]any); ok {
					rid := optStr(row, "receipt_id")
					if rid != "" {
						invMap[rid] = row
					}
				}
			}
		}
		if requireInvocations && !hasInv {
			return Errf("PACK_INVOCATIONS_REQUIRED_MISSING", "invocations.json required but missing")
		}

		prev := ""
		for idx, recAny := range recList {
			rec, ok := recAny.(map[string]any)
			if !ok {
				return Errf("PACK_RECEIPT_TYPE", "receipt %d not object", idx)
			}
			// Optional token_jti binding if token exists
			if tokenJTI != "" {
				if optStr(rec, "token_jti") != tokenJTI {
					// keep soft, matching Python verifier behavior
				}
			}
			computed, err := VerifyReceipt(rec, trusted, receiptProfile)
			if err != nil {
				return Contextf(err, "receipt %d", idx)
			}
			// chain
			if optStr(rec, "prev_receipt_hash") != prev {
				return Errf("PACK_RECEIPT_CHAIN_MISMATCH", "receipt %d: prev_receipt_hash mismatch", idx)
			}
			// commitments check
			if inv, ok := invMap[optStr(rec, "receipt_id")]; ok {
				if p, ok := inv["params"]; ok {
					if ch, err := canonicalCompactVersion(p, "v1"); err == nil {
						if SHA256Hex(ch) != optStr(rec, "params_hash") {
							return Errf("PACK_PARAMS_HASH_MISMATCH", "receipt %d: params_hash mismatch", idx)
						}
					} else {
						return Contextf(err, "invocations params canonical")
					}
				}
				if res, ok := inv["result"]; ok {
					if ch, err := canonicalCompactVersion(res, "v1"); err == nil {
						if SHA256Hex(ch) != optStr(rec, "result_hash") {
							return Errf("PACK_RESULT_HASH_MISMATCH", "receipt %d: result_hash mismatch", idx)
						}
					} else {
						return Contextf(err, "invocations result canonical")
					}
				}
				if resp, ok := inv["response_envelope"]; ok {
					if ch, err := canonicalCompactVersion(resp, "v1"); err == nil {
						if SHA256Hex(ch) != optStr(rec, "response_hash") {
							return Errf("PACK_RESPONSE_HASH_MISMATCH", "receipt %d: response_hash mismatch", idx)
						}
					} else {
						return Contextf(err, "invocations response_envelope canonical")
					}
				}
			}
			prev = computed
		}
	}

	// 5 attestations (optional)
	if r.HasFile("attestations.jsonl") {
		ab, err := r.ReadFile("attestations.jsonl")
		if err != nil {
			return Wrap("PACK_ATTESTATIONS_READ", err, "attestations.jsonl unreadable")
		}
		lines := strings.Split(string(ab), "\n")
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			stAny, err := ParseJSON([]byte(line))
			if err != nil {
				return Contextf(err, "attestations.jsonl line %d", i+1)
			}
			st, ok := stAny.(map[string]any)
			if !ok {
				return Errf("PACK_ATTESTATION_TYPE", "attestations.jsonl line %d: not an object", i+1)
			}
			predAny, ok := st["predicate"].(map[string]any)
			if ok {
				if optStr(predAny, "action_id") != "" && optStr(predAny, "action_id") != actionID {
					return Errf("PACK_ATTESTATION_BINDING_MISMATCH", "attestation line %d: action_id mismatch", i+1)
				}
				if optStr(predAny, "evidence_hash") != "" && optStr(predAny, "evidence_hash") != evidenceHash {
					return Errf("PACK_ATTESTATION_BINDING_MISMATCH", "attestation line %d: evidence_hash mismatch", i+1)
				}
				if optStr(predAny, "decision_hash") != "" && optStr(predAny, "decision_hash") != decisionHash {
					return Errf("PACK_ATTESTATION_BINDING_MISMATCH", "attestation line %d: decision_hash mismatch", i+1)
				}
			}
		}
	}

	// 6 DSSE envelope (optional convenience file)
	if r.HasFile("attestation.dsse.json") {
		envB, err := r.ReadFile("attestation.dsse.json")
		if err != nil {
			return Wrap("PACK_DSSE_READ", err, "attestation.dsse.json unreadable")
		}
		envAny, err := ParseJSON(envB)
		if err != nil {
			return Contextf(err, "attestation.dsse.json")
		}
		env, ok := envAny.(map[string]any)
		if !ok {
			return Errf("PACK_DSSE_TYPE", "attestation.dsse.json must be object")
		}
		if err := VerifyEnvelope(env, trusted); err != nil {
			return Contextf(err, "attestation.dsse.json")
		}
	}

	return nil
}

// canonicalCompactVersion matches verify.py canon() and supports Canonical JSON v1/v2.
func canonicalCompactVersion(v any, version string) ([]byte, error) {
	return CanonicalJSONVersion(v, version)
}
