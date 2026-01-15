package lap

import (
	"os"
	"path/filepath"
)

type VectorFile struct {
	Format  string       `json:"format"`
	Version int          `json:"version"`
	Note    string       `json:"note"`
	Cases   []VectorCase `json:"cases"`
}

type VectorCase struct {
	Name                string            `json:"name"`
	Type                string            `json:"type"`
	InputFile           string            `json:"input_file"`
	TokenFile           string            `json:"token_file"`
	ReceiptFile         string            `json:"receipt_file"`
	TrustedKeys         map[string]string `json:"trusted_keys"`
	Expected            string            `json:"expected"`
	ActionID            string            `json:"action_id"`
	EvidenceHash        string            `json:"evidence_hash"`
	ExpectedReceiptHash string            `json:"expected_receipt_hash"`
	ExpectOK            *bool             `json:"expect_ok"`
	Path                string            `json:"path"`
	RequireInvocations  bool              `json:"require_invocations"`
}

type VectorFailure struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type VectorResult struct {
	Passed   int             `json:"passed"`
	Failed   int             `json:"failed"`
	Failures []VectorFailure `json:"failures,omitempty"`
}

func VerifyVectorsDir(dir string) (VectorResult, error) {
	vecPath := filepath.Join(dir, "vectors.json")
	b, err := os.ReadFile(vecPath)
	if err != nil {
		return VectorResult{}, Wrap("VECTORS_READ", err, "failed to read vectors.json")
	}
	vAny, err := ParseJSON(b)
	if err != nil {
		return VectorResult{}, Contextf(err, "vectors.json")
	}
	vm, ok := vAny.(map[string]any)
	if !ok {
		return VectorResult{}, Errf("VECTORS_TYPE", "vectors.json must be object")
	}
	casesAny, ok := vm["cases"].([]any)
	if !ok {
		return VectorResult{}, Errf("VECTORS_STRUCTURE", "vectors.json missing cases list")
	}

	res := VectorResult{}
	for i, cAny := range casesAny {
		cm, ok := cAny.(map[string]any)
		if !ok {
			res.Failed++
			res.Failures = append(res.Failures, VectorFailure{Name: "", Type: "", Code: "VECTOR_CASE_TYPE", Detail: "case is not an object"})
			_ = i
			continue
		}
		typ := mustStr(cm, "type")
		name := mustStr(cm, "name")
		err := runVectorCase(dir, typ, cm)
		if err != nil {
			res.Failed++
			code := CodeOf(err)
			detail := err.Error()
			if ve, ok := AsVerifyError(err); ok && ve.Detail != "" {
				detail = ve.Detail
			}
			res.Failures = append(res.Failures, VectorFailure{Name: name, Type: typ, Code: code, Detail: detail})
		} else {
			res.Passed++
		}
	}
	if res.Failed > 0 {
		return res, Errf("VECTORS_CASES_FAILED", "%d vector case(s) failed", res.Failed)
	}
	return res, nil
}

func runVectorCase(dir string, typ string, cm map[string]any) error {
	switch typ {
	case "evidence_hash":
		inp := mustStr(cm, "input_file")
		exp := mustStr(cm, "expected")
		canonVer := optStr(cm, "canonical_json_version")
		if canonVer == "" {
			canonVer = "v2"
		}
		b, err := os.ReadFile(filepath.Join(dir, inp))
		if err != nil {
			return Wrap("VECTOR_INPUT_READ", err, "failed to read input file: "+inp)
		}
		obj, err := ParseJSON(b)
		if err != nil {
			return Contextf(err, "vector input %s", inp)
		}
		canon, err := CanonicalJSONVersion(obj, canonVer)
		if err != nil {
			return Contextf(err, "vector input %s canonical", inp)
		}
		got := SHA256Hex(canon)
		if got != exp {
			return Errf("VECTOR_EVIDENCE_HASH_MISMATCH", "evidence_hash mismatch")
		}
		return nil
	case "params_hash":
		inp := mustStr(cm, "input_file")
		exp := mustStr(cm, "expected")
		canonVer := optStr(cm, "canonical_json_version")
		if canonVer == "" {
			canonVer = "v2"
		}
		b, err := os.ReadFile(filepath.Join(dir, inp))
		if err != nil {
			return Wrap("VECTOR_INPUT_READ", err, "failed to read input file: "+inp)
		}
		obj, err := ParseJSON(b)
		if err != nil {
			return Contextf(err, "vector input %s", inp)
		}
		canon, err := CanonicalJSONVersion(obj, canonVer)
		if err != nil {
			return Contextf(err, "vector input %s canonical", inp)
		}
		got := SHA256Hex(canon)
		if got != exp {
			return Errf("VECTOR_PARAMS_HASH_MISMATCH", "params_hash mismatch")
		}
		return nil
	case "decision_hash":
		inp := mustStr(cm, "input_file")
		exp := mustStr(cm, "expected")
		actionID := mustStr(cm, "action_id")
		evidenceHash := mustStr(cm, "evidence_hash")
		b, err := os.ReadFile(filepath.Join(dir, inp))
		if err != nil {
			return Wrap("VECTOR_INPUT_READ", err, "failed to read input file: "+inp)
		}
		objAny, err := ParseJSON(b)
		if err != nil {
			return Contextf(err, "vector input %s", inp)
		}
		obj, ok := objAny.(map[string]any)
		if !ok {
			return Errf("VECTOR_DECISION_TYPE", "decision file must be object")
		}
		comps := []string{actionID, evidenceHash, optStr(obj, "outcome"), optStr(obj, "tier"), optStr(obj, "reason")}
		got := SHA256Hex(SafeHashEncode(comps))
		if got != exp {
			return Errf("VECTOR_DECISION_HASH_MISMATCH", "decision_hash mismatch")
		}
		return nil
	case "token_verify":
		tf := mustStr(cm, "token_file")
		okExp := true
		if v, ok := cm["expect_ok"].(bool); ok {
			okExp = v
		}
		tkeys := map[string]string{}
		if tkAny, ok := cm["trusted_keys"].(map[string]any); ok {
			for k, v := range tkAny {
				if s, ok := v.(string); ok {
					tkeys[k] = s
				}
			}
		}
		b, err := os.ReadFile(filepath.Join(dir, tf))
		if err != nil {
			return Wrap("VECTOR_INPUT_READ", err, "failed to read token file: "+tf)
		}
		tAny, err := ParseJSON(b)
		if err != nil {
			return Contextf(err, "vector token %s", tf)
		}
		tok, ok := tAny.(map[string]any)
		if !ok {
			return Errf("VECTOR_TOKEN_TYPE", "token must be object")
		}
		err = VerifyToken(tok, tkeys)
		if okExp && err != nil {
			return err
		}
		if !okExp && err == nil {
			return Errf("VECTOR_EXPECTED_FAILURE", "expected failure but ok")
		}
		return nil
	case "receipt_verify":
		rf := mustStr(cm, "receipt_file")
		expHash := mustStr(cm, "expected_receipt_hash")
		tkeys := map[string]string{}
		if tkAny, ok := cm["trusted_keys"].(map[string]any); ok {
			for k, v := range tkAny {
				if s, ok := v.(string); ok {
					tkeys[k] = s
				}
			}
		}
		b, err := os.ReadFile(filepath.Join(dir, rf))
		if err != nil {
			return Wrap("VECTOR_INPUT_READ", err, "failed to read receipt file: "+rf)
		}
		rAny, err := ParseJSON(b)
		if err != nil {
			return Contextf(err, "vector receipt %s", rf)
		}
		rec, ok := rAny.(map[string]any)
		if !ok {
			return Errf("VECTOR_RECEIPT_TYPE", "receipt must be object")
		}
		got, err := VerifyReceipt(rec, tkeys, "v1")
		if err != nil {
			return err
		}
		if expHash != "" && got != expHash {
			return Errf("VECTOR_RECEIPT_HASH_MISMATCH", "receipt hash mismatch")
		}
		return nil
	case "audit_pack_verify":
		path := mustStr(cm, "path")
		reqInv := false
		if v, ok := cm["require_invocations"].(bool); ok {
			reqInv = v
		}
		full := filepath.Join(dir, path)
		full = filepath.Clean(full)
		okExp := true
		if v, ok := cm["expect_ok"].(bool); ok {
			okExp = v
		}
		err := VerifyAuditPack(full, reqInv)
		if okExp && err != nil {
			return err
		}
		if !okExp && err == nil {
			return Errf("VECTOR_EXPECTED_FAILURE", "expected failure but ok")
		}
		return nil
	default:
		return Errf("VECTORS_UNKNOWN_TYPE", "unknown vector type: %s", typ)
	}
}

