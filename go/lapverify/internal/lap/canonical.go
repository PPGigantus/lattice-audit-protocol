package lap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ParseJSON parses JSON using UseNumber so numbers round-trip deterministically.
func ParseJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, Wrap("JSON_PARSE_ERROR", err, "invalid JSON")
	}
	return v, nil
}

// CanonicalJSON implements LAP Canonical JSON v1 (legacy/permissive) as used by early verify.py:
// json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
//
// NOTE: v1 is permissive and will stringify unknown types. For protocol interop,
// prefer CanonicalJSONV2 / CanonicalJSONVersion.
func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v, true); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CanonicalJSONV2 implements LAP Canonical JSON v2 (strict):
// json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
//
// v2 rejects non-JSON types rather than stringifying them.
func CanonicalJSONV2(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v, false); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CanonicalJSONVersion selects the canonical JSON variant ("v1" or "v2").
// Empty defaults to v2.
func CanonicalJSONVersion(v any, version string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(version)) {
	case "v1":
		return CanonicalJSON(v)
	case "v2", "":
		return CanonicalJSONV2(v)
	default:
		return nil, Errf("CANONICAL_VERSION_UNKNOWN", "unknown canonical_json_version: %s", version)
	}
}

func writeCanonical(buf *bytes.Buffer, v any, allowDefaultString bool) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		b, _ := json.Marshal(x)
		buf.Write(b)
	case json.Number:
		buf.WriteString(x.String())
	case float64:
		buf.WriteString(strconv.FormatFloat(x, 'g', -1, 64))
	case []any:
		buf.WriteByte('[')
		for i, it := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, it, allowDefaultString); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k], allowDefaultString); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		if allowDefaultString {
			b, _ := json.Marshal(fmt.Sprint(x))
			buf.Write(b)
			return nil
		}
		return Errf("CANONICAL_NONJSON_TYPE", "non-JSON type encountered in canonical v2: %T", v)
	}
	return nil
}
