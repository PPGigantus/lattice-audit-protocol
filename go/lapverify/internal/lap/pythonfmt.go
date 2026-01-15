package lap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

// PyBoolString matches Python str(True/False) => "True"/"False".
func PyBoolString(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

// PyJSONDumpsSortKeys reproduces Python json.dumps(obj, sort_keys=True)
// with default separators (", ", ": ") for the specific budget map shape.
// It is only used for token signature payload compatibility.
func PyJSONDumpsSortKeys(obj any) (string, error) {
	// Handle the common case: map[string]any
	m, ok := obj.(map[string]any)
	if !ok {
		// If it's already a struct or something, fall back to json.Marshal and
		// accept that this should not be used for signature-critical paths.
		b, err := json.Marshal(obj)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteString(", ")
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteString(": ")
		buf.WriteString(pyValueDefaultSpacing(m[k]))
	}
	buf.WriteByte('}')
	return buf.String(), nil
}

func pyValueDefaultSpacing(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		if x {
			return "true"
		}
		return "false"
	case string:
		b, _ := json.Marshal(x)
		return string(b)
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case map[string]any:
		s, _ := PyJSONDumpsSortKeys(x)
		return s
	case []any:
		// Default Python dumps has spaces after commas in lists too
		var buf bytes.Buffer
		buf.WriteByte('[')
		for i, it := range x {
			if i > 0 {
				buf.WriteString(", ")
			}
			buf.WriteString(pyValueDefaultSpacing(it))
		}
		buf.WriteByte(']')
		return buf.String()
	default:
		return fmt.Sprint(x)
	}
}
