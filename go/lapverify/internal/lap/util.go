package lap

import (
	"errors"
	"sort"
	"strings"
)

func mustStr(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok2 := v.(string); ok2 {
			return s
		}
	}
	return ""
}

func optStr(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok2 := v.(string); ok2 {
			return s
		}
	}
	return ""
}

func optBool(m map[string]any, k string) bool {
	if v, ok := m[k]; ok {
		if b, ok2 := v.(bool); ok2 {
			return b
		}
	}
	return false
}

func joinSortedStr(m map[string]any, k string) string {
	v, ok := m[k]
	if !ok || v == nil {
		return ""
	}
	arr, ok := v.([]any)
	if !ok {
		// Sometimes decode gives []interface{}, which is []any; ok.
		return ""
	}
	out := make([]string, 0, len(arr))
	for _, it := range arr {
		s, ok := it.(string)
		if !ok {
			return ""
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// RequireKey ensures required key exists.
func RequireKey(m map[string]any, k string) error {
	if _, ok := m[k]; !ok {
		return errors.New("missing required key: " + k)
	}
	return nil
}
