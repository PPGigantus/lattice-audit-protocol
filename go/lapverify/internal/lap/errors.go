package lap

import (
	"errors"
	"fmt"
)

// VerifyError is a structured verification error with a stable machine-readable Code.
// Detail is human-readable and may include context.
// Cause may wrap an underlying error.
type VerifyError struct {
	Code   string
	Detail string
	Cause  error
}

func (e *VerifyError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Cause != nil {
		if e.Detail != "" {
			return fmt.Sprintf("%s: %s: %v", e.Code, e.Detail, e.Cause)
		}
		return fmt.Sprintf("%s: %v", e.Code, e.Cause)
	}
	if e.Detail != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Detail)
	}
	return e.Code
}

func (e *VerifyError) Unwrap() error { return e.Cause }

// Errf creates a VerifyError with formatted detail.
func Errf(code string, format string, args ...any) error {
	return &VerifyError{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// Wrap wraps an underlying error with a stable code and detail.
func Wrap(code string, err error, detail string) error {
	if err == nil {
		return nil
	}
	return &VerifyError{Code: code, Detail: detail, Cause: err}
}

// Wrapf wraps an underlying error with a stable code and formatted detail.
func Wrapf(code string, err error, format string, args ...any) error {
	if err == nil {
		return nil
	}
	return &VerifyError{Code: code, Detail: fmt.Sprintf(format, args...), Cause: err}
}



// Contextf prefixes VerifyError detail with formatted context while preserving the original code.
// If err is not a VerifyError, it wraps it as UNKNOWN_ERROR.
func Contextf(err error, format string, args ...any) error {
	if err == nil {
		return nil
	}
	ctx := fmt.Sprintf(format, args...)
	if ve, ok := AsVerifyError(err); ok {
		// Preserve code, keep deepest cause.
		detail := ve.Detail
		if detail == "" {
			detail = err.Error()
		}
		return &VerifyError{Code: ve.Code, Detail: ctx + ": " + detail, Cause: ve.Cause}
	}
	return &VerifyError{Code: "UNKNOWN_ERROR", Detail: ctx + ": " + err.Error(), Cause: err}
}
// AsVerifyError finds a VerifyError in the unwrap chain.
func AsVerifyError(err error) (*VerifyError, bool) {
	if err == nil {
		return nil, false
	}
	var ve *VerifyError
	if errors.As(err, &ve) {
		return ve, true
	}
	return nil, false
}

// CodeOf returns the stable error code for err, or UNKNOWN_ERROR.
func CodeOf(err error) string {
	if ve, ok := AsVerifyError(err); ok {
		if ve.Code != "" {
			return ve.Code
		}
	}
	if err == nil {
		return "OK"
	}
	return "UNKNOWN_ERROR"
}
