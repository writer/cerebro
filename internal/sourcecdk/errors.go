package sourcecdk

import (
	"errors"
	"strings"
)

// ErrorKind classifies source failures without relying on provider-specific text.
type ErrorKind string

const (
	ErrorKindInvalidConfig ErrorKind = "invalid_source_config"
	ErrorKindAuth          ErrorKind = "auth"
	ErrorKindPermission    ErrorKind = "permission"
	ErrorKindRateLimited   ErrorKind = "rate_limited"
	ErrorKindProvider      ErrorKind = "provider"
	ErrorKindTransient     ErrorKind = "transient"
	ErrorKindDecode        ErrorKind = "decode"
	ErrorKindInvalidEvent  ErrorKind = "invalid_event"
)

// SourceError carries a stable source failure classification plus bounded labels.
type SourceError struct {
	Kind     ErrorKind
	SourceID string
	Family   string
	Err      error
}

func (e *SourceError) Error() string {
	if e == nil {
		return ""
	}
	parts := []string{string(e.Kind)}
	if sourceID := strings.TrimSpace(e.SourceID); sourceID != "" {
		parts = append(parts, "source="+sourceID)
	}
	if family := strings.TrimSpace(e.Family); family != "" {
		parts = append(parts, "family="+family)
	}
	message := strings.Join(parts, " ")
	if e.Err == nil {
		return message
	}
	return message + ": " + e.Err.Error()
}

func (e *SourceError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// WrapSourceError annotates err with a stable source error kind.
func WrapSourceError(kind ErrorKind, sourceID string, family string, err error) error {
	if err == nil {
		return nil
	}
	return &SourceError{Kind: kind, SourceID: strings.TrimSpace(sourceID), Family: strings.TrimSpace(family), Err: err}
}

// SourceErrorKind returns the stable classification for err.
func SourceErrorKind(err error) ErrorKind {
	if err == nil {
		return ""
	}
	var sourceErr *SourceError
	if errors.As(err, &sourceErr) && sourceErr != nil && sourceErr.Kind != "" {
		return sourceErr.Kind
	}
	if errors.Is(err, ErrInvalidConfig) {
		return ErrorKindInvalidConfig
	}
	if IsRetryableHTTPStatus(err) {
		return ErrorKindTransient
	}
	return ErrorKindProvider
}
