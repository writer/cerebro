// Package cerrors provides sentinel errors and error handling utilities for Cerebro.
package cerrors

import (
	"errors"
	"fmt"
)

// Sentinel errors for common failure conditions.
// Use errors.Is() to check for these errors.
var (
	// Database errors
	ErrNotFound      = errors.New("resource not found")
	ErrAlreadyExists = errors.New("resource already exists")
	ErrDBConnection  = errors.New("database connection failed")
	ErrDBQuery       = errors.New("database query failed")
	ErrDBTimeout     = errors.New("database operation timed out")

	// Validation errors
	ErrInvalidInput    = errors.New("invalid input")
	ErrMissingRequired = errors.New("missing required field")
	ErrInvalidFormat   = errors.New("invalid format")

	// Policy errors
	ErrPolicyNotFound   = errors.New("policy not found")
	ErrPolicyInvalid    = errors.New("policy is invalid")
	ErrPolicyEvaluation = errors.New("policy evaluation failed")

	// Finding errors
	ErrFindingNotFound = errors.New("finding not found")

	// Authentication/Authorization errors
	ErrUnauthorized  = errors.New("unauthorized")
	ErrForbidden     = errors.New("forbidden")
	ErrInvalidAPIKey = errors.New("invalid API key")
	ErrRateLimited   = errors.New("rate limit exceeded")

	// Provider errors
	ErrProviderNotFound = errors.New("provider not found")
	ErrProviderConfig   = errors.New("provider configuration error")
	ErrProviderAuth     = errors.New("provider authentication failed")
	ErrProviderSync     = errors.New("provider sync failed")

	// Agent errors
	ErrAgentNotFound   = errors.New("agent not found")
	ErrSessionNotFound = errors.New("session not found")
	ErrLLMProvider     = errors.New("LLM provider error")

	// Ticketing errors
	ErrTicketNotFound    = errors.New("ticket not found")
	ErrTicketingProvider = errors.New("ticketing provider error")

	// Notification errors
	ErrNotificationFailed = errors.New("notification delivery failed")

	// Context errors
	ErrContextCanceled = errors.New("operation canceled")
	ErrContextTimeout  = errors.New("operation timed out")
)

// Op represents an operation name for error context.
type Op string

// Error represents an application error with context.
type Error struct {
	Op   Op     // Operation that failed
	Kind error  // Category of error (sentinel)
	Err  error  // Underlying error
	Msg  string // Additional context message
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}

	cause := e.Err
	if cause == nil {
		cause = e.Kind
	}

	switch {
	case e.Op != "" && e.Msg != "" && cause != nil:
		return fmt.Sprintf("%s: %s: %v", e.Op, e.Msg, cause)
	case e.Op != "" && e.Msg != "":
		return fmt.Sprintf("%s: %s", e.Op, e.Msg)
	case e.Op != "" && cause != nil:
		return fmt.Sprintf("%s: %v", e.Op, cause)
	case e.Op != "":
		return string(e.Op)
	case e.Msg != "" && cause != nil:
		return fmt.Sprintf("%s: %v", e.Msg, cause)
	case e.Msg != "":
		return e.Msg
	case cause != nil:
		return cause.Error()
	}

	return ""
}

func (e *Error) Unwrap() error {
	return e.Err
}

// Is reports whether the error matches the target.
func (e *Error) Is(target error) bool {
	if e.Kind != nil && errors.Is(e.Kind, target) {
		return true
	}
	return errors.Is(e.Err, target)
}

// E constructs an Error. Arguments can be:
// - Op: the operation name
// - error: the underlying error or sentinel error kind
// - string: additional context message
func E(args ...interface{}) error {
	e := &Error{}
	for _, arg := range args {
		switch a := arg.(type) {
		case Op:
			e.Op = joinOps(e.Op, a)
		case error:
			// If it's a sentinel error, set Kind; otherwise set Err
			if isSentinel(a) {
				e.Kind = joinErrors(e.Kind, a)
			} else {
				e.Err = joinErrors(e.Err, a)
			}
		case string:
			e.Msg = joinMessages(e.Msg, a)
		}
	}
	return e
}

// isSentinel checks if an error is one of our sentinel errors.
func isSentinel(err error) bool {
	sentinels := []error{
		ErrNotFound, ErrAlreadyExists, ErrDBConnection, ErrDBQuery, ErrDBTimeout,
		ErrInvalidInput, ErrMissingRequired, ErrInvalidFormat,
		ErrPolicyNotFound, ErrPolicyInvalid, ErrPolicyEvaluation,
		ErrFindingNotFound,
		ErrUnauthorized, ErrForbidden, ErrInvalidAPIKey, ErrRateLimited,
		ErrProviderNotFound, ErrProviderConfig, ErrProviderAuth, ErrProviderSync,
		ErrAgentNotFound, ErrSessionNotFound, ErrLLMProvider,
		ErrTicketNotFound, ErrTicketingProvider,
		ErrNotificationFailed,
		ErrContextCanceled, ErrContextTimeout,
	}
	for _, s := range sentinels {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
}

// Wrap wraps an error with operation context.
func Wrap(op Op, err error) error {
	if err == nil {
		return nil
	}
	return E(op, err)
}

// Wrapf wraps an error with operation context and a formatted message.
func Wrapf(op Op, err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	return E(op, err, fmt.Sprintf(format, args...))
}

// IsNotFound reports whether err is or wraps ErrNotFound.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound) ||
		errors.Is(err, ErrPolicyNotFound) ||
		errors.Is(err, ErrFindingNotFound) ||
		errors.Is(err, ErrAgentNotFound) ||
		errors.Is(err, ErrSessionNotFound) ||
		errors.Is(err, ErrProviderNotFound) ||
		errors.Is(err, ErrTicketNotFound)
}

// IsValidation reports whether err is a validation error.
func IsValidation(err error) bool {
	return errors.Is(err, ErrInvalidInput) ||
		errors.Is(err, ErrMissingRequired) ||
		errors.Is(err, ErrInvalidFormat)
}

// IsAuth reports whether err is an authentication/authorization error.
func IsAuth(err error) bool {
	return errors.Is(err, ErrUnauthorized) ||
		errors.Is(err, ErrForbidden) ||
		errors.Is(err, ErrInvalidAPIKey)
}

// IsTimeout reports whether err is a timeout error.
func IsTimeout(err error) bool {
	return errors.Is(err, ErrDBTimeout) || errors.Is(err, ErrContextTimeout)
}

func joinErrors(existing, next error) error {
	switch {
	case existing == nil:
		return next
	case next == nil:
		return existing
	default:
		return errors.Join(existing, next)
	}
}

func joinMessages(existing, next string) string {
	switch {
	case existing == "":
		return next
	case next == "":
		return existing
	default:
		return existing + ": " + next
	}
}

func joinOps(existing, next Op) Op {
	switch {
	case existing == "":
		return next
	case next == "":
		return existing
	default:
		return Op(fmt.Sprintf("%s -> %s", existing, next))
	}
}
