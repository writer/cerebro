package sync

import "errors"

type partialFetchError struct {
	err error
}

func (e *partialFetchError) Error() string {
	if e == nil || e.err == nil {
		return "partial fetch"
	}
	return "partial fetch: " + e.err.Error()
}

func (e *partialFetchError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func newPartialFetchError(err error) error {
	if err == nil {
		return nil
	}
	return &partialFetchError{err: err}
}

func isPartialFetchError(err error) bool {
	var partialErr *partialFetchError
	return errors.As(err, &partialErr)
}
