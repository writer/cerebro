package reports

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidReportRequest indicates that the request payload or parameters are invalid.
	ErrInvalidReportRequest = errors.New("invalid report request")
)

func invalidReportRequest(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidReportRequest, message)
}

func invalidReportRequestf(format string, args ...any) error {
	return invalidReportRequest(fmt.Sprintf(format, args...))
}
