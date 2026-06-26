package githubapi

import (
	"errors"
	"fmt"
	"net/http"

	gogithub "github.com/google/go-github/v66/github"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func NotFound(err error) bool {
	status, ok := ErrorStatus(err)
	return ok && status == http.StatusNotFound
}

func ProviderUnavailable(err error) bool {
	status, ok := ErrorStatus(err)
	if !ok {
		return false
	}
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	default:
		return false
	}
}

func ErrorStatus(err error) (int, bool) {
	var apiErr *gogithub.ErrorResponse
	if errors.As(err, &apiErr) && apiErr.Response != nil {
		return apiErr.Response.StatusCode, true
	}
	var statusErr interface{ HTTPStatus() int }
	if errors.As(err, &statusErr) {
		status := statusErr.HTTPStatus()
		return status, status > 0
	}
	return 0, false
}

func LookupError(subject string, err error) error {
	if err == nil {
		return nil
	}
	if NotFound(err) {
		return fmt.Errorf("%s not found: %w", subject, err)
	}
	return fmt.Errorf("%s: %w", subject, err)
}

func ProviderUnavailableLookupError(subject string, err error, allow bool) error {
	if err == nil {
		return nil
	}
	if allow && ProviderUnavailable(err) {
		return nil
	}
	return LookupError(subject, err)
}

func ProviderUnavailableOrError(err error, allow bool) error {
	if allow && ProviderUnavailable(err) {
		return nil
	}
	return err
}

func ProviderUnavailablePull(checkpoint *cerebrov1.SourceCheckpoint) sourcecdk.Pull {
	pull := sourcecdk.NotModifiedPull(checkpoint)
	if pull.ShortCircuitReason == "" {
		pull.ShortCircuitReason = sourcecdk.PullShortCircuitReasonNotModified
	}
	return pull
}
