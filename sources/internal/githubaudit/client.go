package githubaudit

import (
	"context"
	"errors"
	"net/http"

	gogithub "github.com/google/go-github/v66/github"
)

// GetAuditLog fetches an audit-log page and treats unavailable audit-log
// access as an empty page so source runtimes can record a completed run.
func GetAuditLog(ctx context.Context, client *gogithub.Client, owner string, opts *gogithub.GetAuditLogOptions) ([]*gogithub.AuditEntry, *gogithub.Response, error) {
	entries, resp, err := client.Organizations.GetAuditLog(ctx, owner, opts)
	if AuditLogUnavailable(err) {
		return nil, nil, nil
	}
	return entries, resp, err
}

func AuditLogUnavailable(err error) bool {
	var apiErr *gogithub.ErrorResponse
	if !errors.As(err, &apiErr) || apiErr.Response == nil {
		return false
	}
	switch apiErr.Response.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	default:
		return false
	}
}
