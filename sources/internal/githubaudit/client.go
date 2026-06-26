package githubaudit

import (
	"context"

	gogithub "github.com/google/go-github/v66/github"

	"github.com/writer/cerebro/sources/internal/githubapi"
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
	return githubapi.ProviderUnavailable(err)
}
