package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errGitguardianRustProjectionRequired = errors.New("gitguardian projection requires Rust authority")

func gitguardianIncidentsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errGitguardianRustProjectionRequired
}

// gitguardianMembersProjections previously dispatched straight to the shared
// identityUserProjections helper. It now fails closed on its own so that
// shared helper (still used by other identity-user providers) is left
// untouched.
func gitguardianMembersProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errGitguardianRustProjectionRequired
}

// gitguardianAuditEventsProjections previously dispatched straight to the
// shared identityAuditProjections helper. It now fails closed on its own so
// that shared helper (still used by other identity-audit providers) is left
// untouched.
func gitguardianAuditEventsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errGitguardianRustProjectionRequired
}
