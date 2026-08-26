package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errAbnormalSecurityRustProjectionRequired = errors.New("abnormal_security projection requires Rust authority")

func abnormalSecurityResourcesProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAbnormalSecurityRustProjectionRequired
}

func abnormalSecurityThreatsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAbnormalSecurityRustProjectionRequired
}

func abnormalSecurityCasesProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAbnormalSecurityRustProjectionRequired
}

func abnormalSecurityPostureCatalogProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAbnormalSecurityRustProjectionRequired
}

// abnormalSecurityAuditEventsProjections previously dispatched straight to the
// shared identityAuditProjections helper. It now fails closed on its own so
// that shared helper (still used by other identity-audit providers) is left
// untouched.
func abnormalSecurityAuditEventsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAbnormalSecurityRustProjectionRequired
}
