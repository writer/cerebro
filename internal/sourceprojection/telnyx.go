package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errTelnyxRustProjectionRequired = errors.New("telnyx projection requires Rust authority")

// telnyxCallEventProjections, telnyxNotificationEventProjections,
// telnyxNotificationEventConditionProjections, and
// telnyxWirelessConnectivityLogProjections previously dispatched to the
// shared identityAuditProjections helper. telnyxBillingGroupProjections,
// telnyxSimCardGroupProjections, and telnyxSimCardGroupActionProjections
// previously dispatched to the shared identityGroupProjections helper.
// telnyxManagedAccountProjections previously dispatched to the shared
// identityUserProjections helper. They now fail closed on their own so those
// shared helpers (still used by other providers) are left untouched.

func telnyxCallEventProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errTelnyxRustProjectionRequired
}

func telnyxBillingGroupProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errTelnyxRustProjectionRequired
}

func telnyxCredentialConnectionProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errTelnyxRustProjectionRequired
}

func telnyxManagedAccountProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errTelnyxRustProjectionRequired
}

func telnyxCallControlApplicationProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errTelnyxRustProjectionRequired
}

func telnyxNotificationChannelProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errTelnyxRustProjectionRequired
}

func telnyxDetailRecordsReportProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errTelnyxRustProjectionRequired
}

func telnyxNotificationEventProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errTelnyxRustProjectionRequired
}

func telnyxNotificationEventConditionProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errTelnyxRustProjectionRequired
}

func telnyxWirelessConnectivityLogProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errTelnyxRustProjectionRequired
}

func telnyxSimCardGroupProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errTelnyxRustProjectionRequired
}

func telnyxSimCardGroupActionProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errTelnyxRustProjectionRequired
}
