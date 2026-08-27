package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errApideckRustProjectionRequired = errors.New("apideck projection requires Rust authority")

// apideckLedgerAccountProjections previously delegated to the shared
// identityUserProjections helper (still used by rivery, torii, appgate,
// robin, tallyfy, matillion, gsmtasks, and others), so it keeps its own
// fail-closed wrapper here rather than touching that helper.
func apideckLedgerAccountProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errApideckRustProjectionRequired
}

func apideckBillProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errApideckRustProjectionRequired
}

func apideckCreditNoteProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errApideckRustProjectionRequired
}

func apideckCustomerProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errApideckRustProjectionRequired
}
