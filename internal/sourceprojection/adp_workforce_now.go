package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errAdpWorkforceNowRustProjectionRequired = errors.New("adp_workforce_now projection requires Rust authority")

func adpWorkforceNowUsersProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAdpWorkforceNowRustProjectionRequired
}

func adpWorkforceNowEventNotificationsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAdpWorkforceNowRustProjectionRequired
}
