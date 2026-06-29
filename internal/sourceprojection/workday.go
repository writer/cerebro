package sourceprojection

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func workdayUsersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, identityProjectionProfile{Provider: "workday"})
}

func workdayGroupsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, identityProjectionProfile{Provider: "workday"})
}

func workdayAuditEventsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, identityProjectionProfile{Provider: "workday"})
}
