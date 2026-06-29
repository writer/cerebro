package sourceprojection

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func bamboohrUsersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, identityProjectionProfile{Provider: "bamboohr"})
}

func bamboohrGroupsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, identityProjectionProfile{Provider: "bamboohr"})
}

func bamboohrAuditEventsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, identityProjectionProfile{Provider: "bamboohr"})
}
