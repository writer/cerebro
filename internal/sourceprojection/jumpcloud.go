package sourceprojection

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func jumpcloudUsersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, identityProjectionProfile{Provider: "jumpcloud"})
}

func jumpcloudGroupsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, identityProjectionProfile{Provider: "jumpcloud"})
}

func jumpcloudSystemsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return catalogRuntimeAssetProjections(event)
}

func jumpcloudApplicationsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityApplicationProjections(event, identityProjectionProfile{Provider: "jumpcloud"})
}

func jumpcloudSystemGroupsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, identityProjectionProfile{Provider: "jumpcloud"})
}

func jumpcloudGroupMembersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupMembershipProjections(event, identityProjectionProfile{Provider: "jumpcloud"})
}

func jumpcloudAuditEventsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, identityProjectionProfile{Provider: "jumpcloud"})
}
