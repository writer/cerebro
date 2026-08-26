package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errActivecampaignRustProjectionRequired = errors.New("activecampaign projection requires Rust authority")

func activecampaignUsersProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errActivecampaignRustProjectionRequired
}

func activecampaignAccountsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errActivecampaignRustProjectionRequired
}

func activecampaignContactsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errActivecampaignRustProjectionRequired
}

func activecampaignCampaignsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errActivecampaignRustProjectionRequired
}

func activecampaignAutomationsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errActivecampaignRustProjectionRequired
}
