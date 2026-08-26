package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errAppwriteRustProjectionRequired = errors.New("appwrite projection requires Rust authority")

func appwriteTeamProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAppwriteRustProjectionRequired
}

func appwriteLogProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAppwriteRustProjectionRequired
}

func appwriteMembershipProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAppwriteRustProjectionRequired
}

func appwriteContinentProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errAppwriteRustProjectionRequired
}
