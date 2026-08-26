package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errQdrantCloudRustProjectionRequired = errors.New("qdrant_cloud projection requires Rust authority")

func qdrantCloudAccountsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errQdrantCloudRustProjectionRequired
}

func qdrantCloudAccountMembersProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errQdrantCloudRustProjectionRequired
}

func qdrantCloudClustersProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errQdrantCloudRustProjectionRequired
}

func qdrantCloudDatabaseApiKeysProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errQdrantCloudRustProjectionRequired
}

func qdrantCloudBackupsProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errQdrantCloudRustProjectionRequired
}

func qdrantCloudBackupRestoresProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errQdrantCloudRustProjectionRequired
}

func qdrantCloudBackupSchedulesProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errQdrantCloudRustProjectionRequired
}

func qdrantCloudRolesProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errQdrantCloudRustProjectionRequired
}
