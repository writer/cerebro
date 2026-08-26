package sourceprojection

import (
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var errDeepSeekRustProjectionRequired = errors.New("deepseek projection requires Rust authority")

func deepseekModelCatalogProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDeepSeekRustProjectionRequired
}

func deepseekAccountBalancesProjections(_ *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return nil, nil, errDeepSeekRustProjectionRequired
}
