package bootstrap

import (
	"context"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

type securityLifecycleQueryReader interface {
	ListSecurityLifecycle(context.Context, *cerebrov1.SecurityLifecycleQuery) (*cerebrov1.SecurityLifecycleQueryResult, error)
	ResolveSecurityLifecycleFinding(context.Context, string, string) (*cerebrov1.ResolveSecurityLifecycleFindingResponse, error)
}
