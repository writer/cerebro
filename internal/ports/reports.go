package ports

import (
	"context"
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// ErrReportRunNotFound indicates that a persisted report run does not exist.
var ErrReportRunNotFound = errors.New("report run not found")

// ReportStore persists durable report runs in the state store.
type ReportStore interface {
	StateStore
	PutReportRun(context.Context, *cerebrov1.ReportRun) error
	GetReportRun(context.Context, string) (*cerebrov1.ReportRun, error)
}
