package sourcecdk

import (
	"context"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
)

// ProviderClientFactory constructs a provider client from parsed source settings.
type ProviderClientFactory[S any, C any] func(context.Context, S) (C, error)

// PageReader captures the common source shape: make a client, list one provider
// page, normalize records into events, and carry a next cursor token.
type PageReader[S any, C any, R any] struct {
	SourceID string
	Family   string
	Label    string
	Clients  ProviderClientFactory[S, C]
	List     func(context.Context, C, S, string, int) ([]R, string, error)
	Event    func(S, R) (*primitives.Event, error)
	URN      func(S, R) (URN, error)
	PageSize func(S) int
}

// FamilyFromPageReader converts a PageReader into a Family entry.
func FamilyFromPageReader[S any, C any, R any](reader PageReader[S, C, R]) Family[S] {
	return Family[S]{
		Name: strings.TrimSpace(reader.Family),
		Discover: func(ctx context.Context, settings S) ([]URN, error) {
			records, _, err := readProviderPage(ctx, settings, nil, reader, "")
			if err != nil {
				return nil, err
			}
			urns := make([]URN, 0, len(records))
			for _, record := range records {
				if reader.URN == nil {
					continue
				}
				urn, err := reader.URN(settings, record)
				if err != nil {
					return nil, err
				}
				urns = append(urns, urn)
			}
			return urns, nil
		},
		Read: func(ctx context.Context, settings S, cursor *cerebrov1.SourceCursor) (Pull, error) {
			records, next, err := readProviderPage(ctx, settings, cursor, reader, CursorToken(cursor))
			if err != nil {
				return Pull{}, err
			}
			events := make([]*primitives.Event, 0, len(records))
			for _, record := range records {
				if reader.Event == nil {
					return Pull{}, fmt.Errorf("page reader %q event mapper is required", readerLabel(reader))
				}
				event, err := reader.Event(settings, record)
				if err != nil {
					return Pull{}, err
				}
				if event != nil {
					events = append(events, event)
				}
			}
			pull := Pull{Events: events}
			if strings.TrimSpace(next) != "" {
				pull.NextCursor = &cerebrov1.SourceCursor{Opaque: strings.TrimSpace(next)}
			}
			return pull, nil
		},
	}
}

func readProviderPage[S any, C any, R any](ctx context.Context, settings S, _ *cerebrov1.SourceCursor, reader PageReader[S, C, R], token string) ([]R, string, error) {
	if reader.Clients == nil {
		return nil, "", fmt.Errorf("page reader %q client factory is required", readerLabel(reader))
	}
	if reader.List == nil {
		return nil, "", fmt.Errorf("page reader %q list function is required", readerLabel(reader))
	}
	client, err := reader.Clients(ctx, settings)
	if err != nil {
		return nil, "", err
	}
	records, next, err := reader.List(ctx, client, settings, strings.TrimSpace(token), providerPageSize(reader, settings))
	if err != nil {
		return nil, "", err
	}
	return records, strings.TrimSpace(next), nil
}

func providerPageSize[S any, C any, R any](reader PageReader[S, C, R], settings S) int {
	if reader.PageSize == nil {
		return 0
	}
	return reader.PageSize(settings)
}

func readerLabel[S any, C any, R any](reader PageReader[S, C, R]) string {
	for _, value := range []string{reader.Label, reader.Family, reader.SourceID} {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return "source"
}
