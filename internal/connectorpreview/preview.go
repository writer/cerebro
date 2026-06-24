package connectorpreview

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectorcredentials"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceregistry"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	maxPages  = 3
	maxEvents = 25
)

type Response struct {
	GeneratedAt string                          `json:"generated_at"`
	Definition  connectordefinitions.Definition `json:"definition"`
	Status      string                          `json:"status"`
	Events      []json.RawMessage               `json:"events,omitempty"`
	PagesRead   uint32                          `json:"pages_read,omitempty"`
	NextCursor  string                          `json:"next_cursor,omitempty"`
}

func Run(ctx context.Context, definition connectordefinitions.Definition, config map[string]string, pageLimit uint32, checkOnly bool) (Response, error) {
	if definition.Validation.Status == connectordefinitions.ValidationBlocked {
		return Response{}, fmt.Errorf("%w: connector definition is not previewable until blocking validation checks pass", connectorcredentials.ErrInvalidRequest)
	}
	source, err := sourceregistry.DynamicDefinitionSource(definition)
	if err != nil {
		return Response{}, fmt.Errorf("%w: %w", connectorcredentials.ErrInvalidRequest, err)
	}
	sourceConfig := sourcecdk.NewConfig(config)
	if err := source.Check(ctx, sourceConfig); err != nil {
		return Response{}, fmt.Errorf("%w: check failed: %w", connectorcredentials.ErrInvalidRequest, err)
	}
	response := Response{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Definition:  definition,
		Status:      "checked",
	}
	if checkOnly {
		return response, nil
	}
	if pageLimit == 0 {
		pageLimit = 1
	}
	if pageLimit > maxPages {
		pageLimit = maxPages
	}
	var cursor *cerebrov1.SourceCursor
	marshal := protojson.MarshalOptions{UseProtoNames: true}
	for i := uint32(0); i < pageLimit; i++ {
		pull, err := source.Read(ctx, sourceConfig, cursor)
		if err != nil {
			return Response{}, fmt.Errorf("%w: preview read failed: %w", connectorcredentials.ErrInvalidRequest, err)
		}
		response.PagesRead++
		for _, event := range pull.Events {
			if event == nil {
				continue
			}
			body, err := marshal.Marshal(event)
			if err != nil {
				return Response{}, err
			}
			response.Events = append(response.Events, json.RawMessage(body))
			if len(response.Events) >= maxEvents {
				break
			}
		}
		if pull.NextCursor == nil || len(response.Events) >= maxEvents {
			cursor = pull.NextCursor
			break
		}
		cursor = pull.NextCursor
	}
	if cursor != nil {
		response.NextCursor = strings.TrimSpace(cursor.GetOpaque())
	}
	if len(response.Events) > 0 {
		response.Status = "previewed"
	}
	return response, nil
}
