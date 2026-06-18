package graphagent

import (
	"context"
	"strings"

	"github.com/writer/cerebro/internal/telemetry"
)

type instrumentedLLMClient struct {
	provider string
	client   LLMClient
}

func instrumentLLMClient(provider string, client LLMClient) LLMClient {
	if client == nil {
		return nil
	}
	return &instrumentedLLMClient{
		provider: strings.TrimSpace(provider),
		client:   client,
	}
}

func (c *instrumentedLLMClient) DraftCypher(ctx context.Context, req DraftRequest) (*DraftResponse, error) {
	attrs := c.operationAttrs("draft", req.Model, req.TenantID).
		WithField(telemetry.Field{Key: "graphagent.scope_urn.present", Value: strings.TrimSpace(req.ScopeURN) != ""}).
		WithField(telemetry.Field{Key: "graphagent.question.bytes", Value: len(req.Question)}).
		WithField(telemetry.Field{Key: "graphagent.schema.bytes", Value: len(req.Schema)}).
		WithField(telemetry.Field{Key: "graphagent.guardrail.bytes", Value: len(req.Guardrail)}).
		WithField(telemetry.Field{Key: "graphagent.history.count", Value: len(req.History)}).
		WithField(telemetry.Field{Key: "graphagent.max_rows", Value: req.MaxRows}).
		WithField(telemetry.Field{Key: "graphagent.probe.present", Value: req.Probe != nil})
	ctx, span := telemetry.Start(ctx, "graphagent.llm.draft", attrs)
	response, err := c.client.DraftCypher(ctx, req)
	endAttrs := telemetry.Attrs()
	status := "completed"
	if err != nil {
		status = "failed"
		endAttrs = endAttrs.WithField(telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(err)})
		telemetry.CaptureError(ctx, "graphagent.llm.error", err, attrs)
	} else if response != nil {
		endAttrs = endAttrs.
			WithField(telemetry.Field{Key: "graphagent.refusal", Value: strings.TrimSpace(response.Refusal) != ""}).
			WithField(telemetry.Field{Key: "graphagent.plan.present", Value: response.Plan != nil}).
			WithField(telemetry.Field{Key: "graphagent.cypher.present", Value: strings.TrimSpace(response.Cypher) != ""}).
			WithField(telemetry.Field{Key: "graphagent.cypher.bytes", Value: len(response.Cypher)})
	}
	telemetry.End(span, status, endAttrs)
	return response, err
}

func (c *instrumentedLLMClient) Summarize(ctx context.Context, req SummarizeRequest) (string, error) {
	attrs := c.operationAttrs("summarize", req.Model, req.TenantID).
		WithField(telemetry.Field{Key: "graphagent.scope_urn.present", Value: strings.TrimSpace(req.ScopeURN) != ""}).
		WithField(telemetry.Field{Key: "graphagent.question.bytes", Value: len(req.Question)}).
		WithField(telemetry.Field{Key: "graphagent.cypher.bytes", Value: len(req.Cypher)}).
		WithField(telemetry.Field{Key: "graphagent.rows.count", Value: len(req.Rows)}).
		WithField(telemetry.Field{Key: "graphagent.history.count", Value: len(req.History)})
	ctx, span := telemetry.Start(ctx, "graphagent.llm.summarize", attrs)
	summary, err := c.client.Summarize(ctx, req)
	endAttrs := telemetry.Attrs()
	status := "completed"
	if err != nil {
		status = "failed"
		endAttrs = endAttrs.WithField(telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(err)})
		telemetry.CaptureError(ctx, "graphagent.llm.error", err, attrs)
	} else {
		endAttrs = endAttrs.WithField(telemetry.Field{Key: "graphagent.summary.bytes", Value: len(summary)})
	}
	telemetry.End(span, status, endAttrs)
	return summary, err
}

func (c *instrumentedLLMClient) Probe(ctx context.Context) error {
	prober, ok := c.client.(LLMProber)
	if !ok {
		return nil
	}
	attrs := c.operationAttrs("probe", "", "")
	ctx, span := telemetry.Start(ctx, "graphagent.llm.probe", attrs)
	err := prober.Probe(ctx)
	endAttrs := telemetry.Attrs()
	status := "completed"
	if err != nil {
		status = "failed"
		endAttrs = endAttrs.WithField(telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(err)})
		telemetry.CaptureError(ctx, "graphagent.llm.error", err, attrs)
	}
	telemetry.End(span, status, endAttrs)
	return err
}

func (c *instrumentedLLMClient) operationAttrs(operation string, model string, tenantID string) telemetry.Attributes {
	return telemetry.Attrs(
		telemetry.Field{Key: "gen_ai.provider.name", Value: strings.TrimSpace(c.provider)},
		telemetry.Field{Key: "gen_ai.operation.name", Value: strings.TrimSpace(operation)},
		telemetry.Field{Key: "gen_ai.request.model", Value: normalizeModel(model)},
		telemetry.Field{Key: "tenant_id", Value: strings.TrimSpace(tenantID)},
	)
}
