package sourceregistry

import (
	"context"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
)

type depositDefinitionSource struct {
	definition connectordefinitions.Definition
	contracts  []sourcecdk.EventContract
}

func newDepositDefinitionSource(definition connectordefinitions.Definition) *depositDefinitionSource {
	contracts := make([]sourcecdk.EventContract, 0, len(definition.ResourceFamilies))
	for _, family := range definition.ResourceFamilies {
		contracts = append(contracts, sourcecdk.EventContract{
			Kind:                  depositDefinitionEventKind(definition.SourceID, family),
			SchemaRef:             depositDefinitionSchemaRef(definition.SourceID, family),
			RequiredAttributes:    append([]string(nil), family.Event.RequiredAttributes...),
			RequiredPayloadFields: append([]string(nil), family.Event.RequiredPayloadFields...),
		})
	}
	return &depositDefinitionSource{definition: definition, contracts: contracts}
}

func (s *depositDefinitionSource) Spec() *cerebrov1.SourceSpec {
	if s == nil {
		return nil
	}
	return &cerebrov1.SourceSpec{
		Id:          s.definition.SourceID,
		Name:        firstNonEmpty(s.definition.DisplayName, titleFromID(s.definition.SourceID)),
		Description: s.definition.Description,
	}
}

func (s *depositDefinitionSource) Check(_ context.Context, cfg sourcecdk.Config) error {
	if s == nil {
		return fmt.Errorf("deposit connector source is required")
	}
	for _, field := range s.definition.ConfigFields {
		if !field.Required {
			continue
		}
		value, ok := cfg.Lookup(field.Key)
		if !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", sourcecdk.ErrInvalidConfig, field.Key)
		}
	}
	for _, field := range s.definition.Auth.CredentialFields {
		if !field.Required {
			continue
		}
		value, ok := cfg.Lookup(field.Key)
		if !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", sourcecdk.ErrInvalidConfig, field.Key)
		}
	}
	return nil
}

func (s *depositDefinitionSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (s *depositDefinitionSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return sourcecdk.Pull{ShortCircuitReason: sourcecdk.PullShortCircuitReasonNotModified}, nil
}

func (s *depositDefinitionSource) EventContracts() []sourcecdk.EventContract {
	if s == nil {
		return nil
	}
	contracts := make([]sourcecdk.EventContract, 0, len(s.contracts))
	for _, contract := range s.contracts {
		contracts = append(contracts, sourcecdk.EventContract{
			Kind:                  contract.Kind,
			SchemaRef:             contract.SchemaRef,
			RequiredAttributes:    append([]string(nil), contract.RequiredAttributes...),
			RequiredPayloadFields: append([]string(nil), contract.RequiredPayloadFields...),
		})
	}
	return contracts
}

func depositDefinitionEventKind(sourceID string, family connectordefinitions.ResourceFamily) string {
	if kind := strings.TrimSpace(family.Event.Kind); kind != "" {
		return kind
	}
	if kind := strings.TrimSpace(family.EventKind); kind != "" {
		return kind
	}
	return strings.TrimSpace(sourceID) + "." + strings.TrimSpace(family.ID)
}

func depositDefinitionSchemaRef(sourceID string, family connectordefinitions.ResourceFamily) string {
	if schemaRef := strings.TrimSpace(family.Event.SchemaRef); schemaRef != "" {
		return schemaRef
	}
	return strings.TrimSpace(sourceID) + "/" + strings.TrimSpace(family.ID) + "/v1"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func titleFromID(value string) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), "_", " ")
	value = strings.ReplaceAll(value, "-", " ")
	parts := strings.Fields(value)
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}
