package azurearm

import (
	"context"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

type Definition struct {
	Name         string
	Label        string
	ProviderPath string
	APIVersion   string
	Kind         string
	SchemaRef    string
}

var DefaultDefinitions = []Definition{
	{Name: "activity_log_alert", Label: "azure activity log alerts", ProviderPath: "Microsoft.Insights/activityLogAlerts", APIVersion: "2020-10-01", Kind: "azure.activity_log_alert", SchemaRef: "azure/activity_log_alert/v1"},
	{Name: "application_container", Label: "azure container apps", ProviderPath: "Microsoft.App/containerApps", APIVersion: "2023-05-01", Kind: "azure.application_container", SchemaRef: "azure/application_container/v1"},
	{Name: "application_gateway", Label: "azure application gateways", ProviderPath: "Microsoft.Network/applicationGateways", APIVersion: "2023-09-01", Kind: "azure.application_gateway", SchemaRef: "azure/application_gateway/v1"},
	{Name: "application_insight", Label: "azure application insights", ProviderPath: "Microsoft.Insights/components", APIVersion: "2020-02-02", Kind: "azure.application_insight", SchemaRef: "azure/application_insight/v1"},
	{Name: "cognitive_services_account", Label: "azure cognitive services accounts", ProviderPath: "Microsoft.CognitiveServices/accounts", APIVersion: "2023-05-01", Kind: "azure.cognitive_services_account", SchemaRef: "azure/cognitive_services_account/v1"},
	{Name: "cosmos_postgresql", Label: "azure cosmos db for postgresql clusters", ProviderPath: "Microsoft.DBforPostgreSQL/serverGroupsv2", APIVersion: "2023-03-02-preview", Kind: "azure.cosmos_postgresql", SchemaRef: "azure/cosmos_postgresql/v1"},
	{Name: "databricks_workspace", Label: "azure databricks workspaces", ProviderPath: "Microsoft.Databricks/workspaces", APIVersion: "2023-02-01", Kind: "azure.databricks_workspace", SchemaRef: "azure/databricks_workspace/v1"},
	{Name: "defender_config", Label: "azure defender for cloud pricing configs", ProviderPath: "Microsoft.Security/pricings", APIVersion: "2024-01-01", Kind: "azure.defender_config", SchemaRef: "azure/defender_config/v1"},
	{Name: "diagnostic_setting", Label: "azure subscription diagnostic settings", ProviderPath: "Microsoft.Insights/diagnosticSettings", APIVersion: "2021-05-01-preview", Kind: "azure.diagnostic_setting", SchemaRef: "azure/diagnostic_setting/v1"},
	{Name: "load_balancer", Label: "azure load balancers", ProviderPath: "Microsoft.Network/loadBalancers", APIVersion: "2023-09-01", Kind: "azure.load_balancer", SchemaRef: "azure/load_balancer/v1"},
	{Name: "log_alert", Label: "azure log alert rules", ProviderPath: "Microsoft.Insights/scheduledQueryRules", APIVersion: "2023-12-01-preview", Kind: "azure.log_alert", SchemaRef: "azure/log_alert/v1"},
	{Name: "machine_learning_workspace", Label: "azure machine learning workspaces", ProviderPath: "Microsoft.MachineLearningServices/workspaces", APIVersion: "2024-04-01", Kind: "azure.machine_learning_workspace", SchemaRef: "azure/machine_learning_workspace/v1"},
	{Name: "metric_alert_rule", Label: "azure metric alert rules", ProviderPath: "Microsoft.Insights/metricAlerts", APIVersion: "2018-03-01", Kind: "azure.metric_alert_rule", SchemaRef: "azure/metric_alert_rule/v1"},
	{Name: "postgresql_server", Label: "azure postgresql flexible servers", ProviderPath: "Microsoft.DBforPostgreSQL/flexibleServers", APIVersion: "2023-06-01-preview", Kind: "azure.postgresql_server", SchemaRef: "azure/postgresql_server/v1"},
	{Name: "role", Label: "azure role definitions", ProviderPath: "Microsoft.Authorization/roleDefinitions", APIVersion: "2022-04-01", Kind: "azure.role", SchemaRef: "azure/role/v1"},
	{Name: "route_table", Label: "azure route tables", ProviderPath: "Microsoft.Network/routeTables", APIVersion: "2023-09-01", Kind: "azure.route_table", SchemaRef: "azure/route_table/v1"},
	{Name: "security_contact", Label: "azure security contacts", ProviderPath: "Microsoft.Security/securityContacts", APIVersion: "2020-01-01-preview", Kind: "azure.security_contact", SchemaRef: "azure/security_contact/v1"},
	{Name: "server_vulnerability", Label: "azure security assessments", ProviderPath: "Microsoft.Security/assessments", APIVersion: "2020-01-01", Kind: "azure.server_vulnerability", SchemaRef: "azure/server_vulnerability/v1"},
	{Name: "sql_managed_instance", Label: "azure sql managed instances", ProviderPath: "Microsoft.Sql/managedInstances", APIVersion: "2022-05-01-preview", Kind: "azure.sql_managed_instance", SchemaRef: "azure/sql_managed_instance/v1"},
	{Name: "sql_server_on_virtual_machine", Label: "azure sql servers on virtual machines", ProviderPath: "Microsoft.SqlVirtualMachine/sqlVirtualMachines", APIVersion: "2023-10-01", Kind: "azure.sql_server_on_virtual_machine", SchemaRef: "azure/sql_server_on_virtual_machine/v1"},
	{Name: "virtual_machine_scale_set", Label: "azure virtual machine scale sets", ProviderPath: "Microsoft.Compute/virtualMachineScaleSets", APIVersion: "2024-07-01", Kind: "azure.virtual_machine_scale_set", SchemaRef: "azure/virtual_machine_scale_set/v1"},
}

type ListFunc[S any, Source any, Record any] func(context.Context, Source, S, string, int, Definition) ([]Record, string, error)
type EventFunc[S any, Record any] func(S, Record, Definition) (*primitives.Event, error)
type URNFunc[S any, Record any] func(S, Record, Definition) (string, error)

func Families[S any, Source any, Record any](source Source, pageLimit func(S) int, list ListFunc[S, Source, Record], event EventFunc[S, Record], urn URNFunc[S, Record]) []sourcecdk.Family[S] {
	families := make([]sourcecdk.Family[S], 0, len(DefaultDefinitions))
	for _, definition := range DefaultDefinitions {
		definition := definition
		families = append(families, sourcecdk.Family[S]{
			Name: definition.Name,
			Check: func(ctx context.Context, settings S) error {
				_, _, err := list(ctx, source, settings, "", pageLimit(settings), definition)
				return err
			},
			Discover: func(ctx context.Context, settings S) ([]sourcecdk.URN, error) {
				records, _, err := list(ctx, source, settings, "", pageLimit(settings), definition)
				if err != nil {
					return nil, fmt.Errorf("lookup %s: %w", definition.Label, err)
				}
				urns := make([]sourcecdk.URN, 0, len(records))
				for _, record := range records {
					raw, err := urn(settings, record, definition)
					if err != nil {
						return nil, err
					}
					parsed, err := sourcecdk.ParseURN(raw)
					if err != nil {
						return nil, err
					}
					urns = append(urns, parsed)
				}
				return urns, nil
			},
			Read: func(ctx context.Context, settings S, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
				records, next, err := list(ctx, source, settings, strings.TrimSpace(cursor.GetOpaque()), pageLimit(settings), definition)
				if err != nil {
					return sourcecdk.Pull{}, fmt.Errorf("lookup %s: %w", definition.Label, err)
				}
				events := make([]*primitives.Event, 0, len(records))
				for _, record := range records {
					built, err := event(settings, record, definition)
					if err != nil {
						return sourcecdk.Pull{}, err
					}
					events = append(events, built)
				}
				pull := sourcecdk.Pull{Events: events}
				if strings.TrimSpace(next) != "" {
					pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
				}
				return pull, nil
			},
		})
	}
	return families
}
