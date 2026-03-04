package sync

import (
	"context"
	"errors"
	"fmt"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"
)

func (e *GCPSyncEngine) gcpComputeFirewallTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_compute_firewalls",
		Columns: []string{"project_id", "name", "id", "description", "network", "priority", "direction", "source_ranges", "destination_ranges", "source_tags", "target_tags", "source_service_accounts", "target_service_accounts", "allowed", "denied", "disabled", "log_config", "creation_timestamp", "self_link"},
		Fetch:   e.fetchGCPComputeFirewalls,
	}
}

func (e *GCPSyncEngine) gcpComputeNetworkTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_compute_networks",
		Columns: []string{"project_id", "name", "id", "description", "auto_create_subnetworks", "routing_mode", "mtu", "creation_timestamp", "self_link", "subnetworks", "peerings"},
		Fetch:   e.fetchGCPComputeNetworks,
	}
}

func (e *GCPSyncEngine) gcpComputeSubnetworkTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_compute_subnetworks",
		Columns: []string{"project_id", "region", "name", "id", "description", "network", "ip_cidr_range", "gateway_address", "private_ip_google_access", "secondary_ip_ranges", "purpose", "role", "state", "log_config", "creation_timestamp", "self_link"},
		Fetch:   e.fetchGCPComputeSubnetworks,
	}
}

func (e *GCPSyncEngine) fetchGCPComputeFirewalls(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := compute.NewFirewallsRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create firewall client: %w", err)
	}
	defer func() { _ = client.Close() }()

	rows := make([]map[string]interface{}, 0, 100)

	req := &computepb.ListFirewallsRequest{
		Project: projectID,
	}

	it := client.List(ctx, req)
	for {
		fw, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list firewalls: %w", err)
		}

		selfLink := ptrToString(fw.SelfLink)

		row := map[string]interface{}{
			"_cq_id":                  selfLink,
			"project_id":              projectID,
			"name":                    ptrToString(fw.Name),
			"id":                      ptrToUint64(fw.Id),
			"description":             ptrToString(fw.Description),
			"network":                 ptrToString(fw.Network),
			"priority":                ptrToInt32(fw.Priority),
			"direction":               ptrToString(fw.Direction),
			"source_ranges":           fw.SourceRanges,
			"destination_ranges":      fw.DestinationRanges,
			"source_tags":             fw.SourceTags,
			"target_tags":             fw.TargetTags,
			"source_service_accounts": fw.SourceServiceAccounts,
			"target_service_accounts": fw.TargetServiceAccounts,
			"disabled":                ptrToBool(fw.Disabled),
			"creation_timestamp":      ptrToString(fw.CreationTimestamp),
			"self_link":               selfLink,
		}

		// Allowed rules
		if len(fw.Allowed) > 0 {
			var allowed []map[string]interface{}
			for _, a := range fw.Allowed {
				allowed = append(allowed, map[string]interface{}{
					"ip_protocol": ptrToString(a.IPProtocol),
					"ports":       a.Ports,
				})
			}
			row["allowed"] = allowed
		}

		// Denied rules
		if len(fw.Denied) > 0 {
			var denied []map[string]interface{}
			for _, d := range fw.Denied {
				denied = append(denied, map[string]interface{}{
					"ip_protocol": ptrToString(d.IPProtocol),
					"ports":       d.Ports,
				})
			}
			row["denied"] = denied
		}

		// Log config
		if fw.LogConfig != nil {
			row["log_config"] = map[string]interface{}{
				"enable":   ptrToBool(fw.LogConfig.Enable),
				"metadata": ptrToString(fw.LogConfig.Metadata),
			}
		}

		rows = append(rows, row)
	}

	return rows, nil
}

func (e *GCPSyncEngine) fetchGCPComputeNetworks(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := compute.NewNetworksRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create networks client: %w", err)
	}
	defer func() { _ = client.Close() }()

	rows := make([]map[string]interface{}, 0, 100)

	req := &computepb.ListNetworksRequest{
		Project: projectID,
	}

	it := client.List(ctx, req)
	for {
		net, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list networks: %w", err)
		}

		selfLink := ptrToString(net.SelfLink)

		row := map[string]interface{}{
			"_cq_id":                  selfLink,
			"project_id":              projectID,
			"name":                    ptrToString(net.Name),
			"id":                      ptrToUint64(net.Id),
			"description":             ptrToString(net.Description),
			"auto_create_subnetworks": ptrToBool(net.AutoCreateSubnetworks),
			"mtu":                     ptrToInt32(net.Mtu),
			"creation_timestamp":      ptrToString(net.CreationTimestamp),
			"self_link":               selfLink,
			"subnetworks":             net.Subnetworks,
		}

		// Routing config
		if net.RoutingConfig != nil {
			row["routing_mode"] = ptrToString(net.RoutingConfig.RoutingMode)
		}

		// Peerings
		if len(net.Peerings) > 0 {
			var peerings []map[string]interface{}
			for _, p := range net.Peerings {
				peerings = append(peerings, map[string]interface{}{
					"name":                                ptrToString(p.Name),
					"network":                             ptrToString(p.Network),
					"state":                               ptrToString(p.State),
					"auto_create_routes":                  ptrToBool(p.AutoCreateRoutes),
					"export_custom_routes":                ptrToBool(p.ExportCustomRoutes),
					"import_custom_routes":                ptrToBool(p.ImportCustomRoutes),
					"exchange_subnet_routes":              ptrToBool(p.ExchangeSubnetRoutes),
					"export_subnet_routes_with_public_ip": ptrToBool(p.ExportSubnetRoutesWithPublicIp),
					"import_subnet_routes_with_public_ip": ptrToBool(p.ImportSubnetRoutesWithPublicIp),
				})
			}
			row["peerings"] = peerings
		}

		rows = append(rows, row)
	}

	return rows, nil
}

func (e *GCPSyncEngine) fetchGCPComputeSubnetworks(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := compute.NewSubnetworksRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create subnetworks client: %w", err)
	}
	defer func() { _ = client.Close() }()

	rows := make([]map[string]interface{}, 0, 100)

	req := &computepb.AggregatedListSubnetworksRequest{
		Project: projectID,
	}

	it := client.AggregatedList(ctx, req)
	for {
		resp, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list subnetworks: %w", err)
		}

		for _, subnet := range resp.Value.Subnetworks {
			if subnet == nil {
				continue
			}

			selfLink := ptrToString(subnet.SelfLink)

			row := map[string]interface{}{
				"_cq_id":                   selfLink,
				"project_id":               projectID,
				"region":                   ptrToString(subnet.Region),
				"name":                     ptrToString(subnet.Name),
				"id":                       ptrToUint64(subnet.Id),
				"description":              ptrToString(subnet.Description),
				"network":                  ptrToString(subnet.Network),
				"ip_cidr_range":            ptrToString(subnet.IpCidrRange),
				"gateway_address":          ptrToString(subnet.GatewayAddress),
				"private_ip_google_access": ptrToBool(subnet.PrivateIpGoogleAccess),
				"purpose":                  ptrToString(subnet.Purpose),
				"role":                     ptrToString(subnet.Role),
				"state":                    ptrToString(subnet.State),
				"creation_timestamp":       ptrToString(subnet.CreationTimestamp),
				"self_link":                selfLink,
			}

			// Secondary IP ranges
			if len(subnet.SecondaryIpRanges) > 0 {
				var ranges []map[string]interface{}
				for _, r := range subnet.SecondaryIpRanges {
					ranges = append(ranges, map[string]interface{}{
						"range_name":    ptrToString(r.RangeName),
						"ip_cidr_range": ptrToString(r.IpCidrRange),
					})
				}
				row["secondary_ip_ranges"] = ranges
			}

			// Log config
			if subnet.LogConfig != nil {
				row["log_config"] = map[string]interface{}{
					"enable":               ptrToBool(subnet.LogConfig.Enable),
					"aggregation_interval": ptrToString(subnet.LogConfig.AggregationInterval),
					"flow_sampling":        subnet.LogConfig.FlowSampling,
					"metadata":             ptrToString(subnet.LogConfig.Metadata),
				}
			}

			rows = append(rows, row)
		}
	}

	return rows, nil
}

func ptrToInt32(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}
