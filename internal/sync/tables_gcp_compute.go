package sync

import (
	"context"
	"errors"
	"fmt"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"
)

func (e *GCPSyncEngine) gcpComputeInstanceTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_compute_instances",
		Columns: []string{"project_id", "zone", "name", "id", "machine_type", "status", "creation_timestamp", "description", "can_ip_forward", "deletion_protection", "hostname", "labels", "metadata", "network_interfaces", "disks", "service_accounts", "scheduling", "shielded_instance_config", "tags", "self_link"},
		Fetch:   e.fetchGCPComputeInstances,
	}
}

func (e *GCPSyncEngine) fetchGCPComputeInstances(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	client, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create compute client: %w", err)
	}
	defer func() { _ = client.Close() }()

	var rows []map[string]interface{}

	// List all instances across all zones
	req := &computepb.AggregatedListInstancesRequest{
		Project: projectID,
	}

	it := client.AggregatedList(ctx, req)
	for {
		resp, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list instances: %w", err)
		}

		for _, instance := range resp.Value.Instances {
			if instance == nil {
				continue
			}

			selfLink := ""
			if instance.SelfLink != nil {
				selfLink = *instance.SelfLink
			}

			row := map[string]interface{}{
				"_cq_id":              selfLink,
				"project_id":          projectID,
				"name":                ptrToString(instance.Name),
				"id":                  ptrToUint64(instance.Id),
				"machine_type":        ptrToString(instance.MachineType),
				"status":              ptrToString(instance.Status),
				"creation_timestamp":  ptrToString(instance.CreationTimestamp),
				"description":         ptrToString(instance.Description),
				"can_ip_forward":      ptrToBool(instance.CanIpForward),
				"deletion_protection": ptrToBool(instance.DeletionProtection),
				"hostname":            ptrToString(instance.Hostname),
				"labels":              instance.Labels,
				"self_link":           selfLink,
			}

			// Extract zone from self_link
			if selfLink != "" {
				row["zone"] = extractZoneFromSelfLink(selfLink)
			}

			// Add metadata (only include non-sensitive items with reasonable lengths)
			if instance.Metadata != nil && len(instance.Metadata.Items) > 0 {
				metaItems := make(map[string]interface{})
				for _, item := range instance.Metadata.Items {
					if item.Key != nil && item.Value != nil {
						key := *item.Key
						val := *item.Value
						// Skip large values (like SSH keys) that break JSON parsing
						if len(val) < 1000 && key != "ssh-keys" && key != "sshKeys" {
							metaItems[key] = val
						}
					}
				}
				if len(metaItems) > 0 {
					row["metadata"] = metaItems
				}
			}

			// Add network interfaces
			if len(instance.NetworkInterfaces) > 0 {
				var nics []map[string]interface{}
				for _, nic := range instance.NetworkInterfaces {
					nicInfo := map[string]interface{}{
						"name":       ptrToString(nic.Name),
						"network":    ptrToString(nic.Network),
						"subnetwork": ptrToString(nic.Subnetwork),
						"network_ip": ptrToString(nic.NetworkIP),
					}
					if len(nic.AccessConfigs) > 0 {
						var accessConfigs []map[string]string
						for _, ac := range nic.AccessConfigs {
							accessConfigs = append(accessConfigs, map[string]string{
								"name":   ptrToString(ac.Name),
								"nat_ip": ptrToString(ac.NatIP),
								"type":   ptrToString(ac.Type),
							})
						}
						nicInfo["access_configs"] = accessConfigs
					}
					nics = append(nics, nicInfo)
				}
				row["network_interfaces"] = nics
			}

			// Add disks
			if len(instance.Disks) > 0 {
				var disks []map[string]interface{}
				for _, disk := range instance.Disks {
					diskInfo := map[string]interface{}{
						"auto_delete": ptrToBool(disk.AutoDelete),
						"boot":        ptrToBool(disk.Boot),
						"device_name": ptrToString(disk.DeviceName),
						"disk_size":   ptrToInt64(disk.DiskSizeGb),
						"mode":        ptrToString(disk.Mode),
						"source":      ptrToString(disk.Source),
						"type":        ptrToString(disk.Type),
					}
					disks = append(disks, diskInfo)
				}
				row["disks"] = disks
			}

			// Add service accounts
			if len(instance.ServiceAccounts) > 0 {
				var sas []map[string]interface{}
				for _, sa := range instance.ServiceAccounts {
					sas = append(sas, map[string]interface{}{
						"email":  ptrToString(sa.Email),
						"scopes": sa.Scopes,
					})
				}
				row["service_accounts"] = sas
			}

			// Add scheduling
			if instance.Scheduling != nil {
				row["scheduling"] = map[string]interface{}{
					"automatic_restart":   ptrToBool(instance.Scheduling.AutomaticRestart),
					"on_host_maintenance": ptrToString(instance.Scheduling.OnHostMaintenance),
					"preemptible":         ptrToBool(instance.Scheduling.Preemptible),
				}
			}

			// Add shielded instance config
			if instance.ShieldedInstanceConfig != nil {
				row["shielded_instance_config"] = map[string]interface{}{
					"enable_secure_boot":          ptrToBool(instance.ShieldedInstanceConfig.EnableSecureBoot),
					"enable_vtpm":                 ptrToBool(instance.ShieldedInstanceConfig.EnableVtpm),
					"enable_integrity_monitoring": ptrToBool(instance.ShieldedInstanceConfig.EnableIntegrityMonitoring),
				}
			}

			// Add tags
			if instance.Tags != nil {
				row["tags"] = instance.Tags.Items
			}

			rows = append(rows, row)
		}
	}

	return rows, nil
}

func extractZoneFromSelfLink(selfLink string) string {
	// Format: https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instances/{name}
	parts := splitArn(selfLink)
	for i, p := range parts {
		if p == "zones" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func ptrToString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func ptrToBool(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}

func ptrToUint64(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}

func ptrToInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}
