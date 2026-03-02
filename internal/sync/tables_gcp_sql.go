package sync

import (
	"context"
	"fmt"

	sqladmin "google.golang.org/api/sqladmin/v1"
)

func (e *GCPSyncEngine) gcpSQLInstanceTable() GCPTableSpec {
	return GCPTableSpec{
		Name:    "gcp_sql_instances",
		Columns: []string{"project_id", "name", "database_version", "region", "state", "gce_zone", "instance_type", "master_instance_name", "backend_type", "ip_addresses", "server_ca_cert", "settings", "replica_names", "connection_name", "self_link", "service_account_email_address", "disk_encryption_configuration", "disk_encryption_status", "root_password", "create_time"},
		Fetch:   e.fetchGCPSQLInstances,
	}
}

func (e *GCPSyncEngine) fetchGCPSQLInstances(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	service, err := sqladmin.NewService(ctx, gcpClientOptionsFromContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("create sqladmin service: %w", err)
	}

	resp, err := service.Instances.List(projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("list sql instances: %w", err)
	}

	rows := make([]map[string]interface{}, 0, len(resp.Items))

	for _, inst := range resp.Items {
		selfLink := inst.SelfLink
		if selfLink == "" {
			selfLink = fmt.Sprintf("https://sqladmin.googleapis.com/sql/v1beta4/projects/%s/instances/%s", projectID, inst.Name)
		}

		row := map[string]interface{}{
			"_cq_id":                        selfLink,
			"project_id":                    projectID,
			"name":                          inst.Name,
			"database_version":              inst.DatabaseVersion,
			"region":                        inst.Region,
			"state":                         inst.State,
			"gce_zone":                      inst.GceZone,
			"instance_type":                 inst.InstanceType,
			"master_instance_name":          inst.MasterInstanceName,
			"backend_type":                  inst.BackendType,
			"connection_name":               inst.ConnectionName,
			"self_link":                     selfLink,
			"service_account_email_address": inst.ServiceAccountEmailAddress,
			"create_time":                   inst.CreateTime,
		}

		// IP addresses
		if len(inst.IpAddresses) > 0 {
			var ips []map[string]interface{}
			for _, ip := range inst.IpAddresses {
				ips = append(ips, map[string]interface{}{
					"ip_address":     ip.IpAddress,
					"type":           ip.Type,
					"time_to_retire": ip.TimeToRetire,
				})
			}
			row["ip_addresses"] = ips
		}

		// Server CA cert
		if inst.ServerCaCert != nil {
			row["server_ca_cert"] = map[string]interface{}{
				"cert":             inst.ServerCaCert.Cert,
				"common_name":      inst.ServerCaCert.CommonName,
				"create_time":      inst.ServerCaCert.CreateTime,
				"expiration_time":  inst.ServerCaCert.ExpirationTime,
				"sha1_fingerprint": inst.ServerCaCert.Sha1Fingerprint,
			}
		}

		// Settings
		if inst.Settings != nil {
			settings := map[string]interface{}{
				"tier":                        inst.Settings.Tier,
				"activation_policy":           inst.Settings.ActivationPolicy,
				"availability_type":           inst.Settings.AvailabilityType,
				"pricing_plan":                inst.Settings.PricingPlan,
				"replication_type":            inst.Settings.ReplicationType,
				"storage_auto_resize":         inst.Settings.StorageAutoResize,
				"data_disk_size_gb":           inst.Settings.DataDiskSizeGb,
				"data_disk_type":              inst.Settings.DataDiskType,
				"deletion_protection_enabled": inst.Settings.DeletionProtectionEnabled,
			}

			// IP configuration
			if inst.Settings.IpConfiguration != nil {
				ipConfig := map[string]interface{}{
					"ipv4_enabled":    inst.Settings.IpConfiguration.Ipv4Enabled,
					"private_network": inst.Settings.IpConfiguration.PrivateNetwork,
					"require_ssl":     inst.Settings.IpConfiguration.RequireSsl,
					"ssl_mode":        inst.Settings.IpConfiguration.SslMode,
				}

				// Authorized networks
				if len(inst.Settings.IpConfiguration.AuthorizedNetworks) > 0 {
					var networks []map[string]interface{}
					for _, n := range inst.Settings.IpConfiguration.AuthorizedNetworks {
						networks = append(networks, map[string]interface{}{
							"name":            n.Name,
							"value":           n.Value,
							"expiration_time": n.ExpirationTime,
						})
					}
					ipConfig["authorized_networks"] = networks
				}
				settings["ip_configuration"] = ipConfig
			}

			// Backup configuration
			if inst.Settings.BackupConfiguration != nil {
				settings["backup_configuration"] = map[string]interface{}{
					"enabled":                        inst.Settings.BackupConfiguration.Enabled,
					"binary_log_enabled":             inst.Settings.BackupConfiguration.BinaryLogEnabled,
					"start_time":                     inst.Settings.BackupConfiguration.StartTime,
					"location":                       inst.Settings.BackupConfiguration.Location,
					"point_in_time_recovery_enabled": inst.Settings.BackupConfiguration.PointInTimeRecoveryEnabled,
					"transaction_log_retention_days": inst.Settings.BackupConfiguration.TransactionLogRetentionDays,
					"backup_retention_settings":      inst.Settings.BackupConfiguration.BackupRetentionSettings,
				}
			}

			// Database flags
			if len(inst.Settings.DatabaseFlags) > 0 {
				var flags []map[string]interface{}
				for _, f := range inst.Settings.DatabaseFlags {
					flags = append(flags, map[string]interface{}{
						"name":  f.Name,
						"value": f.Value,
					})
				}
				settings["database_flags"] = flags
			}

			// Maintenance window
			if inst.Settings.MaintenanceWindow != nil {
				settings["maintenance_window"] = map[string]interface{}{
					"day":          inst.Settings.MaintenanceWindow.Day,
					"hour":         inst.Settings.MaintenanceWindow.Hour,
					"update_track": inst.Settings.MaintenanceWindow.UpdateTrack,
				}
			}

			row["settings"] = settings
		}

		// Replica names
		row["replica_names"] = inst.ReplicaNames

		// Disk encryption
		if inst.DiskEncryptionConfiguration != nil {
			row["disk_encryption_configuration"] = map[string]interface{}{
				"kms_key_name": inst.DiskEncryptionConfiguration.KmsKeyName,
			}
		}

		if inst.DiskEncryptionStatus != nil {
			row["disk_encryption_status"] = map[string]interface{}{
				"kms_key_version_name": inst.DiskEncryptionStatus.KmsKeyVersionName,
			}
		}

		rows = append(rows, row)
	}

	return rows, nil
}
