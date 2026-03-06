package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/evalops/cerebro/internal/snowflake"
)

func (r *RelationshipExtractor) extractGCPRelationships(ctx context.Context) (int, error) {
	var rels []Relationship

	// GCP Compute instances
	query := `SELECT ID, PROJECT_ID, NETWORK_INTERFACES, SERVICE_ACCOUNTS
	          FROM GCP_COMPUTE_INSTANCES WHERE ID IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_COMPUTE_INSTANCES", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			instanceID := toString(queryRow(row, "id"))
			projectID := toString(queryRow(row, "project_id"))

			// Service account relationships
			if saList := asSlice(queryRow(row, "service_accounts")); len(saList) > 0 {
				for _, sa := range saList {
					if saMap := asMap(sa); saMap != nil {
						if email := getStringAny(saMap, "email", "Email"); email != "" {
							rels = append(rels, Relationship{
								SourceID:   instanceID,
								SourceType: "gcp:compute:instance",
								TargetID:   fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, email),
								TargetType: "gcp:iam:service_account",
								RelType:    RelHasRole,
							})
						}
					}
				}
			}

			// Network relationships
			if nicList := asSlice(queryRow(row, "network_interfaces")); len(nicList) > 0 {
				for _, nic := range nicList {
					if nicMap := asMap(nic); nicMap != nil {
						if network := toString(nicMap["network"]); network != "" {
							rels = append(rels, Relationship{
								SourceID:   instanceID,
								SourceType: "gcp:compute:instance",
								TargetID:   network,
								TargetType: "gcp:compute:network",
								RelType:    RelInVPC,
							})
						}
						if subnetwork := toString(nicMap["subnetwork"]); subnetwork != "" {
							rels = append(rels, Relationship{
								SourceID:   instanceID,
								SourceType: "gcp:compute:instance",
								TargetID:   subnetwork,
								TargetType: "gcp:compute:subnetwork",
								RelType:    RelInSubnet,
							})
						}
					}
				}
			}
		}
	}

	// GCP Compute firewalls - network membership relationships
	query = `SELECT _CQ_ID, SELF_LINK, NETWORK
	         FROM GCP_COMPUTE_FIREWALLS
	         WHERE (_CQ_ID IS NOT NULL OR SELF_LINK IS NOT NULL)`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_COMPUTE_FIREWALLS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			firewallID := normalizeRelationshipID(toString(queryRow(row, "_cq_id")))
			if firewallID == "" {
				firewallID = normalizeRelationshipID(toString(queryRow(row, "self_link")))
			}
			if firewallID == "" {
				continue
			}

			if networkID := normalizeRelationshipID(toString(queryRow(row, "network"))); networkID != "" {
				rels = append(rels, Relationship{
					SourceID:   firewallID,
					SourceType: "gcp:compute:firewall",
					TargetID:   networkID,
					TargetType: "gcp:compute:network",
					RelType:    RelInVPC,
				})
			}
		}
	}

	// GCP Compute networks - peering relationships
	query = `SELECT _CQ_ID, SELF_LINK, PEERINGS
	         FROM GCP_COMPUTE_NETWORKS
	         WHERE (_CQ_ID IS NOT NULL OR SELF_LINK IS NOT NULL)`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_COMPUTE_NETWORKS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			networkID := normalizeRelationshipID(toString(queryRow(row, "_cq_id")))
			if networkID == "" {
				networkID = normalizeRelationshipID(toString(queryRow(row, "self_link")))
			}
			if networkID == "" {
				continue
			}

			for _, peer := range asSlice(queryRow(row, "peerings")) {
				peerMap := asMap(peer)
				if peerMap == nil {
					continue
				}
				peerNetworkID := normalizeRelationshipID(getStringAny(peerMap, "network", "Network"))
				if peerNetworkID == "" || peerNetworkID == networkID {
					continue
				}
				rels = append(rels, Relationship{
					SourceID:   networkID,
					SourceType: "gcp:compute:network",
					TargetID:   peerNetworkID,
					TargetType: "gcp:compute:network",
					RelType:    RelRoutes,
				})
			}
		}
	}

	// GCP Compute subnetworks - network membership relationships
	query = `SELECT _CQ_ID, SELF_LINK, NETWORK
	         FROM GCP_COMPUTE_SUBNETWORKS
	         WHERE NETWORK IS NOT NULL AND (_CQ_ID IS NOT NULL OR SELF_LINK IS NOT NULL)`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_COMPUTE_SUBNETWORKS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			subnetworkID := normalizeRelationshipID(toString(queryRow(row, "_cq_id")))
			if subnetworkID == "" {
				subnetworkID = normalizeRelationshipID(toString(queryRow(row, "self_link")))
			}
			if subnetworkID == "" {
				continue
			}

			if networkID := normalizeRelationshipID(toString(queryRow(row, "network"))); networkID != "" {
				rels = append(rels, Relationship{
					SourceID:   subnetworkID,
					SourceType: "gcp:compute:subnetwork",
					TargetID:   networkID,
					TargetType: "gcp:compute:network",
					RelType:    RelInVPC,
				})
			}
		}
	}

	// GCP GKE clusters - network, service account, and encryption relationships
	query = `SELECT _CQ_ID, SELF_LINK, PROJECT_ID, NAME, LOCATION, NETWORK, SUBNETWORK, NODE_CONFIG, DATABASE_ENCRYPTION
	         FROM GCP_CONTAINER_CLUSTERS
	         WHERE (_CQ_ID IS NOT NULL OR SELF_LINK IS NOT NULL OR NAME IS NOT NULL)`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_CONTAINER_CLUSTERS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			projectID := toString(queryRow(row, "project_id"))
			clusterID := gcpClusterID(
				toString(queryRow(row, "_cq_id")),
				toString(queryRow(row, "self_link")),
				projectID,
				toString(queryRow(row, "location")),
				toString(queryRow(row, "name")),
			)
			if clusterID == "" {
				continue
			}

			if networkID := normalizeRelationshipID(toString(queryRow(row, "network"))); networkID != "" {
				rels = append(rels, Relationship{
					SourceID:   clusterID,
					SourceType: "gcp:gke:cluster",
					TargetID:   networkID,
					TargetType: "gcp:compute:network",
					RelType:    RelInVPC,
				})
			}

			if subnetworkID := normalizeRelationshipID(toString(queryRow(row, "subnetwork"))); subnetworkID != "" {
				rels = append(rels, Relationship{
					SourceID:   clusterID,
					SourceType: "gcp:gke:cluster",
					TargetID:   subnetworkID,
					TargetType: "gcp:compute:subnetwork",
					RelType:    RelInSubnet,
				})
			}

			if nodeConfig := asMap(queryRow(row, "node_config")); nodeConfig != nil {
				if serviceAccount := getStringAny(nodeConfig, "service_account", "serviceAccount"); serviceAccount != "" {
					targetID := serviceAccount
					if projectID != "" && !strings.Contains(serviceAccount, "/") {
						targetID = fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, serviceAccount)
					}
					rels = append(rels, Relationship{
						SourceID:   clusterID,
						SourceType: "gcp:gke:cluster",
						TargetID:   targetID,
						TargetType: "gcp:iam:service_account",
						RelType:    RelHasRole,
					})
				}
			}

			if dbEnc := asMap(queryRow(row, "database_encryption")); dbEnc != nil {
				if kmsKey := getStringAny(dbEnc, "key_name", "keyName"); kmsKey != "" {
					rels = append(rels, Relationship{
						SourceID:   clusterID,
						SourceType: "gcp:gke:cluster",
						TargetID:   kmsKey,
						TargetType: "gcp:kms:key",
						RelType:    RelEncryptedBy,
					})
				}
			}
		}
	}

	// GCP GKE node pools - cluster and service account relationships
	query = `SELECT _CQ_ID, SELF_LINK, PROJECT_ID, LOCATION, CLUSTER_NAME, NAME, CONFIG
	         FROM GCP_CONTAINER_NODE_POOLS
	         WHERE (_CQ_ID IS NOT NULL OR SELF_LINK IS NOT NULL OR (PROJECT_ID IS NOT NULL AND CLUSTER_NAME IS NOT NULL AND NAME IS NOT NULL))`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_CONTAINER_NODE_POOLS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			projectID := toString(queryRow(row, "project_id"))
			location := toString(queryRow(row, "location"))
			clusterName := toString(queryRow(row, "cluster_name"))
			nodePoolID := gcpNodePoolID(
				toString(queryRow(row, "_cq_id")),
				toString(queryRow(row, "self_link")),
				projectID,
				location,
				clusterName,
				toString(queryRow(row, "name")),
			)
			if nodePoolID == "" {
				continue
			}

			if clusterID := gcpClusterID("", "", projectID, location, clusterName); clusterID != "" {
				rels = append(rels, Relationship{
					SourceID:   nodePoolID,
					SourceType: "gcp:gke:node_pool",
					TargetID:   clusterID,
					TargetType: "gcp:gke:cluster",
					RelType:    RelBelongsTo,
				})
			}

			if config := asMap(queryRow(row, "config")); config != nil {
				if serviceAccount := getStringAny(config, "service_account", "serviceAccount"); serviceAccount != "" {
					targetID := serviceAccount
					if projectID != "" && !strings.Contains(serviceAccount, "/") {
						targetID = fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, serviceAccount)
					}
					rels = append(rels, Relationship{
						SourceID:   nodePoolID,
						SourceType: "gcp:gke:node_pool",
						TargetID:   targetID,
						TargetType: "gcp:iam:service_account",
						RelType:    RelHasRole,
					})
				}
			}
		}
	}

	// GCP IAM service accounts - project ownership relationships
	query = `SELECT _CQ_ID, PROJECT_ID, NAME, EMAIL
	         FROM GCP_IAM_SERVICE_ACCOUNTS
	         WHERE PROJECT_ID IS NOT NULL AND (_CQ_ID IS NOT NULL OR NAME IS NOT NULL OR EMAIL IS NOT NULL)`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_IAM_SERVICE_ACCOUNTS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			projectID := toString(queryRow(row, "project_id"))
			if projectID == "" {
				continue
			}
			serviceAccountID := gcpServiceAccountID(
				toString(queryRow(row, "_cq_id")),
				toString(queryRow(row, "name")),
				projectID,
				toString(queryRow(row, "email")),
			)
			if serviceAccountID == "" {
				continue
			}

			rels = append(rels, Relationship{
				SourceID:   serviceAccountID,
				SourceType: "gcp:iam:service_account",
				TargetID:   gcpProjectPath(projectID),
				TargetType: "gcp:project",
				RelType:    RelBelongsTo,
			})
		}
	}

	// GCP IAM service account keys - service account membership relationships
	query = `SELECT _CQ_ID, NAME, PROJECT_ID, SERVICE_ACCOUNT_NAME, SERVICE_ACCOUNT_EMAIL
	         FROM GCP_IAM_SERVICE_ACCOUNT_KEYS
	         WHERE (_CQ_ID IS NOT NULL OR NAME IS NOT NULL) AND (SERVICE_ACCOUNT_NAME IS NOT NULL OR SERVICE_ACCOUNT_EMAIL IS NOT NULL)`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_IAM_SERVICE_ACCOUNT_KEYS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			keyID := normalizeRelationshipID(toString(queryRow(row, "_cq_id")))
			if keyID == "" {
				keyID = normalizeRelationshipID(toString(queryRow(row, "name")))
			}
			if keyID == "" {
				continue
			}

			projectID := toString(queryRow(row, "project_id"))
			serviceAccountID := gcpServiceAccountID(
				"",
				toString(queryRow(row, "service_account_name")),
				projectID,
				toString(queryRow(row, "service_account_email")),
			)
			if serviceAccountID == "" {
				continue
			}

			rels = append(rels, Relationship{
				SourceID:   keyID,
				SourceType: "gcp:iam:service_account_key",
				TargetID:   serviceAccountID,
				TargetType: "gcp:iam:service_account",
				RelType:    RelBelongsTo,
			})
		}
	}

	// GCP IAM policies - policy to project relationships
	query = `SELECT _CQ_ID, PROJECT_ID
	         FROM GCP_IAM_POLICIES
	         WHERE PROJECT_ID IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_IAM_POLICIES", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			projectID := toString(queryRow(row, "project_id"))
			if projectID == "" {
				continue
			}
			policyID := normalizeRelationshipID(toString(queryRow(row, "_cq_id")))
			if policyID == "" {
				policyID = fmt.Sprintf("%s/iam-policy", gcpProjectPath(projectID))
			}

			rels = append(rels, Relationship{
				SourceID:   policyID,
				SourceType: "gcp:iam:policy",
				TargetID:   gcpProjectPath(projectID),
				TargetType: "gcp:project",
				RelType:    RelBelongsTo,
			})
		}
	}

	// GCP IAM members - principal role membership relationships
	query = `SELECT PROJECT_ID, MEMBER, MEMBER_TYPE, EMAIL, ROLES
	         FROM GCP_IAM_MEMBERS
	         WHERE PROJECT_ID IS NOT NULL AND MEMBER IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_IAM_MEMBERS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			projectID := toString(queryRow(row, "project_id"))
			if projectID == "" {
				continue
			}
			principalID, principalType := gcpIAMPrincipal(
				toString(queryRow(row, "member")),
				toString(queryRow(row, "member_type")),
				toString(queryRow(row, "email")),
				projectID,
			)
			if principalID == "" {
				continue
			}

			rels = append(rels, Relationship{
				SourceID:   principalID,
				SourceType: principalType,
				TargetID:   gcpProjectPath(projectID),
				TargetType: "gcp:project",
				RelType:    RelBelongsTo,
			})

			for _, role := range asSlice(queryRow(row, "roles")) {
				roleMap := asMap(role)
				if roleMap == nil {
					continue
				}
				roleName := normalizeRelationshipID(getStringAny(roleMap, "name", "Name"))
				if roleName == "" {
					continue
				}
				rels = append(rels, Relationship{
					SourceID:   principalID,
					SourceType: principalType,
					TargetID:   roleName,
					TargetType: "gcp:iam:role",
					RelType:    RelHasPermission,
				})
			}
		}
	}

	// GCP KMS keys - key ring and key version relationships
	query = `SELECT _CQ_ID, SELF_LINK, KEY_RING, PRIMARY
	         FROM GCP_KMS_KEYS
	         WHERE (_CQ_ID IS NOT NULL OR SELF_LINK IS NOT NULL)`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_KMS_KEYS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			keyID := normalizeRelationshipID(toString(queryRow(row, "_cq_id")))
			if keyID == "" {
				keyID = normalizeRelationshipID(toString(queryRow(row, "self_link")))
			}
			if keyID == "" {
				continue
			}

			if keyRingID := normalizeRelationshipID(toString(queryRow(row, "key_ring"))); keyRingID != "" {
				rels = append(rels, Relationship{
					SourceID:   keyID,
					SourceType: "gcp:kms:key",
					TargetID:   keyRingID,
					TargetType: "gcp:kms:key_ring",
					RelType:    RelBelongsTo,
				})
			}

			if primary := asMap(queryRow(row, "primary")); primary != nil {
				if versionID := normalizeRelationshipID(getStringAny(primary, "name", "Name")); versionID != "" {
					rels = append(rels, Relationship{
						SourceID:   keyID,
						SourceType: "gcp:kms:key",
						TargetID:   versionID,
						TargetType: "gcp:kms:key_version",
						RelType:    RelContains,
					})
				}
			}
		}
	}

	// GCP Logging sinks - destination and writer identity relationships
	query = `SELECT _CQ_ID, PROJECT_ID, NAME, DESTINATION, WRITER_IDENTITY, DESTINATION_IAM_PERMISSIONS_PUBLIC
	         FROM GCP_LOGGING_SINKS
	         WHERE (_CQ_ID IS NOT NULL OR (PROJECT_ID IS NOT NULL AND NAME IS NOT NULL))`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_LOGGING_SINKS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			sinkID := gcpLoggingSinkID(
				toString(queryRow(row, "_cq_id")),
				toString(queryRow(row, "project_id")),
				toString(queryRow(row, "name")),
			)
			if sinkID == "" {
				continue
			}

			if destinationID, destinationType := gcpLoggingDestinationID(toString(queryRow(row, "destination"))); destinationID != "" {
				rels = append(rels, Relationship{
					SourceID:   sinkID,
					SourceType: "gcp:logging:sink",
					TargetID:   destinationID,
					TargetType: destinationType,
					RelType:    RelWritesTo,
				})
			}

			if writerIdentity := toString(queryRow(row, "writer_identity")); writerIdentity != "" {
				principalID, principalType := gcpIAMPrincipal(writerIdentity, "", "", toString(queryRow(row, "project_id")))
				if principalID != "" {
					rels = append(rels, Relationship{
						SourceID:   sinkID,
						SourceType: "gcp:logging:sink",
						TargetID:   principalID,
						TargetType: principalType,
						RelType:    RelHasRole,
					})
				}
			}

			if publicDest, ok := queryRow(row, "destination_iam_permissions_public").(bool); ok && publicDest {
				rels = append(rels, Relationship{
					SourceID:   sinkID,
					SourceType: "gcp:logging:sink",
					TargetID:   "internet",
					TargetType: "network:internet",
					RelType:    RelExposedTo,
				})
			}
		}
	}

	// GCP Logging project sinks summary - project ownership relationship
	query = `SELECT _CQ_ID, PROJECT_ID, SINK_COUNT, DISABLED
	         FROM GCP_LOGGING_PROJECT_SINKS
	         WHERE PROJECT_ID IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_LOGGING_PROJECT_SINKS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			projectID := toString(queryRow(row, "project_id"))
			if projectID == "" {
				continue
			}
			summaryID := normalizeRelationshipID(toString(queryRow(row, "_cq_id")))
			if summaryID == "" {
				summaryID = fmt.Sprintf("%s/logging-sinks", gcpProjectPath(projectID))
			}

			props := map[string]interface{}{}
			if sinkCount := queryRow(row, "sink_count"); sinkCount != nil {
				props["sink_count"] = sinkCount
			}
			if disabled, ok := queryRow(row, "disabled").(bool); ok {
				props["disabled"] = disabled
			}

			propJSON, _ := encodeProperties(props)
			rels = append(rels, Relationship{
				SourceID:   summaryID,
				SourceType: "gcp:logging:project_sinks",
				TargetID:   gcpProjectPath(projectID),
				TargetType: "gcp:project",
				RelType:    RelBelongsTo,
				Properties: propJSON,
			})
		}
	}

	// GCP Cloud Functions - service account is in SERVICE_CONFIG
	query = `SELECT NAME, PROJECT_ID, SERVICE_CONFIG
	         FROM GCP_CLOUDFUNCTIONS_FUNCTIONS WHERE NAME IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_CLOUDFUNCTIONS_FUNCTIONS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			funcName := toString(queryRow(row, "name"))
			projectID := toString(queryRow(row, "project_id"))

			// Extract service account from SERVICE_CONFIG
			if svcConfig := queryRow(row, "service_config"); svcConfig != nil {
				var configMap map[string]interface{}
				configStr := toString(svcConfig)
				if unmarshalErr := json.Unmarshal([]byte(configStr), &configMap); unmarshalErr == nil {
					if saEmail := toString(configMap["service_account_email"]); saEmail != "" {
						targetID := saEmail
						if projectID != "" {
							targetID = fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, saEmail)
						}
						rels = append(rels, Relationship{
							SourceID:   funcName,
							SourceType: "gcp:cloudfunctions:function",
							TargetID:   targetID,
							TargetType: "gcp:iam:service_account",
							RelType:    RelHasRole,
						})
					}
				}
			}
		}
	}

	// GCP Cloud Run Services - extract service account from TEMPLATE
	query = `SELECT NAME, PROJECT_ID, TEMPLATE, INGRESS, URI
	         FROM GCP_CLOUDRUN_SERVICES WHERE NAME IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_CLOUDRUN_SERVICES", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			svcName := toString(queryRow(row, "name"))
			projectID := toString(queryRow(row, "project_id"))
			ingress := toString(queryRow(row, "ingress"))
			uri := toString(queryRow(row, "uri"))

			// Extract service account from TEMPLATE
			if template := queryRow(row, "template"); template != nil {
				var templateMap map[string]interface{}
				templateStr := toString(template)
				if unmarshalErr := json.Unmarshal([]byte(templateStr), &templateMap); unmarshalErr == nil {
					if saEmail := toString(templateMap["service_account"]); saEmail != "" {
						targetID := saEmail
						if projectID != "" && !strings.Contains(saEmail, "/") {
							targetID = fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, saEmail)
						}
						rels = append(rels, Relationship{
							SourceID:   svcName,
							SourceType: "gcp:cloudrun:service",
							TargetID:   targetID,
							TargetType: "gcp:iam:service_account",
							RelType:    RelHasRole,
						})

						// If using default compute SA, flag as high-risk relationship
						if strings.Contains(saEmail, "compute@developer.gserviceaccount.com") {
							props, _ := json.Marshal(map[string]interface{}{
								"risk": "default_compute_sa",
								"note": "Using default compute service account with broad permissions",
							})
							rels = append(rels, Relationship{
								SourceID:   svcName,
								SourceType: "gcp:cloudrun:service",
								TargetID:   targetID,
								TargetType: "gcp:iam:service_account",
								RelType:    "USES_DEFAULT_SA",
								Properties: string(props),
							})
						}
					}
				}
			}

			// If publicly accessible, create exposure relationship
			if ingress == "INGRESS_TRAFFIC_ALL" && uri != "" {
				props, _ := json.Marshal(map[string]interface{}{
					"exposure_level": "high",
					"uri":            uri,
				})
				rels = append(rels, Relationship{
					SourceID:   svcName,
					SourceType: "gcp:cloudrun:service",
					TargetID:   "internet",
					TargetType: "network:internet",
					RelType:    RelExposedTo,
					Properties: string(props),
				})
			}
		}
	}

	// GCP Cloud Run Revisions - extract service account directly
	query = `SELECT NAME, PROJECT_ID, SERVICE, SERVICE_ACCOUNT, CONTAINERS
	         FROM GCP_CLOUDRUN_REVISIONS WHERE NAME IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_CLOUDRUN_REVISIONS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			revName := toString(queryRow(row, "name"))
			projectID := toString(queryRow(row, "project_id"))
			serviceName := toString(queryRow(row, "service"))
			saEmail := toString(queryRow(row, "service_account"))

			// Revision -> Service relationship
			if serviceName != "" {
				rels = append(rels, Relationship{
					SourceID:   revName,
					SourceType: "gcp:cloudrun:revision",
					TargetID:   serviceName,
					TargetType: "gcp:cloudrun:service",
					RelType:    RelBelongsTo,
				})
			}

			// Revision -> Service Account relationship
			if saEmail != "" {
				targetID := saEmail
				if projectID != "" && !strings.Contains(saEmail, "/") {
					targetID = fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, saEmail)
				}
				rels = append(rels, Relationship{
					SourceID:   revName,
					SourceType: "gcp:cloudrun:revision",
					TargetID:   targetID,
					TargetType: "gcp:iam:service_account",
					RelType:    RelHasRole,
				})

				// Flag default compute SA usage
				if strings.Contains(saEmail, "compute@developer.gserviceaccount.com") {
					props, _ := json.Marshal(map[string]interface{}{
						"risk": "default_compute_sa",
						"note": "Revision uses default compute service account",
					})
					rels = append(rels, Relationship{
						SourceID:   revName,
						SourceType: "gcp:cloudrun:revision",
						TargetID:   targetID,
						TargetType: "gcp:iam:service_account",
						RelType:    "USES_DEFAULT_SA",
						Properties: string(props),
					})
				}
			}

			// Extract container image relationships
			if containers := queryRow(row, "containers"); containers != nil {
				var containerList []map[string]interface{}
				containerStr := toString(containers)
				if err := json.Unmarshal([]byte(containerStr), &containerList); err == nil {
					for _, container := range containerList {
						if image := toString(container["image"]); image != "" {
							rels = append(rels, Relationship{
								SourceID:   revName,
								SourceType: "gcp:cloudrun:revision",
								TargetID:   image,
								TargetType: "container:image",
								RelType:    "RUNS_IMAGE",
							})
						}
					}
				}
			}
		}
	}

	// GCP Storage buckets - encryption and logging relationships
	query = `SELECT NAME, LOGGING_LOG_BUCKET, ENCRYPTION_DEFAULT_KMS_KEY
	         FROM GCP_STORAGE_BUCKETS WHERE NAME IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_STORAGE_BUCKETS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			bucketName := toString(queryRow(row, "name"))
			if bucketName == "" {
				continue
			}
			bucketID := gcpStorageBucketID(bucketName)
			if bucketID == "" {
				continue
			}

			if kmsKey := toString(queryRow(row, "encryption_default_kms_key")); kmsKey != "" {
				rels = append(rels, Relationship{
					SourceID:   bucketID,
					SourceType: "gcp:storage:bucket",
					TargetID:   kmsKey,
					TargetType: "gcp:kms:key",
					RelType:    RelEncryptedBy,
				})
			}

			if logBucket := toString(queryRow(row, "logging_log_bucket")); logBucket != "" {
				logBucketID := gcpStorageBucketID(logBucket)
				if logBucketID == "" {
					continue
				}
				rels = append(rels, Relationship{
					SourceID:   bucketID,
					SourceType: "gcp:storage:bucket",
					TargetID:   logBucketID,
					TargetType: "gcp:storage:bucket",
					RelType:    RelLogsTo,
				})
			}
		}
	}

	// GCP Storage objects - bucket membership and encryption relationships
	query = `SELECT _CQ_ID, SELF_LINK, BUCKET, NAME, KMS_KEY_NAME
	         FROM GCP_STORAGE_OBJECTS
	         WHERE BUCKET IS NOT NULL AND (_CQ_ID IS NOT NULL OR SELF_LINK IS NOT NULL OR NAME IS NOT NULL)`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_STORAGE_OBJECTS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			objectID := gcpStorageObjectID(
				toString(queryRow(row, "_cq_id")),
				toString(queryRow(row, "self_link")),
				toString(queryRow(row, "bucket")),
				toString(queryRow(row, "name")),
			)
			if objectID == "" {
				continue
			}

			if bucketID := gcpStorageBucketID(toString(queryRow(row, "bucket"))); bucketID != "" {
				rels = append(rels, Relationship{
					SourceID:   objectID,
					SourceType: "gcp:storage:object",
					TargetID:   bucketID,
					TargetType: "gcp:storage:bucket",
					RelType:    RelBelongsTo,
				})
			}

			if kmsKey := toString(queryRow(row, "kms_key_name")); kmsKey != "" {
				rels = append(rels, Relationship{
					SourceID:   objectID,
					SourceType: "gcp:storage:object",
					TargetID:   kmsKey,
					TargetType: "gcp:kms:key",
					RelType:    RelEncryptedBy,
				})
			}
		}
	}

	// GCP Pub/Sub topics - encryption relationships
	query = `SELECT _CQ_ID, PROJECT_ID, NAME, KMS_KEY_NAME
	         FROM GCP_PUBSUB_TOPICS
	         WHERE (_CQ_ID IS NOT NULL OR (PROJECT_ID IS NOT NULL AND NAME IS NOT NULL))`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_PUBSUB_TOPICS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			topicID := gcpPubSubTopicID(
				toString(queryRow(row, "_cq_id")),
				toString(queryRow(row, "project_id")),
				toString(queryRow(row, "name")),
			)
			if topicID == "" {
				continue
			}

			if kmsKey := toString(queryRow(row, "kms_key_name")); kmsKey != "" {
				rels = append(rels, Relationship{
					SourceID:   topicID,
					SourceType: "gcp:pubsub:topic",
					TargetID:   kmsKey,
					TargetType: "gcp:kms:key",
					RelType:    RelEncryptedBy,
				})
			}
		}
	}

	// GCP IDS endpoints - network and forwarding rule relationships
	query = `SELECT _CQ_ID, NAME, NETWORK, ENDPOINT_FORWARDING_RULE
	         FROM GCP_IDS_ENDPOINTS
	         WHERE (_CQ_ID IS NOT NULL OR NAME IS NOT NULL)`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_IDS_ENDPOINTS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			endpointID := gcpIDSEndpointID(
				toString(queryRow(row, "_cq_id")),
				toString(queryRow(row, "name")),
			)
			if endpointID == "" {
				continue
			}

			if networkID := normalizeRelationshipID(toString(queryRow(row, "network"))); networkID != "" {
				rels = append(rels, Relationship{
					SourceID:   endpointID,
					SourceType: "gcp:ids:endpoint",
					TargetID:   networkID,
					TargetType: "gcp:compute:network",
					RelType:    RelInVPC,
				})
			}

			if forwardingRuleID := normalizeRelationshipID(toString(queryRow(row, "endpoint_forwarding_rule"))); forwardingRuleID != "" {
				rels = append(rels, Relationship{
					SourceID:   endpointID,
					SourceType: "gcp:ids:endpoint",
					TargetID:   forwardingRuleID,
					TargetType: "gcp:compute:forwarding_rule",
					RelType:    RelAttachedTo,
				})
			}
		}
	}

	// GCP Artifact Registry repositories - encryption relationships
	query = `SELECT PROJECT_ID, NAME, SELF_LINK, KMS_KEY_NAME
	         FROM GCP_ARTIFACT_REGISTRY_REPOSITORIES
	         WHERE (SELF_LINK IS NOT NULL OR NAME IS NOT NULL)`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_ARTIFACT_REGISTRY_REPOSITORIES", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			repositoryID := toString(queryRow(row, "self_link"))
			if repositoryID == "" {
				projectID := toString(queryRow(row, "project_id"))
				repoName := toString(queryRow(row, "name"))
				if projectID != "" && repoName != "" {
					repositoryID = fmt.Sprintf("projects/%s/locations/-/repositories/%s", projectID, repoName)
				}
			}
			if repositoryID == "" {
				continue
			}

			if kmsKey := toString(queryRow(row, "kms_key_name")); kmsKey != "" {
				rels = append(rels, Relationship{
					SourceID:   repositoryID,
					SourceType: "gcp:artifactregistry:repository",
					TargetID:   kmsKey,
					TargetType: "gcp:kms:key",
					RelType:    RelEncryptedBy,
				})
			}
		}
	}

	// GCP Artifact Registry packages - repository membership relationships
	query = `SELECT _CQ_ID, PROJECT_ID, NAME, SELF_LINK, REPOSITORY
	         FROM GCP_ARTIFACT_REGISTRY_PACKAGES
	         WHERE (_CQ_ID IS NOT NULL OR SELF_LINK IS NOT NULL)`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_ARTIFACT_REGISTRY_PACKAGES", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			packageID := gcpArtifactPackageID(
				toString(queryRow(row, "_cq_id")),
				toString(queryRow(row, "self_link")),
				toString(queryRow(row, "project_id")),
				toString(queryRow(row, "repository")),
				toString(queryRow(row, "name")),
			)
			if packageID == "" {
				continue
			}

			repositoryID := gcpArtifactRepositoryIDFromPackage(
				packageID,
				toString(queryRow(row, "project_id")),
				toString(queryRow(row, "repository")),
			)
			if repositoryID == "" {
				continue
			}

			rels = append(rels, Relationship{
				SourceID:   packageID,
				SourceType: "gcp:artifactregistry:package",
				TargetID:   repositoryID,
				TargetType: "gcp:artifactregistry:repository",
				RelType:    RelBelongsTo,
			})
		}
	}

	// GCP Artifact Registry versions - package membership relationships
	query = `SELECT _CQ_ID, PROJECT_ID, NAME, SELF_LINK, REPOSITORY, PACKAGE AS PACKAGE_NAME
	         FROM GCP_ARTIFACT_REGISTRY_VERSIONS
	         WHERE (_CQ_ID IS NOT NULL OR SELF_LINK IS NOT NULL)`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_ARTIFACT_REGISTRY_VERSIONS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			projectID := toString(queryRow(row, "project_id"))
			repository := toString(queryRow(row, "repository"))
			packageName := toString(queryRow(row, "package_name"))

			versionID := gcpArtifactVersionID(
				toString(queryRow(row, "_cq_id")),
				toString(queryRow(row, "self_link")),
				projectID,
				repository,
				packageName,
				toString(queryRow(row, "name")),
			)
			if versionID == "" {
				continue
			}

			packageID := gcpArtifactPackageIDFromVersion(versionID, projectID, repository, packageName)
			if packageID == "" {
				continue
			}
			repositoryID := gcpArtifactRepositoryIDFromPackage(packageID, projectID, repository)

			rels = append(rels, Relationship{
				SourceID:   versionID,
				SourceType: "gcp:artifactregistry:version",
				TargetID:   packageID,
				TargetType: "gcp:artifactregistry:package",
				RelType:    RelBelongsTo,
			})

			if repositoryID != "" {
				rels = append(rels, Relationship{
					SourceID:   versionID,
					SourceType: "gcp:artifactregistry:version",
					TargetID:   repositoryID,
					TargetType: "gcp:artifactregistry:repository",
					RelType:    RelBelongsTo,
				})
			}
		}
	}

	// GCP Artifact Registry images (security sync) - repository/package membership
	query = `SELECT _CQ_ID, URI, NAME, REPOSITORY
	         FROM GCP_ARTIFACT_REGISTRY_IMAGES
	         WHERE (URI IS NOT NULL OR _CQ_ID IS NOT NULL OR NAME IS NOT NULL)`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_ARTIFACT_REGISTRY_IMAGES", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			imageID := gcpArtifactImageID(
				toString(queryRow(row, "uri")),
				toString(queryRow(row, "_cq_id")),
				toString(queryRow(row, "name")),
			)
			if imageID == "" {
				continue
			}

			repositoryID := gcpArtifactRepositoryID(
				toString(queryRow(row, "repository")),
				toString(queryRow(row, "name")),
			)
			if repositoryID != "" {
				rels = append(rels, Relationship{
					SourceID:   imageID,
					SourceType: "gcp:artifactregistry:image",
					TargetID:   repositoryID,
					TargetType: "gcp:artifactregistry:repository",
					RelType:    RelBelongsTo,
				})
			}

			if packageID := gcpArtifactPackageIDFromImage(toString(queryRow(row, "name"))); packageID != "" {
				rels = append(rels, Relationship{
					SourceID:   imageID,
					SourceType: "gcp:artifactregistry:image",
					TargetID:   packageID,
					TargetType: "gcp:artifactregistry:package",
					RelType:    RelBelongsTo,
				})
			}
		}
	}

	// GCP vulnerability occurrences - image vulnerability relationships
	query = `SELECT _CQ_ID, RESOURCE_URI, SEVERITY, CVE_ID, FIX_AVAILABLE
	         FROM GCP_CONTAINER_VULNERABILITIES
	         WHERE RESOURCE_URI IS NOT NULL AND _CQ_ID IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_CONTAINER_VULNERABILITIES", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			imageID := gcpArtifactImageID(toString(queryRow(row, "resource_uri")), "", "")
			vulnID := normalizeRelationshipID(toString(queryRow(row, "_cq_id")))
			if imageID == "" || vulnID == "" {
				continue
			}

			props := map[string]interface{}{}
			if severity := toString(queryRow(row, "severity")); severity != "" {
				props["severity"] = severity
			}
			if cve := toString(queryRow(row, "cve_id")); cve != "" {
				props["cve_id"] = cve
			}
			if fixAvailable := queryRow(row, "fix_available"); fixAvailable != nil {
				props["fix_available"] = fixAvailable
			}

			propJSON, _ := encodeProperties(props)
			rels = append(rels, Relationship{
				SourceID:   imageID,
				SourceType: "gcp:artifactregistry:image",
				TargetID:   vulnID,
				TargetType: "gcp:container:vulnerability",
				RelType:    RelHasVulnerability,
				Properties: propJSON,
			})
		}
	}

	// GCP SCC findings - finding to affected resource relationships
	query = `SELECT _CQ_ID, NAME, RESOURCE_NAME, CATEGORY, SEVERITY, STATE
	         FROM GCP_SCC_FINDINGS
	         WHERE RESOURCE_NAME IS NOT NULL AND (_CQ_ID IS NOT NULL OR NAME IS NOT NULL)`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_SCC_FINDINGS", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			findingID := gcpSCCFindingID(
				toString(queryRow(row, "_cq_id")),
				toString(queryRow(row, "name")),
			)
			resourceID := normalizeRelationshipID(toString(queryRow(row, "resource_name")))
			if findingID == "" || resourceID == "" {
				continue
			}

			props := map[string]interface{}{}
			if category := toString(queryRow(row, "category")); category != "" {
				props["category"] = category
			}
			if severity := toString(queryRow(row, "severity")); severity != "" {
				props["severity"] = severity
			}
			if state := toString(queryRow(row, "state")); state != "" {
				props["state"] = state
			}

			propJSON, _ := encodeProperties(props)
			rels = append(rels, Relationship{
				SourceID:   findingID,
				SourceType: "gcp:scc:finding",
				TargetID:   resourceID,
				TargetType: "gcp:resource",
				RelType:    RelBelongsTo,
				Properties: propJSON,
			})
		}
	}

	// GCP Org Policy relationships
	query = `SELECT SELF_LINK, PARENT, CONSTRAINT
	         FROM GCP_ORG_POLICIES
	         WHERE SELF_LINK IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_ORG_POLICIES", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			policyID := toString(queryRow(row, "self_link"))
			if policyID == "" {
				continue
			}

			if parent := toString(queryRow(row, "parent")); parent != "" {
				rels = append(rels, Relationship{
					SourceID:   policyID,
					SourceType: "gcp:orgpolicy:policy",
					TargetID:   parent,
					TargetType: "gcp:resource",
					RelType:    RelBelongsTo,
				})
			}

			if constraint := toString(queryRow(row, "constraint")); constraint != "" {
				rels = append(rels, Relationship{
					SourceID:   policyID,
					SourceType: "gcp:orgpolicy:policy",
					TargetID:   constraint,
					TargetType: "gcp:orgpolicy:constraint",
					RelType:    RelProtects,
				})
			}
		}
	}

	// GCP SQL instances - service account, network, and encryption relationships
	query = `SELECT NAME, PROJECT_ID, SELF_LINK, SERVICE_ACCOUNT_EMAIL_ADDRESS, SETTINGS, DISK_ENCRYPTION_CONFIGURATION
	         FROM GCP_SQL_INSTANCES WHERE NAME IS NOT NULL`

	if result, ok, err := r.queryRowsForTable(ctx, "GCP_SQL_INSTANCES", query); err != nil {
		return 0, err
	} else if ok {
		for _, row := range result.Rows {
			instanceID := toString(queryRow(row, "self_link"))
			name := toString(queryRow(row, "name"))
			projectID := toString(queryRow(row, "project_id"))
			if instanceID == "" && projectID != "" && name != "" {
				instanceID = fmt.Sprintf("projects/%s/instances/%s", projectID, name)
			}
			if instanceID == "" {
				continue
			}

			if saEmail := toString(queryRow(row, "service_account_email_address")); saEmail != "" {
				targetID := saEmail
				if projectID != "" && !strings.Contains(saEmail, "/") {
					targetID = fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, saEmail)
				}
				rels = append(rels, Relationship{
					SourceID:   instanceID,
					SourceType: "gcp:sql:instance",
					TargetID:   targetID,
					TargetType: "gcp:iam:service_account",
					RelType:    RelHasRole,
				})
			}

			if settings := asMap(queryRow(row, "settings")); settings != nil {
				if privateNetwork := getStringAny(settings, "private_network", "privateNetwork"); privateNetwork != "" {
					rels = append(rels, Relationship{
						SourceID:   instanceID,
						SourceType: "gcp:sql:instance",
						TargetID:   privateNetwork,
						TargetType: "gcp:compute:network",
						RelType:    RelInVPC,
					})
				}
			}

			if encConfig := asMap(queryRow(row, "disk_encryption_configuration")); encConfig != nil {
				if kmsKey := getStringAny(encConfig, "kms_key_name", "kmsKeyName"); kmsKey != "" {
					rels = append(rels, Relationship{
						SourceID:   instanceID,
						SourceType: "gcp:sql:instance",
						TargetID:   kmsKey,
						TargetType: "gcp:kms:key",
						RelType:    RelEncryptedBy,
					})
				}
			}
		}
	}

	assetRels, err := r.extractGCPAssetInventoryRelationships(ctx)
	if err != nil {
		if !isMissingRelationshipSourceError(err) {
			return 0, err
		}
	} else {
		rels = append(rels, assetRels...)
	}

	return r.persistRelationships(ctx, rels)
}

func (r *RelationshipExtractor) extractGCPAssetInventoryRelationships(ctx context.Context) ([]Relationship, error) {
	tablesSet := make(map[string]struct{})
	for _, table := range GCPAssetTypes {
		tablesSet[table] = struct{}{}
	}

	tables := make([]string, 0, len(tablesSet))
	for table := range tablesSet {
		tables = append(tables, table)
	}
	sort.Strings(tables)

	rels := make([]Relationship, 0)
	for _, table := range tables {
		if err := snowflake.ValidateTableName(table); err != nil {
			continue
		}

		columnSet, err := r.getTableColumnSet(ctx, table)
		if err != nil {
			return nil, err
		}
		if !hasTableColumn(columnSet, "_CQ_ID") {
			continue
		}

		query := buildGCPAssetInventoryQuery(table, columnSet)
		result, err := r.sf.Query(ctx, query)
		if err != nil {
			if isMissingRelationshipSourceError(err) {
				continue
			}
			return nil, err
		}

		for _, row := range result.Rows {
			sourceID := normalizeRelationshipID(toString(queryRow(row, "_cq_id")))
			if sourceID == "" {
				continue
			}
			sourceType := gcpAssetNodeType(toString(queryRow(row, "asset_type")))
			if sourceType == "" {
				sourceType = "gcp:resource"
			}

			if parentID := normalizeRelationshipID(toString(queryRow(row, "parent_full_name"))); parentID != "" {
				targetType := gcpAssetNodeType(toString(queryRow(row, "parent_asset_type")))
				if targetType == "" {
					targetType = "gcp:resource"
				}
				rels = append(rels, Relationship{
					SourceID:   sourceID,
					SourceType: sourceType,
					TargetID:   parentID,
					TargetType: targetType,
					RelType:    RelBelongsTo,
				})
			}

			if kmsKeys := asSlice(queryRow(row, "kms_keys")); len(kmsKeys) > 0 {
				for _, key := range kmsKeys {
					kmsKeyID := extractGCPKMSKeyID(key)
					if kmsKeyID == "" {
						continue
					}
					rels = append(rels, Relationship{
						SourceID:   sourceID,
						SourceType: sourceType,
						TargetID:   kmsKeyID,
						TargetType: "gcp:kms:key",
						RelType:    RelEncryptedBy,
					})
				}
			}

			if relationItems := asSlice(queryRow(row, "relationships")); len(relationItems) > 0 {
				for _, item := range relationItems {
					relMap := asMap(item)
					if relMap == nil {
						continue
					}
					targetID := normalizeRelationshipID(getStringAny(relMap, "full_resource_name", "fullResourceName", "target", "target_id", "targetId"))
					if targetID == "" {
						continue
					}

					relType := normalizeGCPAssetRelationshipType(getStringAny(relMap, "type", "relationship_type", "relationshipType"))
					if relType == "" {
						relType = RelAttachedTo
					}
					targetType := gcpAssetNodeType(getStringAny(relMap, "asset_type", "assetType"))
					if targetType == "" {
						targetType = "gcp:resource"
					}

					rels = append(rels, Relationship{
						SourceID:   sourceID,
						SourceType: sourceType,
						TargetID:   targetID,
						TargetType: targetType,
						RelType:    relType,
					})
				}
			}
		}
	}

	return rels, nil
}
