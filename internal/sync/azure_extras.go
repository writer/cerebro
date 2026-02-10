package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

func (e *AzureSyncEngine) azureFunctionAppTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_functions_apps",
		Columns: []string{
			"id", "name", "location", "resource_group", "kind", "state", "https_only",
			"client_cert_enabled", "identity", "tags", "subscription_id", "site_config",
			"auth_level", "http_trigger",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			client, err := armappservice.NewWebAppsClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}
			pager := client.NewListPager(nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, app := range page.Value {
					if !isFunctionApp(app.Kind) {
						continue
					}

					row := map[string]interface{}{
						"_cq_id":          ptrStr(app.ID),
						"id":              ptrStr(app.ID),
						"name":            ptrStr(app.Name),
						"location":        ptrStr(app.Location),
						"resource_group":  resourceGroupFromID(ptrStr(app.ID)),
						"kind":            ptrStr(app.Kind),
						"subscription_id": subscriptionID,
						"tags":            app.Tags,
					}

					if app.Properties != nil {
						row["state"] = ptrStr(app.Properties.State)
						row["https_only"] = app.Properties.HTTPSOnly
						row["client_cert_enabled"] = app.Properties.ClientCertEnabled
						if app.Properties.SiteConfig != nil {
							row["site_config"] = map[string]interface{}{
								"http20_enabled":  app.Properties.SiteConfig.Http20Enabled,
								"ftps_state":      app.Properties.SiteConfig.FtpsState,
								"min_tls_version": app.Properties.SiteConfig.MinTLSVersion,
							}
						}
					}
					if app.Identity != nil {
						row["identity"] = app.Identity
					}

					authLevel, httpTrigger, err := fetchFunctionAppAuth(ctx, client, row["resource_group"].(string), ptrStr(app.Name))
					if err == nil {
						if authLevel != "" {
							row["auth_level"] = authLevel
						}
						row["http_trigger"] = httpTrigger
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *AzureSyncEngine) azureStorageContainerTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_storage_containers",
		Columns: []string{
			"id", "name", "account_name", "resource_group", "public_access",
			"immutability_policy", "has_immutability_policy", "legal_hold",
			"metadata", "last_modified", "lease_status", "lease_state",
			"subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			accountsClient, err := armstorage.NewAccountsClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}
			containersClient, err := armstorage.NewBlobContainersClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}
			accountsPager := accountsClient.NewListPager(nil)
			for accountsPager.More() {
				page, err := accountsPager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, account := range page.Value {
					accountName := ptrStr(account.Name)
					resourceGroup := resourceGroupFromID(ptrStr(account.ID))
					if accountName == "" || resourceGroup == "" {
						continue
					}

					containersPager := containersClient.NewListPager(resourceGroup, accountName, nil)
					for containersPager.More() {
						containerPage, err := containersPager.NextPage(ctx)
						if err != nil {
							return nil, err
						}
						for _, container := range containerPage.Value {
							row := map[string]interface{}{
								"_cq_id":          ptrStr(container.ID),
								"id":              ptrStr(container.ID),
								"name":            ptrStr(container.Name),
								"account_name":    accountName,
								"resource_group":  resourceGroup,
								"subscription_id": subscriptionID,
							}

							if container.Properties != nil {
								row["public_access"] = ptrToStringValue(container.Properties.PublicAccess)
								row["metadata"] = container.Properties.Metadata
								row["last_modified"] = container.Properties.LastModifiedTime
								row["lease_status"] = container.Properties.LeaseStatus
								row["lease_state"] = container.Properties.LeaseState
								row["legal_hold"] = container.Properties.LegalHold
								row["immutability_policy"] = container.Properties.ImmutabilityPolicy
								row["has_immutability_policy"] = container.Properties.ImmutabilityPolicy != nil
							}

							results = append(results, row)
						}
					}
				}
			}

			return results, nil
		},
	}
}

func (e *AzureSyncEngine) azureStorageBlobTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_storage_blobs",
		Columns: []string{
			"id", "name", "container_name", "account_name", "resource_group",
			"content_length", "content_type", "etag", "last_modified", "blob_type",
			"access_tier", "metadata", "snapshot", "version_id", "subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			accountsClient, err := armstorage.NewAccountsClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}
			containersClient, err := armstorage.NewBlobContainersClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}
			accountsPager := accountsClient.NewListPager(nil)
			for accountsPager.More() {
				page, err := accountsPager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, account := range page.Value {
					accountName := ptrStr(account.Name)
					resourceGroup := resourceGroupFromID(ptrStr(account.ID))
					if accountName == "" || resourceGroup == "" {
						continue
					}

					serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", accountName)
					blobClient, err := azblob.NewClient(serviceURL, cred, nil)
					if err != nil {
						return nil, err
					}

					containersPager := containersClient.NewListPager(resourceGroup, accountName, nil)
					for containersPager.More() {
						containerPage, err := containersPager.NextPage(ctx)
						if err != nil {
							return nil, err
						}
						for _, container := range containerPage.Value {
							containerName := ptrStr(container.Name)
							if containerName == "" {
								continue
							}

							pager := blobClient.NewListBlobsFlatPager(containerName, nil)
							for pager.More() {
								resp, err := pager.NextPage(ctx)
								if err != nil {
									return nil, err
								}
								for _, item := range resp.Segment.BlobItems {
									blobName := ptrStr(item.Name)
									blobID := fmt.Sprintf("%s%s/%s", serviceURL, containerName, blobName)
									row := map[string]interface{}{
										"_cq_id":          blobID,
										"id":              blobID,
										"name":            blobName,
										"container_name":  containerName,
										"account_name":    accountName,
										"resource_group":  resourceGroup,
										"subscription_id": subscriptionID,
										"metadata":        item.Metadata,
										"snapshot":        ptrStr(item.Snapshot),
										"version_id":      ptrStr(item.VersionID),
									}

									if item.Properties != nil {
										row["content_length"] = item.Properties.ContentLength
										row["content_type"] = ptrStr(item.Properties.ContentType)
										row["etag"] = ptrToStringValue(item.Properties.ETag)
										row["last_modified"] = item.Properties.LastModified
										row["blob_type"] = item.Properties.BlobType
										row["access_tier"] = item.Properties.AccessTier
									}

									results = append(results, row)
								}
							}
						}
					}
				}
			}

			return results, nil
		},
	}
}

func (e *AzureSyncEngine) azureKeyVaultKeyTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_keyvault_keys",
		Columns: []string{
			"id", "name", "vault_uri", "attributes", "tags", "managed", "subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			vaultClient, err := armkeyvault.NewVaultsClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}
			pager := vaultClient.NewListBySubscriptionPager(nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, vault := range page.Value {
					vaultURI := ""
					if vault.Properties != nil {
						vaultURI = ptrStr(vault.Properties.VaultURI)
					}
					if vaultURI == "" {
						continue
					}

					keyClient, err := azkeys.NewClient(vaultURI, cred, nil)
					if err != nil {
						return nil, err
					}

					keyPager := keyClient.NewListKeyPropertiesPager(nil)
					for keyPager.More() {
						keyPage, err := keyPager.NextPage(ctx)
						if err != nil {
							return nil, err
						}
						for _, key := range keyPage.Value {
							keyID := ""
							keyName := ""
							if key.KID != nil {
								keyID = string(*key.KID)
								keyName = key.KID.Name()
							}
							row := map[string]interface{}{
								"_cq_id":          keyID,
								"id":              keyID,
								"name":            keyName,
								"vault_uri":       vaultURI,
								"tags":            key.Tags,
								"managed":         key.Managed,
								"subscription_id": subscriptionID,
							}
							if key.Attributes != nil {
								row["attributes"] = map[string]interface{}{
									"enabled":    key.Attributes.Enabled,
									"created":    key.Attributes.Created,
									"updated":    key.Attributes.Updated,
									"not_before": key.Attributes.NotBefore,
									"expires":    key.Attributes.Expires,
								}
							}

							results = append(results, row)
						}
					}
				}
			}

			return results, nil
		},
	}
}

func isFunctionApp(kind *string) bool {
	if kind == nil {
		return false
	}
	return strings.Contains(strings.ToLower(*kind), "functionapp")
}

func fetchFunctionAppAuth(ctx context.Context, client *armappservice.WebAppsClient, resourceGroup, name string) (string, bool, error) {
	if resourceGroup == "" || name == "" {
		return "", false, nil
	}

	pager := client.NewListFunctionsPager(resourceGroup, name, nil)
	var authLevel string
	var httpTrigger bool

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return "", false, err
		}
		for _, fn := range page.Value {
			level, hasHTTP := parseFunctionBindings(fn.Properties)
			if hasHTTP {
				httpTrigger = true
				if level != "" {
					if authLevel == "" || strings.EqualFold(level, "anonymous") {
						authLevel = strings.ToLower(level)
					}
				}
			}
		}
	}

	return authLevel, httpTrigger, nil
}

func parseFunctionBindings(properties *armappservice.FunctionEnvelopeProperties) (string, bool) {
	if properties == nil || properties.Config == nil {
		return "", false
	}

	configBytes, err := json.Marshal(properties.Config)
	if err != nil {
		return "", false
	}
	var config map[string]interface{}
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return "", false
	}

	bindingsValue, ok := config["bindings"]
	if !ok {
		return "", false
	}
	bindings, ok := bindingsValue.([]interface{})
	if !ok {
		return "", false
	}

	var authLevel string
	var httpTrigger bool
	for _, binding := range bindings {
		bindingMap, ok := binding.(map[string]interface{})
		if !ok {
			continue
		}
		bindingType, _ := bindingMap["type"].(string)
		if strings.EqualFold(bindingType, "httpTrigger") {
			httpTrigger = true
			if level, ok := bindingMap["authLevel"].(string); ok {
				authLevel = level
			}
		}
	}

	return authLevel, httpTrigger
}

func resourceGroupFromID(id string) string {
	parts := strings.Split(id, "/")
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func ptrToStringValue[T ~string](value *T) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
