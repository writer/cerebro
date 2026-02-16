package sync

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func (e *SyncEngine) kmsKeyTable() TableSpec {
	return TableSpec{
		Name:    "aws_kms_keys",
		Columns: []string{"arn", "account_id", "region", "key_id", "description", "key_state", "key_usage", "creation_date", "enabled", "key_manager", "origin"},
		Fetch:   e.fetchKMSKeys,
	}
}

func (e *SyncEngine) kmsAliasTable() TableSpec {
	return TableSpec{
		Name:    "aws_kms_aliases",
		Columns: []string{"arn", "account_id", "region", "alias_name", "alias_arn", "target_key_id", "creation_date", "last_updated_date"},
		Fetch:   e.fetchKMSAliases,
	}
}

func (e *SyncEngine) kmsKeyPolicyTable() TableSpec {
	return TableSpec{
		Name:    "aws_kms_key_policies",
		Columns: []string{"arn", "account_id", "region", "key_id", "key_arn", "policy_name", "policy"},
		Fetch:   e.fetchKMSKeyPolicies,
	}
}

func (e *SyncEngine) kmsGrantTable() TableSpec {
	return TableSpec{
		Name: "aws_kms_grants",
		Columns: []string{
			"arn", "account_id", "region", "key_id", "key_arn", "grant_id", "grant_name",
			"grantee_principal", "retiring_principal", "issuing_account", "operations",
			"constraints", "creation_date",
		},
		Fetch: e.fetchKMSGrants,
	}
}

func (e *SyncEngine) kmsKeyRotationStatusTable() TableSpec {
	return TableSpec{
		Name:    "aws_kms_key_rotation_statuses",
		Columns: []string{"arn", "account_id", "region", "key_id", "key_arn", "key_rotation_enabled"},
		Fetch:   e.fetchKMSKeyRotationStatuses,
	}
}

func (e *SyncEngine) kmsCustomKeyStoreTable() TableSpec {
	return TableSpec{
		Name: "aws_kms_custom_key_stores",
		Columns: []string{
			"arn", "account_id", "region", "custom_key_store_id", "custom_key_store_name",
			"custom_key_store_type", "connection_state", "connection_error_code", "creation_date",
			"cloud_hsm_cluster_id", "trust_anchor_certificate", "xks_proxy_configuration",
		},
		Fetch: e.fetchKMSCustomKeyStores,
	}
}

func (e *SyncEngine) fetchKMSKeys(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := kms.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, key := range page.Keys {
			descOut, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: key.KeyId})
			if err != nil {
				continue
			}

			km := descOut.KeyMetadata
			rows = append(rows, map[string]interface{}{
				"_cq_id":        aws.ToString(km.Arn),
				"arn":           aws.ToString(km.Arn),
				"account_id":    accountID,
				"region":        region,
				"key_id":        aws.ToString(km.KeyId),
				"description":   aws.ToString(km.Description),
				"key_state":     string(km.KeyState),
				"key_usage":     string(km.KeyUsage),
				"creation_date": km.CreationDate,
				"enabled":       km.Enabled,
				"key_manager":   string(km.KeyManager),
				"origin":        string(km.Origin),
			})
		}
	}
	return rows, nil
}

func (e *SyncEngine) fetchKMSAliases(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := kms.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := kms.NewListAliasesPaginator(client, &kms.ListAliasesInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, alias := range page.Aliases {
			aliasArn := aws.ToString(alias.AliasArn)
			aliasName := aws.ToString(alias.AliasName)
			arn := aliasArn
			if arn == "" {
				arn = fmt.Sprintf("arn:aws:kms:%s:%s:%s", region, accountID, aliasName)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":            arn,
				"arn":               arn,
				"account_id":        accountID,
				"region":            region,
				"alias_name":        aliasName,
				"alias_arn":         aliasArn,
				"target_key_id":     aws.ToString(alias.TargetKeyId),
				"creation_date":     alias.CreationDate,
				"last_updated_date": alias.LastUpdatedDate,
			})
		}
	}

	return rows, nil
}

func (e *SyncEngine) fetchKMSKeyPolicies(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := kms.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, key := range page.Keys {
			keyID := aws.ToString(key.KeyId)

			descOut, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: key.KeyId})
			if err != nil || descOut.KeyMetadata == nil {
				continue
			}
			keyArn := aws.ToString(descOut.KeyMetadata.Arn)

			policyName := "default"
			policyOut, err := client.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
				KeyId:      key.KeyId,
				PolicyName: aws.String(policyName),
			})
			if err != nil {
				continue
			}

			policyArn := fmt.Sprintf("%s/policy/%s", keyArn, policyName)
			if keyArn == "" {
				policyArn = fmt.Sprintf("arn:aws:kms:%s:%s:key/%s/policy/%s", region, accountID, keyID, policyName)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":      policyArn,
				"arn":         policyArn,
				"account_id":  accountID,
				"region":      region,
				"key_id":      keyID,
				"key_arn":     keyArn,
				"policy_name": policyName,
				"policy":      aws.ToString(policyOut.Policy),
			})
		}
	}

	return rows, nil
}

func (e *SyncEngine) fetchKMSGrants(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := kms.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, key := range page.Keys {
			keyID := aws.ToString(key.KeyId)
			descOut, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: key.KeyId})
			if err != nil || descOut.KeyMetadata == nil {
				continue
			}
			keyArn := aws.ToString(descOut.KeyMetadata.Arn)

			grantPaginator := kms.NewListGrantsPaginator(client, &kms.ListGrantsInput{
				KeyId: key.KeyId,
			})
			for grantPaginator.HasMorePages() {
				out, err := grantPaginator.NextPage(ctx)
				if err != nil {
					break
				}

				for _, grant := range out.Grants {
					grantID := aws.ToString(grant.GrantId)
					arn := fmt.Sprintf("%s/grant/%s", keyArn, grantID)
					if keyArn == "" {
						arn = fmt.Sprintf("arn:aws:kms:%s:%s:key/%s/grant/%s", region, accountID, keyID, grantID)
					}

					rows = append(rows, map[string]interface{}{
						"_cq_id":             arn,
						"arn":                arn,
						"account_id":         accountID,
						"region":             region,
						"key_id":             keyID,
						"key_arn":            keyArn,
						"grant_id":           grantID,
						"grant_name":         aws.ToString(grant.Name),
						"grantee_principal":  aws.ToString(grant.GranteePrincipal),
						"retiring_principal": aws.ToString(grant.RetiringPrincipal),
						"issuing_account":    aws.ToString(grant.IssuingAccount),
						"operations":         grant.Operations,
						"constraints":        grant.Constraints,
						"creation_date":      grant.CreationDate,
					})
				}
			}
		}
	}

	return rows, nil
}

func (e *SyncEngine) fetchKMSKeyRotationStatuses(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := kms.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, key := range page.Keys {
			keyID := aws.ToString(key.KeyId)
			descOut, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: key.KeyId})
			if err != nil || descOut.KeyMetadata == nil {
				continue
			}
			keyArn := aws.ToString(descOut.KeyMetadata.Arn)

			statusOut, err := client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{
				KeyId: key.KeyId,
			})
			if err != nil {
				continue
			}

			arn := fmt.Sprintf("%s/rotation-status", keyArn)
			if keyArn == "" {
				arn = fmt.Sprintf("arn:aws:kms:%s:%s:key/%s/rotation-status", region, accountID, keyID)
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":               arn,
				"arn":                  arn,
				"account_id":           accountID,
				"region":               region,
				"key_id":               keyID,
				"key_arn":              keyArn,
				"key_rotation_enabled": statusOut.KeyRotationEnabled,
			})
		}
	}

	return rows, nil
}

func (e *SyncEngine) fetchKMSCustomKeyStores(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := kms.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	paginator := kms.NewDescribeCustomKeyStoresPaginator(client, &kms.DescribeCustomKeyStoresInput{})
	var rows []map[string]interface{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, store := range page.CustomKeyStores {
			storeID := aws.ToString(store.CustomKeyStoreId)
			arn := fmt.Sprintf("arn:aws:kms:%s:%s:custom-key-store/%s", region, accountID, storeID)
			rows = append(rows, map[string]interface{}{
				"_cq_id":                   arn,
				"arn":                      arn,
				"account_id":               accountID,
				"region":                   region,
				"custom_key_store_id":      storeID,
				"custom_key_store_name":    aws.ToString(store.CustomKeyStoreName),
				"custom_key_store_type":    string(store.CustomKeyStoreType),
				"connection_state":         string(store.ConnectionState),
				"connection_error_code":    string(store.ConnectionErrorCode),
				"creation_date":            store.CreationDate,
				"cloud_hsm_cluster_id":     aws.ToString(store.CloudHsmClusterId),
				"trust_anchor_certificate": aws.ToString(store.TrustAnchorCertificate),
				"xks_proxy_configuration":  store.XksProxyConfiguration,
			})
		}
	}

	return rows, nil
}
