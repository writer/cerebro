package sync

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

// Cognito User Pools table
func (e *SyncEngine) cognitoUserPoolTable() TableSpec {
	return TableSpec{
		Name: "aws_cognito_user_pools",
		Columns: []string{
			"_cq_hash", "arn", "id", "name", "account_id", "region",
			"creation_date", "last_modified_date", "status",
			"admin_create_user_config", "auto_verified_attributes",
			"deletion_protection", "email_configuration", "email_verification_message",
			"email_verification_subject", "estimated_number_of_users",
			"lambda_config", "mfa_configuration", "policies",
			"schema_attributes", "sms_authentication_message",
			"sms_configuration", "sms_verification_message",
			"user_attribute_update_settings", "user_pool_add_ons",
			"username_attributes", "username_configuration",
			"verification_message_template", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := cognitoidentityprovider.NewFromConfig(cfg, func(o *cognitoidentityprovider.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			var nextToken *string
			for {
				out, err := client.ListUserPools(ctx, &cognitoidentityprovider.ListUserPoolsInput{
					MaxResults: aws.Int32(60),
					NextToken:  nextToken,
				})
				if err != nil {
					return nil, err
				}

				for _, pool := range out.UserPools {
					// Get full details
					detail, err := client.DescribeUserPool(ctx, &cognitoidentityprovider.DescribeUserPoolInput{
						UserPoolId: pool.Id,
					})
					if err != nil {
						continue
					}
					up := detail.UserPool

					arn := fmt.Sprintf("arn:aws:cognito-idp:%s:%s:userpool/%s", region, accountID, aws.ToString(up.Id))

					adminConfigJSON, _ := json.Marshal(up.AdminCreateUserConfig)
					autoVerifiedJSON, _ := json.Marshal(up.AutoVerifiedAttributes)
					emailConfigJSON, _ := json.Marshal(up.EmailConfiguration)
					lambdaConfigJSON, _ := json.Marshal(up.LambdaConfig)
					policiesJSON, _ := json.Marshal(up.Policies)
					schemaJSON, _ := json.Marshal(up.SchemaAttributes)
					smsConfigJSON, _ := json.Marshal(up.SmsConfiguration)
					updateSettingsJSON, _ := json.Marshal(up.UserAttributeUpdateSettings)
					addOnsJSON, _ := json.Marshal(up.UserPoolAddOns)
					usernameAttrsJSON, _ := json.Marshal(up.UsernameAttributes)
					usernameConfigJSON, _ := json.Marshal(up.UsernameConfiguration)
					verificationJSON, _ := json.Marshal(up.VerificationMessageTemplate)
					tagsJSON, _ := json.Marshal(up.UserPoolTags)

					row := map[string]interface{}{
						"arn":                            arn,
						"id":                             aws.ToString(up.Id),
						"name":                           aws.ToString(up.Name),
						"account_id":                     accountID,
						"region":                         region,
						"creation_date":                  timeToString(up.CreationDate),
						"last_modified_date":             timeToString(up.LastModifiedDate),
						"status":                         "", // Deprecated field
						"admin_create_user_config":       string(adminConfigJSON),
						"auto_verified_attributes":       string(autoVerifiedJSON),
						"deletion_protection":            string(up.DeletionProtection),
						"email_configuration":            string(emailConfigJSON),
						"email_verification_message":     aws.ToString(up.EmailVerificationMessage),
						"email_verification_subject":     aws.ToString(up.EmailVerificationSubject),
						"estimated_number_of_users":      up.EstimatedNumberOfUsers,
						"lambda_config":                  string(lambdaConfigJSON),
						"mfa_configuration":              string(up.MfaConfiguration),
						"policies":                       string(policiesJSON),
						"schema_attributes":              string(schemaJSON),
						"sms_authentication_message":     aws.ToString(up.SmsAuthenticationMessage),
						"sms_configuration":              string(smsConfigJSON),
						"sms_verification_message":       aws.ToString(up.SmsVerificationMessage),
						"user_attribute_update_settings": string(updateSettingsJSON),
						"user_pool_add_ons":              string(addOnsJSON),
						"username_attributes":            string(usernameAttrsJSON),
						"username_configuration":         string(usernameConfigJSON),
						"verification_message_template":  string(verificationJSON),
						"tags":                           string(tagsJSON),
					}
					results = append(results, row)
				}

				if out.NextToken == nil {
					break
				}
				nextToken = out.NextToken
			}
			return results, nil
		},
	}
}

// Cognito User Pool Clients table
func (e *SyncEngine) cognitoUserPoolClientTable() TableSpec {
	return TableSpec{
		Name: "aws_cognito_user_pool_clients",
		Columns: []string{
			"_cq_hash", "client_id", "user_pool_id", "account_id", "region",
			"client_name", "creation_date", "last_modified_date",
			"allowed_oauth_flows", "allowed_oauth_flows_user_pool_client",
			"allowed_oauth_scopes", "analytics_configuration",
			"auth_session_validity", "callback_urls", "default_redirect_uri",
			"enable_propagate_additional_user_context_data",
			"enable_token_revocation", "explicit_auth_flows",
			"id_token_validity", "logout_urls", "prevent_user_existence_errors",
			"read_attributes", "refresh_token_validity", "supported_identity_providers",
			"token_validity_units", "write_attributes",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := cognitoidentityprovider.NewFromConfig(cfg, func(o *cognitoidentityprovider.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			// First get all user pools
			var poolNextToken *string
			for {
				poolsOut, err := client.ListUserPools(ctx, &cognitoidentityprovider.ListUserPoolsInput{
					MaxResults: aws.Int32(60),
					NextToken:  poolNextToken,
				})
				if err != nil {
					return nil, err
				}

				for _, pool := range poolsOut.UserPools {
					poolID := aws.ToString(pool.Id)

					// Get clients for this pool
					var clientNextToken *string
					for {
						clientsOut, err := client.ListUserPoolClients(ctx, &cognitoidentityprovider.ListUserPoolClientsInput{
							UserPoolId: aws.String(poolID),
							MaxResults: aws.Int32(60),
							NextToken:  clientNextToken,
						})
						if err != nil {
							break
						}

						for _, c := range clientsOut.UserPoolClients {
							// Get full client details
							detail, err := client.DescribeUserPoolClient(ctx, &cognitoidentityprovider.DescribeUserPoolClientInput{
								UserPoolId: aws.String(poolID),
								ClientId:   c.ClientId,
							})
							if err != nil {
								continue
							}
							upc := detail.UserPoolClient

							oauthFlowsJSON, _ := json.Marshal(upc.AllowedOAuthFlows)
							oauthScopesJSON, _ := json.Marshal(upc.AllowedOAuthScopes)
							analyticsJSON, _ := json.Marshal(upc.AnalyticsConfiguration)
							callbacksJSON, _ := json.Marshal(upc.CallbackURLs)
							authFlowsJSON, _ := json.Marshal(upc.ExplicitAuthFlows)
							logoutsJSON, _ := json.Marshal(upc.LogoutURLs)
							readAttrsJSON, _ := json.Marshal(upc.ReadAttributes)
							providersJSON, _ := json.Marshal(upc.SupportedIdentityProviders)
							tokenUnitsJSON, _ := json.Marshal(upc.TokenValidityUnits) // #nosec G117 -- serializing API response metadata, not credentials
							writeAttrsJSON, _ := json.Marshal(upc.WriteAttributes)

							row := map[string]interface{}{
								"client_id":                            aws.ToString(upc.ClientId),
								"user_pool_id":                         poolID,
								"account_id":                           accountID,
								"region":                               region,
								"client_name":                          aws.ToString(upc.ClientName),
								"creation_date":                        timeToString(upc.CreationDate),
								"last_modified_date":                   timeToString(upc.LastModifiedDate),
								"allowed_oauth_flows":                  string(oauthFlowsJSON),
								"allowed_oauth_flows_user_pool_client": upc.AllowedOAuthFlowsUserPoolClient,
								"allowed_oauth_scopes":                 string(oauthScopesJSON),
								"analytics_configuration":              string(analyticsJSON),
								"auth_session_validity":                upc.AuthSessionValidity,
								"callback_urls":                        string(callbacksJSON),
								"default_redirect_uri":                 aws.ToString(upc.DefaultRedirectURI),
								"enable_propagate_additional_user_context_data": upc.EnablePropagateAdditionalUserContextData,
								"enable_token_revocation":                       upc.EnableTokenRevocation,
								"explicit_auth_flows":                           string(authFlowsJSON),
								"id_token_validity":                             upc.IdTokenValidity,
								"logout_urls":                                   string(logoutsJSON),
								"prevent_user_existence_errors":                 string(upc.PreventUserExistenceErrors),
								"read_attributes":                               string(readAttrsJSON),
								"refresh_token_validity":                        upc.RefreshTokenValidity,
								"supported_identity_providers":                  string(providersJSON),
								"token_validity_units":                          string(tokenUnitsJSON),
								"write_attributes":                              string(writeAttrsJSON),
							}
							results = append(results, row)
						}

						if clientsOut.NextToken == nil {
							break
						}
						clientNextToken = clientsOut.NextToken
					}
				}

				if poolsOut.NextToken == nil {
					break
				}
				poolNextToken = poolsOut.NextToken
			}
			return results, nil
		},
	}
}

// Cognito Identity Providers table
func (e *SyncEngine) cognitoIdentityProviderTable() TableSpec {
	return TableSpec{
		Name: "aws_cognito_identity_providers",
		Columns: []string{
			"_cq_hash", "provider_name", "user_pool_id", "account_id", "region",
			"provider_type", "creation_date", "last_modified_date",
			"attribute_mapping", "idp_identifiers", "provider_details",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := cognitoidentityprovider.NewFromConfig(cfg, func(o *cognitoidentityprovider.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			// First get all user pools
			var poolNextToken *string
			for {
				poolsOut, err := client.ListUserPools(ctx, &cognitoidentityprovider.ListUserPoolsInput{
					MaxResults: aws.Int32(60),
					NextToken:  poolNextToken,
				})
				if err != nil {
					return nil, err
				}

				for _, pool := range poolsOut.UserPools {
					poolID := aws.ToString(pool.Id)

					// Get identity providers for this pool
					var providerNextToken *string
					for {
						providersOut, err := client.ListIdentityProviders(ctx, &cognitoidentityprovider.ListIdentityProvidersInput{
							UserPoolId: aws.String(poolID),
							MaxResults: aws.Int32(60),
							NextToken:  providerNextToken,
						})
						if err != nil {
							break
						}

						for _, provider := range providersOut.Providers {
							// Get full details
							detail, err := client.DescribeIdentityProvider(ctx, &cognitoidentityprovider.DescribeIdentityProviderInput{
								UserPoolId:   aws.String(poolID),
								ProviderName: provider.ProviderName,
							})
							if err != nil {
								continue
							}
							idp := detail.IdentityProvider

							attrMappingJSON, _ := json.Marshal(idp.AttributeMapping)
							identifiersJSON, _ := json.Marshal(idp.IdpIdentifiers)
							detailsJSON, _ := json.Marshal(idp.ProviderDetails)

							row := map[string]interface{}{
								"provider_name":      aws.ToString(idp.ProviderName),
								"user_pool_id":       poolID,
								"account_id":         accountID,
								"region":             region,
								"provider_type":      string(idp.ProviderType),
								"creation_date":      timeToString(idp.CreationDate),
								"last_modified_date": timeToString(idp.LastModifiedDate),
								"attribute_mapping":  string(attrMappingJSON),
								"idp_identifiers":    string(identifiersJSON),
								"provider_details":   string(detailsJSON),
							}
							results = append(results, row)
						}

						if providersOut.NextToken == nil {
							break
						}
						providerNextToken = providersOut.NextToken
					}
				}

				if poolsOut.NextToken == nil {
					break
				}
				poolNextToken = poolsOut.NextToken
			}
			return results, nil
		},
	}
}
