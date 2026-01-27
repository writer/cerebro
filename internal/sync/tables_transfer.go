package sync

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
)

// Transfer Family Servers table
func (e *SyncEngine) transferServerTable() TableSpec {
	return TableSpec{
		Name: "aws_transfer_servers",
		Columns: []string{
			"_cq_hash", "arn", "server_id", "account_id", "region",
			"domain", "endpoint_type", "identity_provider_type", "logging_role",
			"state", "user_count", "certificate", "endpoint_details",
			"host_key_fingerprint", "identity_provider_details",
			"post_authentication_login_banner", "pre_authentication_login_banner",
			"protocol_details", "protocols", "s3_storage_options",
			"security_policy_name", "structured_log_destinations",
			"workflow_details", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := transfer.NewFromConfig(cfg, func(o *transfer.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := transfer.NewListServersPaginator(client, &transfer.ListServersInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, server := range page.Servers {
					// Get full details
					detail, err := client.DescribeServer(ctx, &transfer.DescribeServerInput{
						ServerId: server.ServerId,
					})
					if err != nil {
						continue
					}
					s := detail.Server

					endpointJSON, _ := json.Marshal(s.EndpointDetails)
					idpDetailsJSON, _ := json.Marshal(s.IdentityProviderDetails)
					protocolDetailsJSON, _ := json.Marshal(s.ProtocolDetails)
					protocolsJSON, _ := json.Marshal(s.Protocols)
					s3OptionsJSON, _ := json.Marshal(s.S3StorageOptions)
					logDestsJSON, _ := json.Marshal(s.StructuredLogDestinations)
					workflowJSON, _ := json.Marshal(s.WorkflowDetails)

					tags := map[string]string{}
					for _, t := range s.Tags {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}
					tagsJSON, _ := json.Marshal(tags)

					row := map[string]interface{}{
						"arn":                              aws.ToString(s.Arn),
						"server_id":                        aws.ToString(s.ServerId),
						"account_id":                       accountID,
						"region":                           region,
						"domain":                           string(s.Domain),
						"endpoint_type":                    string(s.EndpointType),
						"identity_provider_type":           string(s.IdentityProviderType),
						"logging_role":                     aws.ToString(s.LoggingRole),
						"state":                            string(s.State),
						"user_count":                       s.UserCount,
						"certificate":                      aws.ToString(s.Certificate),
						"endpoint_details":                 string(endpointJSON),
						"host_key_fingerprint":             aws.ToString(s.HostKeyFingerprint),
						"identity_provider_details":        string(idpDetailsJSON),
						"post_authentication_login_banner": aws.ToString(s.PostAuthenticationLoginBanner),
						"pre_authentication_login_banner":  aws.ToString(s.PreAuthenticationLoginBanner),
						"protocol_details":                 string(protocolDetailsJSON),
						"protocols":                        string(protocolsJSON),
						"s3_storage_options":               string(s3OptionsJSON),
						"security_policy_name":             aws.ToString(s.SecurityPolicyName),
						"structured_log_destinations":      string(logDestsJSON),
						"workflow_details":                 string(workflowJSON),
						"tags":                             string(tagsJSON),
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}

// Transfer Family Users table
func (e *SyncEngine) transferUserTable() TableSpec {
	return TableSpec{
		Name: "aws_transfer_users",
		Columns: []string{
			"_cq_hash", "arn", "user_name", "server_id", "account_id", "region",
			"home_directory", "home_directory_mappings", "home_directory_type",
			"policy", "posix_profile", "role", "ssh_public_keys", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := transfer.NewFromConfig(cfg, func(o *transfer.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			// First get all servers
			serverPaginator := transfer.NewListServersPaginator(client, &transfer.ListServersInput{})
			for serverPaginator.HasMorePages() {
				serverPage, err := serverPaginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, server := range serverPage.Servers {
					serverID := aws.ToString(server.ServerId)

					// Get users for this server
					userPaginator := transfer.NewListUsersPaginator(client, &transfer.ListUsersInput{
						ServerId: aws.String(serverID),
					})
					for userPaginator.HasMorePages() {
						userPage, err := userPaginator.NextPage(ctx)
						if err != nil {
							break
						}

						for _, user := range userPage.Users {
							// Get full user details
							detail, err := client.DescribeUser(ctx, &transfer.DescribeUserInput{
								ServerId: aws.String(serverID),
								UserName: user.UserName,
							})
							if err != nil {
								continue
							}
							u := detail.User

							mappingsJSON, _ := json.Marshal(u.HomeDirectoryMappings)
							posixJSON, _ := json.Marshal(u.PosixProfile)
							keysJSON, _ := json.Marshal(u.SshPublicKeys)

							tags := map[string]string{}
							for _, t := range u.Tags {
								if t.Key != nil && t.Value != nil {
									tags[*t.Key] = *t.Value
								}
							}
							tagsJSON, _ := json.Marshal(tags)

							row := map[string]interface{}{
								"arn":                     aws.ToString(u.Arn),
								"user_name":               aws.ToString(u.UserName),
								"server_id":               serverID,
								"account_id":              accountID,
								"region":                  region,
								"home_directory":          aws.ToString(u.HomeDirectory),
								"home_directory_mappings": string(mappingsJSON),
								"home_directory_type":     string(u.HomeDirectoryType),
								"policy":                  aws.ToString(u.Policy),
								"posix_profile":           string(posixJSON),
								"role":                    aws.ToString(u.Role),
								"ssh_public_keys":         string(keysJSON),
								"tags":                    string(tagsJSON),
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
