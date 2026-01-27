package sync

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
)

// ACM Certificate table
func (e *SyncEngine) acmCertificateTable() TableSpec {
	return TableSpec{
		Name: "aws_acm_certificates",
		Columns: []string{
			"_cq_hash", "arn", "domain_name", "account_id", "region",
			"subject_alternative_names", "status", "type", "issuer",
			"created_at", "issued_at", "not_before", "not_after",
			"key_algorithm", "signature_algorithm", "in_use_by",
			"failure_reason", "revocation_reason", "revoked_at",
			"renewal_eligibility", "renewal_summary", "certificate_transparency_logging",
			"extended_key_usage", "key_usage", "options", "tags",
		},
		Fetch: func(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
			client := acm.NewFromConfig(cfg, func(o *acm.Options) {
				o.Region = region
			})
			accountID := e.getAccountIDFromConfig(ctx, cfg)
			var results []map[string]interface{}

			paginator := acm.NewListCertificatesPaginator(client, &acm.ListCertificatesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					return nil, err
				}

				for _, cert := range page.CertificateSummaryList {
					// Get full certificate details
					detail, err := client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
						CertificateArn: cert.CertificateArn,
					})
					if err != nil {
						continue
					}
					c := detail.Certificate

					// Get tags
					tagsOut, _ := client.ListTagsForCertificate(ctx, &acm.ListTagsForCertificateInput{
						CertificateArn: cert.CertificateArn,
					})
					tags := map[string]string{}
					if tagsOut != nil {
						for _, t := range tagsOut.Tags {
							if t.Key != nil && t.Value != nil {
								tags[*t.Key] = *t.Value
							}
						}
					}
					tagsJSON, _ := json.Marshal(tags)

					sanJSON, _ := json.Marshal(c.SubjectAlternativeNames)
					inUseByJSON, _ := json.Marshal(c.InUseBy)
					extKeyUsageJSON, _ := json.Marshal(c.ExtendedKeyUsages)
					keyUsageJSON, _ := json.Marshal(c.KeyUsages)
					optionsJSON, _ := json.Marshal(c.Options)
					renewalJSON, _ := json.Marshal(c.RenewalSummary)

					row := map[string]interface{}{
						"arn":                              aws.ToString(c.CertificateArn),
						"domain_name":                      aws.ToString(c.DomainName),
						"account_id":                       accountID,
						"region":                           region,
						"subject_alternative_names":        string(sanJSON),
						"status":                           string(c.Status),
						"type":                             string(c.Type),
						"issuer":                           aws.ToString(c.Issuer),
						"created_at":                       timeToString(c.CreatedAt),
						"issued_at":                        timeToString(c.IssuedAt),
						"not_before":                       timeToString(c.NotBefore),
						"not_after":                        timeToString(c.NotAfter),
						"key_algorithm":                    string(c.KeyAlgorithm),
						"signature_algorithm":              aws.ToString(c.SignatureAlgorithm),
						"in_use_by":                        string(inUseByJSON),
						"failure_reason":                   string(c.FailureReason),
						"revocation_reason":                string(c.RevocationReason),
						"revoked_at":                       timeToString(c.RevokedAt),
						"renewal_eligibility":              string(c.RenewalEligibility),
						"renewal_summary":                  string(renewalJSON),
						"certificate_transparency_logging": "",
						"extended_key_usage":               string(extKeyUsageJSON),
						"key_usage":                        string(keyUsageJSON),
						"options":                          string(optionsJSON),
						"tags":                             string(tagsJSON),
					}
					if c.Options != nil {
						row["certificate_transparency_logging"] = string(c.Options.CertificateTransparencyLoggingPreference)
					}
					results = append(results, row)
				}
			}
			return results, nil
		},
	}
}
