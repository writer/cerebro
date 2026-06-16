package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsIAMSAMLProvider struct {
	Summary iamtypes.SAMLProviderListEntry
	Detail  *iam.GetSAMLProviderOutput
}

func listIAMSAMLProviders(ctx context.Context, clients awsClients, _ settings, cursor string, _ int) ([]awsIAMSAMLProvider, string, error) {
	if strings.TrimSpace(cursor) != "" {
		return nil, "", nil
	}
	out, err := clients.iam.ListSAMLProviders(ctx, &iam.ListSAMLProvidersInput{})
	if err != nil {
		return nil, "", err
	}
	records := make([]awsIAMSAMLProvider, 0, len(out.SAMLProviderList))
	for _, summary := range out.SAMLProviderList {
		record := awsIAMSAMLProvider{Summary: summary}
		arn := awssdk.ToString(summary.Arn)
		if arn != "" {
			detail, err := clients.iam.GetSAMLProvider(ctx, &iam.GetSAMLProviderInput{SAMLProviderArn: awssdk.String(arn)})
			if err != nil && !optionalAWSError(err, "NoSuchEntity") {
				return nil, "", fmt.Errorf("get iam saml provider %q: %w", arn, err)
			}
			record.Detail = detail
		}
		records = append(records, record)
	}
	return records, "", nil
}

func iamSAMLProviderEvent(settings settings, record awsIAMSAMLProvider) (*primitives.Event, error) {
	providerARN := awssdk.ToString(record.Summary.Arn)
	providerName := iamSAMLProviderName(providerARN)
	tags := iamTagMap(nil)
	createDate := record.Summary.CreateDate
	validUntil := record.Summary.ValidUntil
	assertionEncryptionMode := ""
	metadataDocumentLength := 0
	providerUUID := ""
	if record.Detail != nil {
		tags = iamTagMap(record.Detail.Tags)
		createDate = firstTimePtr(record.Detail.CreateDate, createDate)
		validUntil = firstTimePtr(record.Detail.ValidUntil, validUntil)
		assertionEncryptionMode = string(record.Detail.AssertionEncryptionMode)
		metadataDocumentLength = len(awssdk.ToString(record.Detail.SAMLMetadataDocument))
		providerUUID = awssdk.ToString(record.Detail.SAMLProviderUUID)
	}
	attributes := commonCloudAssetAttributes(settings, "global", familyIAMSAMLProvider, providerARN, providerName, "iam_saml_provider", tags)
	attributes["arn"] = providerARN
	attributes["assertion_encryption_mode"] = assertionEncryptionMode
	attributes["create_date"] = formatTimePtr(createDate)
	attributes["expired"] = boolString(validUntil != nil && validUntil.Before(time.Now().UTC()))
	attributes["metadata_document_length"] = strconv.Itoa(metadataDocumentLength)
	attributes["metadata_document_present"] = boolString(metadataDocumentLength > 0)
	attributes["policy_resource_type"] = "aws::iam::saml_provider"
	attributes["provider_arn"] = providerARN
	attributes["provider_name"] = providerName
	attributes["provider_uuid"] = providerUUID
	attributes["valid_until"] = formatTimePtr(validUntil)
	if validUntil != nil {
		attributes["valid_until_days"] = strconv.Itoa(iamSAMLProviderValidUntilDays(*validUntil, time.Now().UTC()))
	}
	payload, err := json.Marshal(map[string]any{
		"account_id":                settings.accountID,
		"region":                    "global",
		"provider_arn":              providerARN,
		"provider_name":             providerName,
		"provider_uuid":             providerUUID,
		"assertion_encryption_mode": assertionEncryptionMode,
		"metadata_document_length":  metadataDocumentLength,
		"metadata_document_present": metadataDocumentLength > 0,
		"valid_until":               formatTimePtr(validUntil),
		"valid_until_days":          attributes["valid_until_days"],
		"tags":                      tags,
	})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-iam-saml-provider-"+providerARN, "aws.iam_saml_provider", "aws/iam_saml_provider/v1", payload, attributes, firstTime(createDate))
}

func iamSAMLProviderName(arn string) string {
	arn = strings.TrimSpace(arn)
	if arn == "" {
		return ""
	}
	return path.Base(arn)
}

func iamSAMLProviderValidUntilDays(validUntil time.Time, now time.Time) int {
	days := int(validUntil.Sub(now).Hours() / 24)
	if validUntil.Before(now) && days == 0 {
		return -1
	}
	return days
}

func iamTagMap(tags []iamtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, tag := range tags {
		out[awssdk.ToString(tag.Key)] = awssdk.ToString(tag.Value)
	}
	return out
}

func formatTimePtr(value *time.Time) string {
	if value == nil || value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}
