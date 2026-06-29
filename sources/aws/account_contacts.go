package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	accountsvc "github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"

	"github.com/writer/cerebro/internal/primitives"
)

type awsAccountContact struct {
	AccountID                        string
	PrimaryContactConfigured         bool
	SecurityAlternateContactPresent  bool
	SecurityAlternateContactComplete bool
	SecurityContactEmailPresent      bool
	SecurityContactNamePresent       bool
	SecurityContactPhonePresent      bool
	AccountSecurityContactConfigured bool
	AccountAlternateContactCompliant bool
}

func listAccountContacts(ctx context.Context, clients awsClients, settings settings, _ string, _ int) ([]awsAccountContact, string, error) {
	if clients.account == nil {
		return nil, "", fmt.Errorf("aws account client is not configured")
	}
	record := awsAccountContact{AccountID: settings.accountID}
	primary, err := clients.account.GetContactInformation(ctx, &accountsvc.GetContactInformationInput{})
	if err != nil {
		if !optionalAWSError(err, "ResourceNotFoundException") {
			return nil, "", fmt.Errorf("get account contact information: %w", err)
		}
	} else if primary != nil {
		record.PrimaryContactConfigured = primaryContactConfigured(primary.ContactInformation)
	}
	security, err := clients.account.GetAlternateContact(ctx, &accountsvc.GetAlternateContactInput{AlternateContactType: accounttypes.AlternateContactTypeSecurity})
	if err != nil {
		if !optionalAWSError(err, "ResourceNotFoundException") {
			return nil, "", fmt.Errorf("get account security alternate contact: %w", err)
		}
	} else if security != nil {
		record.SecurityAlternateContactPresent = security.AlternateContact != nil
		record.SecurityContactEmailPresent = nonEmptyString(securityContactEmail(security.AlternateContact))
		record.SecurityContactNamePresent = nonEmptyString(securityContactName(security.AlternateContact))
		record.SecurityContactPhonePresent = nonEmptyString(securityContactPhone(security.AlternateContact))
		record.SecurityAlternateContactComplete = record.SecurityContactEmailPresent && record.SecurityContactNamePresent && record.SecurityContactPhonePresent
	}
	record.AccountSecurityContactConfigured = record.SecurityAlternateContactComplete
	record.AccountAlternateContactCompliant = record.SecurityAlternateContactComplete
	return []awsAccountContact{record}, "", nil
}

func accountContactEvent(settings settings, record awsAccountContact) (*primitives.Event, error) {
	accountID := firstNonEmpty(record.AccountID, settings.accountID)
	attributes := map[string]string{
		"account_alternate_contact_security_compliant": boolString(record.AccountAlternateContactCompliant),
		"account_id":                          accountID,
		"account_security_contact_configured": boolString(record.AccountSecurityContactConfigured),
		"domain":                              accountID,
		"family":                              familyAccountContact,
		"primary_contact_configured":          boolString(record.PrimaryContactConfigured),
		"resource_id":                         accountID,
		"resource_name":                       accountID,
		"resource_provider":                   "aws",
		"resource_type":                       "aws_account",
		"security_alternate_contact_complete": boolString(record.SecurityAlternateContactComplete),
		"security_alternate_contact_present":  boolString(record.SecurityAlternateContactPresent),
		"security_contact_email_present":      boolString(record.SecurityContactEmailPresent),
		"security_contact_name_present":       boolString(record.SecurityContactNamePresent),
		"security_contact_phone_present":      boolString(record.SecurityContactPhonePresent),
	}
	payload, err := json.Marshal(map[string]any{
		"account_id": accountID,
		"primary_contact": map[string]bool{
			"configured": record.PrimaryContactConfigured,
		},
		"security_contact": map[string]any{
			"alternate_contact_type": string(accounttypes.AlternateContactTypeSecurity),
			"complete":               record.SecurityAlternateContactComplete,
			"email_present":          record.SecurityContactEmailPresent,
			"name_present":           record.SecurityContactNamePresent,
			"phone_present":          record.SecurityContactPhonePresent,
			"present":                record.SecurityAlternateContactPresent,
		},
	})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "aws-account-contact-"+accountID, "aws.account_contact", "aws/account_contact/v1", payload, attributes, time.Now().UTC())
}

func primaryContactConfigured(contact *accounttypes.ContactInformation) bool {
	if contact == nil {
		return false
	}
	return nonEmptyString(contact.FullName) && nonEmptyString(contact.PhoneNumber) && nonEmptyString(contact.CountryCode)
}

func securityContactEmail(contact *accounttypes.AlternateContact) *string {
	if contact == nil {
		return nil
	}
	return contact.EmailAddress
}

func securityContactName(contact *accounttypes.AlternateContact) *string {
	if contact == nil {
		return nil
	}
	return contact.Name
}

func securityContactPhone(contact *accounttypes.AlternateContact) *string {
	if contact == nil {
		return nil
	}
	return contact.PhoneNumber
}

func nonEmptyString(value *string) bool {
	return value != nil && strings.TrimSpace(*value) != ""
}
