package awsaccount

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/smithy-go"
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

const FamilyAccountContact = "account_contact"

type AccountClient interface {
	GetAlternateContact(context.Context, *account.GetAlternateContactInput, ...func(*account.Options)) (*account.GetAlternateContactOutput, error)
	GetContactInformation(context.Context, *account.GetContactInformationInput, ...func(*account.Options)) (*account.GetContactInformationOutput, error)
}

type AccountContact struct {
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

func accountContactFamily[S any, C any](clientFactory func(context.Context, S) (C, error), accountFromClients func(C) any, accountID func(S) string) sourcecdk.Family[S] {
	const label = "aws account contacts"
	return sourcecdk.Family[S]{
		Name: FamilyAccountContact,
		Check: func(ctx context.Context, settings S) error {
			client, err := resolveAccountClient(ctx, settings, clientFactory, accountFromClients)
			if err != nil {
				return err
			}
			_, err = listAccountContacts(ctx, client, accountID(settings))
			return err
		},
		Discover: func(ctx context.Context, settings S) ([]sourcecdk.URN, error) {
			client, err := resolveAccountClient(ctx, settings, clientFactory, accountFromClients)
			if err != nil {
				return nil, err
			}
			records, err := listAccountContacts(ctx, client, accountID(settings))
			if err != nil {
				return nil, fmt.Errorf("lookup %s for %s: %w", label, accountID(settings), err)
			}
			urns := make([]sourcecdk.URN, 0, len(records))
			for _, record := range records {
				parsed, err := sourcecdk.ParseURN(accountContactURN(accountID(settings), record))
				if err != nil {
					return nil, err
				}
				urns = append(urns, parsed)
			}
			return urns, nil
		},
		Read: func(ctx context.Context, settings S, _ *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			client, err := resolveAccountClient(ctx, settings, clientFactory, accountFromClients)
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			records, err := listAccountContacts(ctx, client, accountID(settings))
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("lookup %s for %s: %w", label, accountID(settings), err)
			}
			build := func(record AccountContact) (*primitives.Event, error) {
				spec, err := accountContactEvent(accountID(settings), record)
				if err != nil {
					return nil, err
				}
				return event(accountID(settings), spec), nil
			}
			return sourcecdk.PullFromRecords(records, "", build, AccountContactCursor)
		},
	}
}

func resolveAccountClient[S any, C any](ctx context.Context, settings S, clientFactory func(context.Context, S) (C, error), accountFromClients func(C) any) (AccountClient, error) {
	clients, err := clientFactory(ctx, settings)
	if err != nil {
		return nil, err
	}
	client, ok := accountFromClients(clients).(AccountClient)
	if !ok {
		return nil, fmt.Errorf("aws account client does not support contact posture APIs")
	}
	return client, nil
}

func listAccountContacts(ctx context.Context, client AccountClient, accountID string) ([]AccountContact, error) {
	record := AccountContact{AccountID: accountID}
	primary, err := client.GetContactInformation(ctx, &account.GetContactInformationInput{})
	if err != nil {
		if !optionalAccountError(err, "ResourceNotFoundException") {
			return nil, fmt.Errorf("get account contact information: %w", err)
		}
	} else if primary != nil {
		record.PrimaryContactConfigured = primaryContactConfigured(primary.ContactInformation)
	}
	security, err := client.GetAlternateContact(ctx, &account.GetAlternateContactInput{AlternateContactType: accounttypes.AlternateContactTypeSecurity})
	if err != nil {
		if !optionalAccountError(err, "ResourceNotFoundException") {
			return nil, fmt.Errorf("get account security alternate contact: %w", err)
		}
	} else if security != nil {
		record.SecurityAlternateContactPresent = security.AlternateContact != nil
		record.SecurityContactEmailPresent = populated(securityContactEmail(security.AlternateContact))
		record.SecurityContactNamePresent = populated(securityContactName(security.AlternateContact))
		record.SecurityContactPhonePresent = populated(securityContactPhone(security.AlternateContact))
		record.SecurityAlternateContactComplete = record.SecurityContactEmailPresent && record.SecurityContactNamePresent && record.SecurityContactPhonePresent
	}
	record.AccountSecurityContactConfigured = record.SecurityAlternateContactComplete
	record.AccountAlternateContactCompliant = record.SecurityAlternateContactComplete
	return []AccountContact{record}, nil
}

func accountContactEvent(accountID string, record AccountContact) (eventSpec, error) {
	accountID = firstNonEmpty(record.AccountID, accountID)
	attributes := map[string]string{
		"account_alternate_contact_security_compliant": boolString(record.AccountAlternateContactCompliant),
		"account_id":                          accountID,
		"account_security_contact_configured": boolString(record.AccountSecurityContactConfigured),
		"domain":                              accountID,
		"family":                              FamilyAccountContact,
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
		return eventSpec{}, err
	}
	return eventSpec{ID: "aws-account-contact-" + accountID, Kind: "aws.account_contact", SchemaRef: "aws/account_contact/v1", Payload: payload, Attributes: attributes, OccurredAt: time.Now().UTC()}, nil
}

func accountContactURN(accountID string, record AccountContact) string {
	return fmt.Sprintf("urn:cerebro:%s:aws_account_contact:%s", accountID, firstNonEmpty(record.AccountID, accountID))
}

func AccountContactCursor(record AccountContact) string {
	return firstNonEmpty(record.AccountID, "account")
}

func primaryContactConfigured(contact *accounttypes.ContactInformation) bool {
	if contact == nil {
		return false
	}
	return populated(contact.FullName) && populated(contact.PhoneNumber) && populated(contact.CountryCode)
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

func populated(value *string) bool {
	return value != nil && strings.TrimSpace(*value) != ""
}

func optionalAccountError(err error, codes ...string) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	for _, code := range codes {
		if apiErr.ErrorCode() == code {
			return true
		}
	}
	return false
}
