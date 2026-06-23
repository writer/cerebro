package awsaccount

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	familyAccountPasswordPolicy = "iam_account_password_policy"
	familyAccountSummary        = "iam_account_summary"
	familyCredentialReport      = "iam_credential_report" // #nosec G101 -- source family identifier, not credential material.

	credentialReportGenerateAttempts = 5
	credentialReportGenerateDelay    = 100 * time.Millisecond
)

type iamClient interface {
	GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
	GetAccountPasswordPolicy(context.Context, *iam.GetAccountPasswordPolicyInput, ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error)
	GenerateCredentialReport(context.Context, *iam.GenerateCredentialReportInput, ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error)
	GetCredentialReport(context.Context, *iam.GetCredentialReportInput, ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error)
}

type AccountSummary struct {
	SummaryMap map[string]int32
}

type AccountPasswordPolicy struct {
	Present bool
	Policy  *iamtypes.PasswordPolicy
}

type CredentialReportRow struct {
	GeneratedTime *time.Time
	ReportFormat  string
	Values        map[string]string
}

func Families[S any, C any](clientFactory func(context.Context, S) (C, error), iamFromClients func(C) any, accountID func(S) string) []sourcecdk.Family[S] {
	return []sourcecdk.Family[S]{
		family(clientFactory, iamFromClients, accountID, familyAccountSummary, "aws iam account summary", listAccountSummary, accountSummaryEvent, accountSummaryURN),
		family(clientFactory, iamFromClients, accountID, familyAccountPasswordPolicy, "aws iam account password policy", listAccountPasswordPolicy, accountPasswordPolicyEvent, accountPasswordPolicyURN),
		family(clientFactory, iamFromClients, accountID, familyCredentialReport, "aws iam credential report", listCredentialReport, credentialReportEvent, credentialReportURN),
	}
}

func family[S any, C any, T any](clientFactory func(context.Context, S) (C, error), iamFromClients func(C) any, accountID func(S) string, name string, label string, list func(context.Context, iamClient) ([]T, error), build func(string, T) (eventSpec, error), urn func(string, T) string) sourcecdk.Family[S] {
	return sourcecdk.Family[S]{
		Name: name,
		Check: func(ctx context.Context, settings S) error {
			client, err := resolveIAMClient(ctx, settings, clientFactory, iamFromClients)
			if err != nil {
				return err
			}
			_, err = list(ctx, client)
			return err
		},
		Discover: func(ctx context.Context, settings S) ([]sourcecdk.URN, error) {
			client, err := resolveIAMClient(ctx, settings, clientFactory, iamFromClients)
			if err != nil {
				return nil, err
			}
			records, err := list(ctx, client)
			if err != nil {
				return nil, fmt.Errorf("lookup %s for %s: %w", label, accountID(settings), err)
			}
			urns := make([]sourcecdk.URN, 0, len(records))
			for _, record := range records {
				parsed, err := sourcecdk.ParseURN(urn(accountID(settings), record))
				if err != nil {
					return nil, err
				}
				urns = append(urns, parsed)
			}
			return urns, nil
		},
		Read: func(ctx context.Context, settings S, _ *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			client, err := resolveIAMClient(ctx, settings, clientFactory, iamFromClients)
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			records, err := list(ctx, client)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("lookup %s for %s: %w", label, accountID(settings), err)
			}
			events := make([]*primitives.Event, 0, len(records))
			for _, record := range records {
				spec, err := build(accountID(settings), record)
				if err != nil {
					return sourcecdk.Pull{}, err
				}
				events = append(events, event(accountID(settings), spec))
			}
			return sourcecdk.Pull{Events: events}, nil
		},
	}
}

func resolveIAMClient[S any, C any](ctx context.Context, settings S, clientFactory func(context.Context, S) (C, error), iamFromClients func(C) any) (iamClient, error) {
	clients, err := clientFactory(ctx, settings)
	if err != nil {
		return nil, err
	}
	client, ok := iamFromClients(clients).(iamClient)
	if !ok {
		return nil, fmt.Errorf("aws iam client does not support account posture APIs")
	}
	return client, nil
}

func listAccountSummary(ctx context.Context, client iamClient) ([]AccountSummary, error) {
	out, err := client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, err
	}
	return []AccountSummary{{SummaryMap: out.SummaryMap}}, nil
}

func listAccountPasswordPolicy(ctx context.Context, client iamClient) ([]AccountPasswordPolicy, error) {
	out, err := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		var missing *iamtypes.NoSuchEntityException
		if errors.As(err, &missing) {
			return []AccountPasswordPolicy{{Present: false}}, nil
		}
		return nil, err
	}
	return []AccountPasswordPolicy{{Present: out.PasswordPolicy != nil, Policy: out.PasswordPolicy}}, nil
}
