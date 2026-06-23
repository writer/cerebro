package awsaccount

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func listCredentialReport(ctx context.Context, client iamClient) ([]CredentialReportRow, error) {
	out, ready, err := getCredentialReport(ctx, client)
	if err != nil {
		return nil, err
	}
	if !ready {
		return nil, nil
	}
	rows, err := parseCredentialReport(out.Content)
	if err != nil {
		return nil, err
	}
	records := make([]CredentialReportRow, 0, len(rows))
	for _, row := range rows {
		records = append(records, CredentialReportRow{GeneratedTime: out.GeneratedTime, ReportFormat: string(out.ReportFormat), Values: row})
	}
	return records, nil
}

func getCredentialReport(ctx context.Context, client iamClient) (*iam.GetCredentialReportOutput, bool, error) {
	for attempt := 0; attempt < credentialReportGenerateAttempts; attempt++ {
		generated, err := client.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
		if err != nil {
			return nil, false, err
		}
		if generated == nil || credentialReportReady(generated.State) {
			out, err := client.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
			if err == nil {
				return out, true, nil
			}
			if !credentialReportPending(err) {
				return nil, false, err
			}
		}
		if attempt == credentialReportGenerateAttempts-1 {
			break
		}
		if err := waitForCredentialReport(ctx); err != nil {
			return nil, false, err
		}
	}
	return nil, false, nil
}

func credentialReportReady(state iamtypes.ReportStateType) bool {
	return state == "" || state == iamtypes.ReportStateTypeComplete
}

func credentialReportPending(err error) bool {
	var expired *iamtypes.CredentialReportExpiredException
	if errors.As(err, &expired) {
		return true
	}
	var missing *iamtypes.CredentialReportNotPresentException
	if errors.As(err, &missing) {
		return true
	}
	var notReady *iamtypes.CredentialReportNotReadyException
	return errors.As(err, &notReady)
}

func waitForCredentialReport(ctx context.Context) error {
	timer := time.NewTimer(credentialReportGenerateDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func parseCredentialReport(content []byte) ([]map[string]string, error) {
	rows, err := parseCredentialReportCSV(string(content))
	if err == nil && len(rows) > 0 {
		return rows, nil
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(content)))
	if decodeErr != nil {
		return rows, err
	}
	decodedRows, decodedErr := parseCredentialReportCSV(string(decoded))
	if decodedErr != nil {
		return rows, err
	}
	return decodedRows, nil
}

func parseCredentialReportCSV(content string) ([]map[string]string, error) {
	reader := csv.NewReader(strings.NewReader(content))
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 2 {
		return nil, nil
	}
	headers := records[0]
	rows := make([]map[string]string, 0, len(records)-1)
	for _, record := range records[1:] {
		row := make(map[string]string, len(headers))
		for index, header := range headers {
			if index >= len(record) {
				row[header] = ""
				continue
			}
			row[header] = record[index]
		}
		if firstNonEmpty(row["user"], row["arn"]) != "" {
			rows = append(rows, row)
		}
	}
	return rows, nil
}
