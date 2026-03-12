package sync

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/writer/cerebro/internal/warehouse"
)

type mockIAMPolicyDocumentClient struct {
	getPolicyOut        *iam.GetPolicyOutput
	getPolicyErr        error
	getPolicyVersionOut *iam.GetPolicyVersionOutput
	getPolicyVersionErr error
}

func (m *mockIAMPolicyDocumentClient) GetPolicy(_ context.Context, _ *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	return m.getPolicyOut, m.getPolicyErr
}

func (m *mockIAMPolicyDocumentClient) GetPolicyVersion(_ context.Context, _ *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return m.getPolicyVersionOut, m.getPolicyVersionErr
}

type mockIAMLastAccessClient struct {
	generateOut *iam.GenerateServiceLastAccessedDetailsOutput
	generateErr error
	pages       []*iam.GetServiceLastAccessedDetailsOutput
	getIndex    int
	markers     []string
}

func (m *mockIAMLastAccessClient) GenerateServiceLastAccessedDetails(_ context.Context, _ *iam.GenerateServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	return m.generateOut, m.generateErr
}

func (m *mockIAMLastAccessClient) GetServiceLastAccessedDetails(_ context.Context, input *iam.GetServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	if input != nil && input.Marker != nil {
		m.markers = append(m.markers, aws.ToString(input.Marker))
	} else {
		m.markers = append(m.markers, "")
	}
	if m.getIndex >= len(m.pages) {
		return nil, fmt.Errorf("unexpected GetServiceLastAccessedDetails call %d", m.getIndex+1)
	}
	page := m.pages[m.getIndex]
	m.getIndex++
	return page, nil
}

func TestFetchIAMPolicyDocumentDecodesURLDocument(t *testing.T) {
	encoded := url.QueryEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	mockClient := &mockIAMPolicyDocumentClient{
		getPolicyOut:        &iam.GetPolicyOutput{Policy: &iamtypes.Policy{DefaultVersionId: aws.String("v1")}},
		getPolicyVersionOut: &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: aws.String(encoded)}},
	}

	doc, err := fetchIAMPolicyDocument(context.Background(), mockClient, "arn:aws:iam::123456789012:policy/Test")
	if err != nil {
		t.Fatalf("fetchIAMPolicyDocument returned error: %v", err)
	}
	if !strings.Contains(doc, `"Action":"s3:GetObject"`) {
		t.Fatalf("expected decoded policy document, got %q", doc)
	}
}

func TestFetchRoleActionLastAccessIncludesPaginatedActions(t *testing.T) {
	firstSeen := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	secondSeen := firstSeen.Add(2 * time.Hour)

	mockClient := &mockIAMLastAccessClient{
		generateOut: &iam.GenerateServiceLastAccessedDetailsOutput{JobId: aws.String("job-1")},
		pages: []*iam.GetServiceLastAccessedDetailsOutput{
			{
				JobStatus:   iamtypes.JobStatusTypeCompleted,
				IsTruncated: true,
				Marker:      aws.String("next-page"),
				ServicesLastAccessed: []iamtypes.ServiceLastAccessed{
					{
						ServiceNamespace: aws.String("s3"),
						TrackedActionsLastAccessed: []iamtypes.TrackedActionLastAccessed{
							{
								ActionName:       aws.String("GetObject"),
								LastAccessedTime: aws.Time(firstSeen),
							},
						},
					},
				},
			},
			{
				JobStatus:   iamtypes.JobStatusTypeCompleted,
				IsTruncated: false,
				ServicesLastAccessed: []iamtypes.ServiceLastAccessed{
					{
						ServiceNamespace: aws.String("ec2"),
						TrackedActionsLastAccessed: []iamtypes.TrackedActionLastAccessed{
							{
								ActionName:       aws.String("DescribeInstances"),
								LastAccessedTime: aws.Time(secondSeen),
							},
						},
					},
				},
			},
		},
	}

	tracked, err := fetchRoleActionLastAccess(context.Background(), mockClient, "arn:aws:iam::123456789012:role/Test")
	if err != nil {
		t.Fatalf("fetchRoleActionLastAccess returned error: %v", err)
	}

	if usage, ok := tracked["s3:getobject"]; !ok || !usage.LastAccessedTime.Equal(firstSeen) {
		t.Fatalf("expected first-page action to be tracked, got %#v", tracked["s3:getobject"])
	}
	if usage, ok := tracked["ec2:describeinstances"]; !ok || !usage.LastAccessedTime.Equal(secondSeen) {
		t.Fatalf("expected second-page action to be tracked, got %#v", tracked["ec2:describeinstances"])
	}

	if len(mockClient.markers) != 2 {
		t.Fatalf("expected 2 GetServiceLastAccessedDetails calls, got %d", len(mockClient.markers))
	}
	if mockClient.markers[0] != "" || mockClient.markers[1] != "next-page" {
		t.Fatalf("unexpected pagination markers: %#v", mockClient.markers)
	}
}

func TestDeleteIdentityCenterUsageRowsNotInInstanceScopesQuery(t *testing.T) {
	store := &warehouse.MemoryWarehouse{}
	e := &SyncEngine{sf: store, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	e.deleteIdentityCenterUsageRowsNotInInstance(
		context.Background(),
		"arn:aws:sso:::instance/ssoins-123",
		"123456789012",
		[]string{"arn:aws:sso:::permissionSet/ssoins-123/ps-1", "arn:aws:sso:::permissionSet/ssoins-123/ps-2"},
	)

	if len(store.Execs) == 0 {
		t.Fatal("expected cleanup query to execute")
	}
	call := store.Execs[len(store.Execs)-1]
	if !strings.Contains(strings.ToLower(call.Statement), "identity_center_instance_arn = ?") {
		t.Fatalf("expected instance scope in cleanup query, got %q", call.Statement)
	}
	if !strings.Contains(strings.ToLower(call.Statement), "permission_set_arn not in") {
		t.Fatalf("expected NOT IN cleanup query, got %q", call.Statement)
	}
	if len(call.Args) != 4 {
		t.Fatalf("expected 4 query args, got %#v", call.Args)
	}
}

func TestIdentityCenterProbeRegionsPrioritizesAndDeduplicates(t *testing.T) {
	regions := identityCenterProbeRegions(
		"us-west-2",
		"eu-west-1",
		[]string{"us-west-2", "ap-southeast-2"},
		[]string{"us-east-1", "ap-southeast-2", "eu-west-1"},
	)

	want := []string{"us-west-2", "eu-west-1", "ap-southeast-2", "us-east-1"}
	if len(regions) != len(want) {
		t.Fatalf("unexpected region count: got %#v want %#v", regions, want)
	}
	for i := range want {
		if regions[i] != want[i] {
			t.Fatalf("unexpected region order: got %#v want %#v", regions, want)
		}
	}
}
