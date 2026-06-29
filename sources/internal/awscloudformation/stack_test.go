package awscloudformation

import (
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	cloudformationtypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

func TestEventTreatsUncheckedDriftAsNotDetected(t *testing.T) {
	event, err := Event(Settings{AccountID: "123456789012", Region: "us-east-1"}, cloudformationtypes.Stack{
		DriftInformation:            &cloudformationtypes.StackDriftInformation{StackDriftStatus: cloudformationtypes.StackDriftStatusNotChecked},
		EnableTerminationProtection: awssdk.Bool(true),
		StackId:                     awssdk.String("arn:aws:cloudformation:us-east-1:123456789012:stack/prod-app/stack-123"),
		StackName:                   awssdk.String("prod-app"),
		StackStatus:                 cloudformationtypes.StackStatusUpdateComplete,
	})
	if err != nil {
		t.Fatalf("Event() error = %v", err)
	}
	if got := event.Attributes["drift_detected"]; got != "false" {
		t.Fatalf("drift_detected = %q, want false", got)
	}
	if got := event.Attributes["cloudformation_stack_drift_detected_compliant"]; got != "true" {
		t.Fatalf("cloudformation_stack_drift_detected_compliant = %q, want true", got)
	}
	if got := event.Attributes["drift_status"]; got != string(cloudformationtypes.StackDriftStatusNotChecked) {
		t.Fatalf("drift_status = %q, want NOT_CHECKED", got)
	}
}
