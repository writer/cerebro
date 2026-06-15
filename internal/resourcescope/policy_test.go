package resourcescope

import "testing"

func TestPolicyConfigValueRoundTripsCanonicalPolicy(t *testing.T) {
	value, err := ConfigValue(Policy{
		ExcludedFamilies:     []string{" S3_Bucket ", "s3_bucket"},
		ExcludedAssetClasses: []string{"aws.EC2_Instance"},
		ExcludedResourceURNs: []string{"urn:cerebro:tenant:aws_s3_bucket:bucket-a"},
		ExcludedResources: []ResourceSelector{{
			Type:   "AWS.S3_BUCKET",
			ID:     "bucket-a",
			Reason: "not monitored",
		}},
	})
	if err != nil {
		t.Fatalf("ConfigValue() error = %v", err)
	}
	policy, err := FromConfig(map[string]string{ConfigKey: value})
	if err != nil {
		t.Fatalf("FromConfig() error = %v", err)
	}
	if policy.Empty() {
		t.Fatal("policy unexpectedly empty")
	}
	if !policy.ExcludesFamily("aws", "s3_bucket") {
		t.Fatal("policy did not exclude aws s3_bucket family")
	}
	if !policy.ExcludesFamily("aws", "ec2_instance") {
		t.Fatal("policy did not exclude aws ec2_instance asset class")
	}
	if !policy.ExcludesEvent("aws.s3_bucket", "event-1", map[string]string{"asset_urn": "urn:cerebro:tenant:aws_s3_bucket:bucket-a"}) {
		t.Fatal("policy did not exclude exact resource urn")
	}
	if !policy.ExcludesEvent("aws.s3_bucket", "event-1", map[string]string{"resource_type": "aws.s3_bucket", "resource_id": "bucket-a"}) {
		t.Fatal("policy did not exclude typed resource id")
	}
}

func TestPolicyRejectsMalformedResourceSelectors(t *testing.T) {
	_, err := Normalize(Policy{ExcludedResources: []ResourceSelector{{Type: "aws.s3_bucket"}}})
	if err == nil {
		t.Fatal("Normalize() succeeded for selector without urn or type/id")
	}
}

func TestEmptyPolicyDoesNotStoreConfigValue(t *testing.T) {
	value, err := ConfigValue(Policy{ExcludedFamilies: []string{" "}})
	if err != nil {
		t.Fatalf("ConfigValue() error = %v", err)
	}
	if value != "" {
		t.Fatalf("ConfigValue() = %q, want empty", value)
	}
}
