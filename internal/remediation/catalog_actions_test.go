package remediation

import "testing"

func TestPublicStorageAccessStillEnabled_ParsesResourceJSON(t *testing.T) {
	execution := &Execution{
		TriggerData: map[string]any{
			"resource_json": `{"public_access":"true"}`,
		},
	}

	public, detail := publicStorageAccessStillEnabled(execution)
	if !public {
		t.Fatalf("public = false, want true (detail=%q)", detail)
	}
}

func TestBucketDefaultEncryptionStillDisabled_MatchesPolicySignalWithoutConfig(t *testing.T) {
	execution := &Execution{
		TriggerData: map[string]any{
			"policy_id": "aws-s3-bucket-encryption-enabled",
			"resource": map[string]any{
				"name": "audit-logs",
			},
		},
	}

	disabled, detail := bucketDefaultEncryptionStillDisabled(execution)
	if !disabled {
		t.Fatalf("disabled = false, want true (detail=%q)", detail)
	}
}

func TestBucketDefaultEncryptionStillDisabled_DetectsExistingConfig(t *testing.T) {
	execution := &Execution{
		TriggerData: map[string]any{
			"policy_id": "aws-s3-bucket-encryption-enabled",
			"resource": map[string]any{
				"sse_algorithm": "AES256",
			},
		},
	}

	disabled, detail := bucketDefaultEncryptionStillDisabled(execution)
	if disabled {
		t.Fatalf("disabled = true, want false (detail=%q)", detail)
	}
}

func TestBucketDefaultEncryptionStillDisabled_DetectsExistingConfigInResourceJSON(t *testing.T) {
	execution := &Execution{
		TriggerData: map[string]any{
			"policy_id": "aws-s3-bucket-encryption-enabled",
			"resource": map[string]any{
				"resource_json": map[string]any{
					"encryption_configuration": map[string]any{
						"rules": []any{
							map[string]any{"sse_algorithm": "AES256"},
						},
					},
				},
			},
		},
	}

	disabled, detail := bucketDefaultEncryptionStillDisabled(execution)
	if disabled {
		t.Fatalf("disabled = true, want false (detail=%q)", detail)
	}
}

func TestPublicSecurityGroupIngressMatchesRuleRows(t *testing.T) {
	execution := &Execution{
		TriggerData: map[string]any{
			"policy_id": "aws-security-group-restrict-rdp",
			"direction": "ingress",
			"protocol":  "tcp",
			"from_port": 3389,
			"to_port":   3389,
			"ip_ranges": []any{
				map[string]any{"CidrIp": "0.0.0.0/0"},
			},
		},
	}

	matches, detail := publicSecurityGroupIngressMatches(execution)
	if len(matches) != 1 {
		t.Fatalf("matches = %#v, want one match (detail=%q)", matches, detail)
	}
	if matches[0]["from_port"] != 3389 {
		t.Fatalf("unexpected match payload: %#v", matches[0])
	}
}

func TestPublicSecurityGroupIngressMatches_SSHDoesNotMatchUDP(t *testing.T) {
	execution := &Execution{
		TriggerData: map[string]any{
			"policy_id": "aws-security-group-restrict-ssh",
			"direction": "ingress",
			"protocol":  "udp",
			"from_port": 22,
			"to_port":   22,
			"ip_ranges": []any{
				map[string]any{"CidrIp": "0.0.0.0/0"},
			},
		},
	}

	matches, detail := publicSecurityGroupIngressMatches(execution)
	if len(matches) != 0 {
		t.Fatalf("matches = %#v, want none (detail=%q)", matches, detail)
	}
}

func TestPublicSecurityGroupIngressMatches_SSHMatchesAllTrafficRule(t *testing.T) {
	execution := &Execution{
		TriggerData: map[string]any{
			"policy_id": "aws-security-group-restrict-ssh",
			"direction": "ingress",
			"protocol":  "-1",
			"from_port": -1,
			"to_port":   -1,
			"ip_ranges": []any{
				map[string]any{"CidrIp": "0.0.0.0/0"},
			},
		},
	}

	matches, detail := publicSecurityGroupIngressMatches(execution)
	if len(matches) != 1 {
		t.Fatalf("matches = %#v, want one match (detail=%q)", matches, detail)
	}
	if matches[0]["port_label"] != "all" {
		t.Fatalf("unexpected match payload: %#v", matches[0])
	}
}

func TestPublicSecurityGroupIngressMatches_AllTrafficDoesNotMatchProtocolSpecificRulesWithoutPorts(t *testing.T) {
	execution := &Execution{
		TriggerData: map[string]any{
			"policy_id": "aws-ec2-sg-no-all-traffic-ingress",
			"direction": "ingress",
			"protocol":  "icmp",
			"ip_ranges": []any{
				map[string]any{"CidrIp": "0.0.0.0/0"},
			},
		},
	}

	matches, detail := publicSecurityGroupIngressMatches(execution)
	if len(matches) != 0 {
		t.Fatalf("matches = %#v, want none (detail=%q)", matches, detail)
	}
}
