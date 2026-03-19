package builders

import "testing"

func TestAWSSecurityGroupNodeFromRecordMarksPublicIngress(t *testing.T) {
	node := awsSecurityGroupNodeFromRecord(map[string]any{
		"arn":            "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123",
		"group_id":       "sg-123",
		"group_name":     "web",
		"account_id":     "123456789012",
		"region":         "us-east-1",
		"ip_permissions": []map[string]any{{"IpRanges": []map[string]any{{"CidrIp": "0.0.0.0/0"}}}},
	}, "aws", "", "")
	if node == nil {
		t.Fatal("expected node")
	}
	if node.Kind != NodeKindNetwork {
		t.Fatalf("expected network node kind, got %q", node.Kind)
	}
	if public, _ := node.Properties["public"].(bool); !public {
		t.Fatalf("expected public security group, got %#v", node.Properties)
	}
}

func TestGCPFirewallNodeFromRecordMarksPublicIngress(t *testing.T) {
	node := gcpFirewallNodeFromRecord(map[string]any{
		"self_link":     "https://compute.googleapis.com/projects/p1/global/firewalls/fw-1",
		"name":          "fw-1",
		"project_id":    "p1",
		"direction":     "INGRESS",
		"source_ranges": []string{"0.0.0.0/0"},
		"allowed":       []map[string]any{{"ip_protocol": "tcp", "ports": []string{"22"}}},
	}, "gcp", "", "")
	if node == nil {
		t.Fatal("expected node")
	}
	if node.Kind != NodeKindNetwork {
		t.Fatalf("expected network node kind, got %q", node.Kind)
	}
	if public, _ := node.Properties["public"].(bool); !public {
		t.Fatalf("expected public firewall node, got %#v", node.Properties)
	}
}

func TestAzureNetworkSecurityGroupNodeFromRecordMarksPublicIngress(t *testing.T) {
	node := azureNetworkSecurityGroupNodeFromRecord(map[string]any{
		"id":              "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-1",
		"name":            "nsg-1",
		"subscription_id": "sub-1",
		"location":        "eastus",
		"security_rules": []map[string]any{{
			"Direction":            "Inbound",
			"Access":               "Allow",
			"SourceAddressPrefix":  "*",
			"DestinationPortRange": "22",
		}},
	}, "azure", "", "")
	if node == nil {
		t.Fatal("expected node")
	}
	if node.Kind != NodeKindNetwork {
		t.Fatalf("expected network node kind, got %q", node.Kind)
	}
	if public, _ := node.Properties["public"].(bool); !public {
		t.Fatalf("expected public NSG node, got %#v", node.Properties)
	}
}

func TestAzureNetworkSecurityGroupAllowsInternetSupportsStructuredPrefixLists(t *testing.T) {
	record := map[string]any{
		"security_rules": []map[string]any{{
			"direction":               "Inbound",
			"access":                  "Allow",
			"source_address_prefixes": []string{"*"},
			"destination_port_ranges": []string{"22"},
		}},
	}

	if !azureNetworkSecurityGroupAllowsInternet(record) {
		t.Fatalf("expected structured source_address_prefixes to be treated as public ingress, got %#v", record)
	}
}

func TestNetworkAssetNodeIDsMatchCDCRemovalFallback(t *testing.T) {
	tests := []struct {
		name    string
		table   string
		payload map[string]any
		node    *Node
	}{
		{
			name:  "aws security group prefers cq id over raw id fields",
			table: "aws_ec2_security_groups",
			payload: map[string]any{
				"_cq_id":   "cq-sg-123",
				"group_id": "sg-123",
				"id":       "legacy-id",
				"name":     "web",
			},
			node: awsSecurityGroupNodeFromRecord(map[string]any{
				"_cq_id":   "cq-sg-123",
				"group_id": "sg-123",
				"id":       "legacy-id",
				"name":     "web",
			}, "aws", "", ""),
		},
		{
			name:  "gcp firewall prefers self link",
			table: "gcp_compute_firewalls",
			payload: map[string]any{
				"self_link": "https://compute.googleapis.com/projects/p1/global/firewalls/fw-1",
				"_cq_id":    "cq-fw-1",
				"id":        "1234567890",
				"name":      "fw-1",
			},
			node: gcpFirewallNodeFromRecord(map[string]any{
				"self_link": "https://compute.googleapis.com/projects/p1/global/firewalls/fw-1",
				"_cq_id":    "cq-fw-1",
				"id":        "1234567890",
				"name":      "fw-1",
			}, "gcp", "", ""),
		},
		{
			name:  "azure network security group prefers cq id before name",
			table: "azure_network_security_groups",
			payload: map[string]any{
				"_cq_id": "cq-nsg-1",
				"name":   "nsg-1",
			},
			node: azureNetworkSecurityGroupNodeFromRecord(map[string]any{
				"_cq_id": "cq-nsg-1",
				"name":   "nsg-1",
			}, "azure", "", ""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.node == nil {
				t.Fatal("expected node")
			}
			if got := cdcNodeID(tt.table, tt.payload, ""); got != tt.node.ID {
				t.Fatalf("expected cdc removal id %q to match node id %q", got, tt.node.ID)
			}
		})
	}
}
