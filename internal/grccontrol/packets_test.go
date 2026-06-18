package grccontrol

import (
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/compliance"
)

func TestRenderMarkdownEscapesUserSuppliedMarkdownSyntax(t *testing.T) {
	generatedAt := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	result := PacketResult{
		Profile: Profile{
			ID:   "customer-profile",
			Name: "Customer [Audit](https://evil.example) ~~strike~~",
		},
		Packet: compliance.ControlEvidencePacket{
			GeneratedAt: generatedAt,
			Summary: compliance.ControlPostureSummary{
				Total:    1,
				ByStatus: map[compliance.ControlPostureStatus]int{},
			},
			Controls: []compliance.ControlEvidencePacketControl{{
				Control: compliance.ControlPostureControl{
					FrameworkName: "Customer [Framework](https://evil.example)",
					ControlID:     "IAM-1",
					Title:         "Click [here](https://evil.example) <script>",
					OwnerDomain:   "security|platform",
				},
				Status: compliance.ControlPosturePassing,
				Readiness: compliance.ControlEvidencePacketReadiness{
					Score:   100,
					Rating:  compliance.ControlEvidenceQualityStrong,
					Summary: "Ready [now](https://evil.example)",
				},
				Evidence: compliance.ControlEvidencePacketEvidence{
					Expectations: []compliance.ControlEvidenceExpectationPosture{{
						ID:           "evidence-1",
						Title:        "Proof [link](https://evil.example)",
						Type:         "system|state",
						Required:     true,
						Status:       compliance.ControlEvidenceExpectationSatisfied,
						Quality:      compliance.ControlEvidenceQualityStrong,
						FreshnessSLA: "30d",
					}},
					Items: []compliance.ControlEvidencePacketEvidenceItem{{
						ID:           "item-1",
						EvidenceType: "runtime|config",
						Status:       "passing",
						Quality:      compliance.ControlEvidenceQualityStrong,
						Source:       "collector|agent",
					}},
				},
				Findings: []compliance.ControlEvidencePacketFinding{{
					ID:       "finding-1",
					Severity: "high",
					Status:   "open",
					RuleID:   "rule-1",
					Title:    "Finding [link](https://evil.example)",
				}},
			}},
		},
	}

	markdown := RenderMarkdown(result)

	for _, disallowed := range []string{
		"[Audit](https://evil.example)",
		"[Framework](https://evil.example)",
		"[here](https://evil.example)",
		"[now](https://evil.example)",
		"~~strike~~",
		"<script>",
	} {
		if strings.Contains(markdown, disallowed) {
			t.Fatalf("markdown contains unescaped fragment %q:\n%s", disallowed, markdown)
		}
	}
	for _, required := range []string{
		`Customer \[Audit\]\(https://evil.example\)`,
		`\~\~strike\~\~`,
		`Customer \[Framework\]\(https://evil.example\) IAM-1`,
		`Click \[here\]\(https://evil.example\) \<script\>`,
		`security\|platform`,
		`collector\|agent`,
	} {
		if !strings.Contains(markdown, required) {
			t.Fatalf("markdown missing escaped fragment %q:\n%s", required, markdown)
		}
	}
}
