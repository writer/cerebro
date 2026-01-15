package agents

import (
	"github.com/google/uuid"
)

// NewDeepResearchAgent creates a specialized agent for code-to-cloud research
func NewDeepResearchAgent(provider LLMProvider, tools *SecurityTools) *Agent {
	return &Agent{
		ID:          "deep-research-agent-" + uuid.New().String()[:8],
		Name:        "Deep Research Agent",
		Description: "Specialized agent for bridging code analysis and cloud verification.",
		Provider:    provider,
		Tools:       tools.GetTools(),
		Memory:      NewMemory(100),
	}
}

// GetDeepResearchPlaybook returns the standard playbook
func GetDeepResearchPlaybook() *Playbook {
	return &Playbook{
		ID:          "deep-research-code-to-cloud",
		Name:        "Code-to-Cloud Deep Research",
		Description: "Investigate security findings by analyzing source code and verifying against cloud infrastructure.",
		Steps: []PlaybookStep{
			{
				Order:       1,
				Name:        "Analyze Code Context",
				Description: "Examine the source code surrounding the finding to understand the implementation details.",
				Action:      "analyze_repo",
			},
			{
				Order:       2,
				Name:        "Identify Cloud Resources",
				Description: "Extract cloud resource identifiers (ARN, bucket name, etc.) from the code.",
				Action:      "analyze_repo",
			},
			{
				Order:       3,
				Name:        "Verify Cloud State",
				Description: "Check the actual state of the identified resource in the cloud environment.",
				Action:      "inspect_cloud_resource",
			},
			{
				Order:       4,
				Name:        "Assess Risk",
				Description: "Compare code intent with cloud reality to determine actual risk.",
				Action:      "evaluate_policy",
			},
		},
	}
}
