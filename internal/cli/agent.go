package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/evalops/cerebro/internal/agents"
	"github.com/evalops/cerebro/internal/agents/providers"
	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/scm"
)

const (
	// agentTurnTimeout is the maximum time allowed for a single agent turn (LLM call + tool execution)
	agentTurnTimeout = 5 * time.Minute
	// agentSessionTimeout is the maximum time for an entire agent session
	agentSessionTimeout = 30 * time.Minute
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Start the Deep Research Agent",
	Long: `Start an interactive session with the Deep Research Agent to investigate findings.
Requires ANTHROPIC_API_KEY environment variable.`,
	RunE: runAgent,
}

func init() {
	rootCmd.AddCommand(agentCmd)
}

func runAgent(cmd *cobra.Command, args []string) error {
	// Create context with session timeout and signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ctx, sessionCancel := context.WithTimeout(ctx, agentSessionTimeout)
	defer sessionCancel()

	// 1. Initialize App (to get DB, Config, etc.)
	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize app: %w", err)
	}
	defer func() { _ = application.Close() }()

	// 2. Initialize Provider (Anthropic)
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		return fmt.Errorf("ANTHROPIC_API_KEY is required")
	}

	provider := providers.NewAnthropicProvider(providers.AnthropicConfig{
		APIKey: apiKey,
		Model:  "claude-3-5-sonnet-20241022",
	})

	// 3. Initialize SCM
	scmClient := scm.NewConfiguredClient(
		application.Config.GitHubToken,
		application.Config.GitLabToken,
		application.Config.GitLabBaseURL,
	)

	// 4. Initialize Tools
	tools := agents.NewSecurityTools(
		application.Snowflake,
		application.Findings,
		application.Policy,
		scmClient,
	)

	// 4. Initialize Agent
	agent := agents.NewDeepResearchAgent(provider, tools)

	registry := agents.NewAgentRegistry()
	registry.RegisterAgent(agent)

	// 5. Create Session
	session, err := registry.CreateSession(agent.ID, "cli-user", agents.SessionContext{
		Playbook: agents.GetDeepResearchPlaybook(),
	})
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	fmt.Printf("\n🤖 Deep Research Agent Active (%s)\n", agent.ID)
	fmt.Println("Type 'exit' or 'quit' to stop.")
	fmt.Println("------------------------------------------------")

	reader := bufio.NewReader(os.Stdin)

	for {
		// Check if context is cancelled (timeout or signal)
		select {
		case <-ctx.Done():
			fmt.Println("\nSession ended:", ctx.Err())
			return nil
		default:
		}

		fmt.Print("\n> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		input = strings.TrimSpace(input)

		if input == "exit" || input == "quit" {
			break
		}
		if input == "" {
			continue
		}

		// Add user message
		session.Status = "active"
		session.Messages = append(session.Messages, agents.Message{
			Role:    "user",
			Content: input,
		})

		fmt.Println("Agent is thinking...")

		// Create turn-level timeout context
		turnCtx, turnCancel := context.WithTimeout(ctx, agentTurnTimeout)
		err = runAgentLoop(turnCtx, provider, session, agent.Tools, func(tool *agents.Tool, _ agents.ToolCall) bool {
			return promptToolApproval(reader, tool.Name)
		})
		turnCancel()

		if err != nil {
			if turnCtx.Err() == context.DeadlineExceeded {
				fmt.Println("Turn timed out. Please try a simpler request.")
			} else {
				fmt.Printf("Error: %v\n", err)
			}
		}
	}

	return nil
}

func runAgentLoop(
	ctx context.Context,
	provider agents.LLMProvider,
	session *agents.Session,
	tools []agents.Tool,
	approver func(tool *agents.Tool, call agents.ToolCall) bool,
) error {
	maxTurns := 15 // Limit recursion depth

	for i := 0; i < maxTurns; i++ {
		// Check context before each turn
		if err := ctx.Err(); err != nil {
			return err
		}

		// Prepare messages including System prompt
		messages := append([]agents.Message{{Role: "system", Content: session.GetSystemPrompt()}}, session.Messages...)

		resp, err := provider.Complete(ctx, messages, tools)
		if err != nil {
			return err
		}

		// Append assistant message
		session.Messages = append(session.Messages, resp.Message)

		// Print content if any
		if resp.Message.Content != "" {
			fmt.Printf("\n%s\n", resp.Message.Content)
		}

		// Handle tool calls
		if len(resp.Message.ToolCalls) > 0 {
			for _, tc := range resp.Message.ToolCalls {
				fmt.Printf("\n[Tool Call] %s\n", tc.Name)

				// Find tool
				var tool *agents.Tool
				for _, t := range tools {
					if t.Name == tc.Name {
						tool = &t
						break
					}
				}

				if tool == nil {
					result := fmt.Sprintf("Error: Tool %s not found", tc.Name)
					session.Messages = append(session.Messages, agents.Message{
						Role:    "tool",
						Content: result,
						Name:    tc.ID, // Used as tool_use_id
					})
					continue
				}

				approved := true
				if tool.RequiresApproval {
					approved = false
					if approver != nil {
						approved = approver(tool, tc)
					}

					if !approved {
						session.Status = "pending_approval"
						output := fmt.Sprintf("{\"error\":\"tool %s requires approval before execution\",\"code\":\"approval_required\"}", tc.Name)
						fmt.Printf("[Tool Approval Required] %s\n", tc.Name)
						session.Messages = append(session.Messages, agents.Message{
							Role:    "tool",
							Content: output,
							Name:    tc.ID,
						})
						continue
					}
					session.Status = "active"
				}

				if err := tool.ValidateExecution(approved); err != nil {
					var toolErr *agents.ToolError
					output := fmt.Sprintf("Error executing tool: %v", err)
					if errors.As(err, &toolErr) {
						output = toolErr.JSON()
					}
					session.Messages = append(session.Messages, agents.Message{
						Role:    "tool",
						Content: output,
						Name:    tc.ID,
					})
					continue
				}

				// Execute tool
				output, err := tool.Handler(ctx, tc.Arguments)
				if err != nil {
					var toolErr *agents.ToolError
					if errors.As(err, &toolErr) {
						output = toolErr.JSON()
					} else {
						output = fmt.Sprintf("Error executing tool: %v", err)
					}
				}

				// Truncate output if too long for display, but keep full for context
				displayOutput := output
				if len(displayOutput) > 500 {
					displayOutput = displayOutput[:500] + "... (truncated)"
				}
				fmt.Printf("[Tool Output] %s\n", displayOutput)

				// Append tool result
				session.Messages = append(session.Messages, agents.Message{
					Role:    "tool",
					Content: output,
					Name:    tc.ID, // Used as tool_use_id
				})
			}
			// Continue loop to let LLM process tool results
			continue
		}

		// No tool calls, interaction turn complete
		break
	}
	return nil
}

func promptToolApproval(reader *bufio.Reader, toolName string) bool {
	for {
		fmt.Printf("Approve tool %s? [y/N]: ", toolName)
		input, err := reader.ReadString('\n')
		if err != nil {
			return false
		}

		normalized := strings.ToLower(strings.TrimSpace(input))
		switch normalized {
		case "y", "yes":
			return true
		case "", "n", "no":
			return false
		default:
			fmt.Println("Please answer y or n.")
		}
	}
}
