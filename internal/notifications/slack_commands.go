package notifications

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/writerinternal/cerebro/internal/findings"
)

// SlackCommandHandler handles Slack slash commands
type SlackCommandHandler struct {
	signingSecret string
	findings      findings.FindingStore
}

type SlackCommandConfig struct {
	SigningSecret string
}

func NewSlackCommandHandler(cfg SlackCommandConfig, fs findings.FindingStore) *SlackCommandHandler {
	return &SlackCommandHandler{
		signingSecret: cfg.SigningSecret,
		findings:      fs,
	}
}

// SlackCommand represents an incoming slash command
type SlackCommand struct {
	Token       string `schema:"token"`
	TeamID      string `schema:"team_id"`
	ChannelID   string `schema:"channel_id"`
	ChannelName string `schema:"channel_name"`
	UserID      string `schema:"user_id"`
	UserName    string `schema:"user_name"`
	Command     string `schema:"command"`
	Text        string `schema:"text"`
	ResponseURL string `schema:"response_url"`
	TriggerID   string `schema:"trigger_id"`
}

// SlackResponse is the response format for slash commands
type SlackResponse struct {
	ResponseType string            `json:"response_type,omitempty"` // ephemeral or in_channel
	Text         string            `json:"text,omitempty"`
	Attachments  []SlackAttachment `json:"attachments,omitempty"`
	Blocks       []SlackBlock      `json:"blocks,omitempty"`
}

type SlackAttachment struct {
	Color      string       `json:"color,omitempty"`
	Title      string       `json:"title,omitempty"`
	Text       string       `json:"text,omitempty"`
	Fields     []SlackField `json:"fields,omitempty"`
	Footer     string       `json:"footer,omitempty"`
	FooterIcon string       `json:"footer_icon,omitempty"`
	Timestamp  int64        `json:"ts,omitempty"`
}

type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

type SlackBlock struct {
	Type string     `json:"type"`
	Text *SlackText `json:"text,omitempty"`
}

type SlackText struct {
	Type string `json:"type"` // plain_text or mrkdwn
	Text string `json:"text"`
}

// HandleCommand processes a slash command and returns a response
func (h *SlackCommandHandler) HandleCommand(cmd SlackCommand) SlackResponse {
	args := strings.Fields(cmd.Text)
	if len(args) == 0 {
		return h.helpResponse()
	}

	switch args[0] {
	case "findings":
		return h.findingsCommand(args[1:])
	case "stats":
		return h.statsCommand()
	case "help":
		return h.helpResponse()
	default:
		return SlackResponse{
			ResponseType: "ephemeral",
			Text:         fmt.Sprintf("Unknown command: %s. Use `/cerebro help` for available commands.", args[0]),
		}
	}
}

func (h *SlackCommandHandler) findingsCommand(args []string) SlackResponse {
	filter := findings.FindingFilter{}

	// Parse arguments
	for _, arg := range args {
		switch {
		case arg == "critical" || arg == "high" || arg == "medium" || arg == "low":
			filter.Severity = arg
		case arg == "open" || arg == "resolved" || arg == "suppressed":
			filter.Status = arg
		}
	}

	if filter.Status == "" {
		filter.Status = "open"
	}

	list := h.findings.List(filter)
	if len(list) == 0 {
		return SlackResponse{
			ResponseType: "ephemeral",
			Text:         "No findings match your criteria.",
		}
	}

	// Limit to 10 for Slack display
	if len(list) > 10 {
		list = list[:10]
	}

	attachments := make([]SlackAttachment, len(list))
	for i, f := range list {
		attachments[i] = SlackAttachment{
			Color: severityColor(f.Severity),
			Title: f.PolicyName,
			Text:  f.Description,
			Fields: []SlackField{
				{Title: "Severity", Value: f.Severity, Short: true},
				{Title: "Status", Value: f.Status, Short: true},
				{Title: "ID", Value: f.ID, Short: true},
			},
		}
	}

	return SlackResponse{
		ResponseType: "ephemeral",
		Text:         fmt.Sprintf("Found %d findings:", len(list)),
		Attachments:  attachments,
	}
}

func (h *SlackCommandHandler) statsCommand() SlackResponse {
	stats := h.findings.Stats()

	return SlackResponse{
		ResponseType: "ephemeral",
		Attachments: []SlackAttachment{
			{
				Color: "#0066FF",
				Title: "Security Findings Overview",
				Fields: []SlackField{
					{Title: "Total", Value: fmt.Sprintf("%d", stats.Total), Short: true},
					{Title: "Critical", Value: fmt.Sprintf("%d", stats.BySeverity["critical"]), Short: true},
					{Title: "High", Value: fmt.Sprintf("%d", stats.BySeverity["high"]), Short: true},
					{Title: "Medium", Value: fmt.Sprintf("%d", stats.BySeverity["medium"]), Short: true},
					{Title: "Low", Value: fmt.Sprintf("%d", stats.BySeverity["low"]), Short: true},
					{Title: "Open", Value: fmt.Sprintf("%d", stats.ByStatus["open"]), Short: true},
				},
				Footer: "Cerebro Security",
			},
		},
	}
}

func (h *SlackCommandHandler) helpResponse() SlackResponse {
	return SlackResponse{
		ResponseType: "ephemeral",
		Text:         "*Cerebro Security Commands*",
		Attachments: []SlackAttachment{
			{
				Color: "#0066FF",
				Fields: []SlackField{
					{Title: "/cerebro findings [severity] [status]", Value: "List security findings. Filter by severity (critical, high, medium, low) or status (open, resolved).", Short: false},
					{Title: "/cerebro stats", Value: "Show findings statistics overview.", Short: false},
					{Title: "/cerebro help", Value: "Show this help message.", Short: false},
				},
			},
		},
	}
}

func severityColor(severity string) string {
	switch severity {
	case "critical":
		return "#FF0000"
	case "high":
		return "#FF6600"
	case "medium":
		return "#FFCC00"
	case "low":
		return "#0066FF"
	default:
		return "#808080"
	}
}

// ServeHTTP handles incoming Slack slash commands
func (h *SlackCommandHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	cmd := SlackCommand{
		Token:       r.FormValue("token"),
		TeamID:      r.FormValue("team_id"),
		ChannelID:   r.FormValue("channel_id"),
		ChannelName: r.FormValue("channel_name"),
		UserID:      r.FormValue("user_id"),
		UserName:    r.FormValue("user_name"),
		Command:     r.FormValue("command"),
		Text:        r.FormValue("text"),
		ResponseURL: r.FormValue("response_url"),
		TriggerID:   r.FormValue("trigger_id"),
	}

	response := h.HandleCommand(cmd)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// DailyDigest generates a daily summary for Slack
func (h *SlackCommandHandler) DailyDigest() SlackResponse {
	stats := h.findings.Stats()

	// Get critical and high findings
	critical := h.findings.List(findings.FindingFilter{Severity: "critical", Status: "open"})
	high := h.findings.List(findings.FindingFilter{Severity: "high", Status: "open"})

	summary := fmt.Sprintf(
		"*Daily Security Digest*\n\n"+
			":rotating_light: *%d* Critical | :warning: *%d* High | :large_yellow_circle: *%d* Medium | :large_blue_circle: *%d* Low\n\n"+
			"Total Open: *%d*",
		stats.BySeverity["critical"],
		stats.BySeverity["high"],
		stats.BySeverity["medium"],
		stats.BySeverity["low"],
		stats.ByStatus["open"],
	)

	attachments := []SlackAttachment{}

	// Add critical findings
	if len(critical) > 0 {
		for i, f := range critical {
			if i >= 3 {
				break
			}
			attachments = append(attachments, SlackAttachment{
				Color: "#FF0000",
				Title: f.PolicyName,
				Text:  f.Description,
				Fields: []SlackField{
					{Title: "ID", Value: f.ID, Short: true},
				},
			})
		}
	}

	// Add high findings
	if len(high) > 0 {
		for i, f := range high {
			if i >= 3 {
				break
			}
			attachments = append(attachments, SlackAttachment{
				Color: "#FF6600",
				Title: f.PolicyName,
				Text:  f.Description,
				Fields: []SlackField{
					{Title: "ID", Value: f.ID, Short: true},
				},
			})
		}
	}

	return SlackResponse{
		ResponseType: "in_channel",
		Text:         summary,
		Attachments:  attachments,
	}
}
