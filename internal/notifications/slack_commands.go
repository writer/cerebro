package notifications

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

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
		switch arg {
		case "critical", "high", "medium", "low":
			filter.Severity = arg
		case "open", "resolved", "suppressed":
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
					{Title: "Open", Value: fmt.Sprintf("%d", stats.ByStatus["OPEN"]), Short: true},
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

	// Read body for signature verification
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		return
	}

	// Verify Slack signature if signing secret is configured
	if h.signingSecret != "" {
		if !h.verifySlackSignature(r.Header, body) {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}
	}

	// Parse form from body
	formValues, err := parseFormBody(string(body))
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	cmd := SlackCommand{
		Token:       formValues["token"],
		TeamID:      formValues["team_id"],
		ChannelID:   formValues["channel_id"],
		ChannelName: formValues["channel_name"],
		UserID:      formValues["user_id"],
		UserName:    formValues["user_name"],
		Command:     formValues["command"],
		Text:        formValues["text"],
		ResponseURL: formValues["response_url"],
		TriggerID:   formValues["trigger_id"],
	}

	response := h.HandleCommand(cmd)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// verifySlackSignature verifies the Slack request signature
func (h *SlackCommandHandler) verifySlackSignature(header http.Header, body []byte) bool {
	timestamp := header.Get("X-Slack-Request-Timestamp")
	signature := header.Get("X-Slack-Signature")

	if timestamp == "" || signature == "" {
		return false
	}

	// Check timestamp to prevent replay attacks (5 min window)
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	if math.Abs(float64(time.Now().Unix()-ts)) > 300 {
		return false
	}

	// Compute expected signature
	sigBaseString := fmt.Sprintf("v0:%s:%s", timestamp, string(body))
	mac := hmac.New(sha256.New, []byte(h.signingSecret))
	mac.Write([]byte(sigBaseString))
	expectedSig := "v0=" + hex.EncodeToString(mac.Sum(nil))

	// Constant-time comparison
	return hmac.Equal([]byte(signature), []byte(expectedSig))
}

// parseFormBody parses URL-encoded form data from a string
func parseFormBody(body string) (map[string]string, error) {
	values := make(map[string]string)
	for _, pair := range strings.Split(body, "&") {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			// URL decode the value
			key := parts[0]
			value := strings.ReplaceAll(parts[1], "+", " ")
			values[key] = value
		}
	}
	return values, nil
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
