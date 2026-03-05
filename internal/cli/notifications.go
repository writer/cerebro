package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/notifications"
)

var notificationsCmd = &cobra.Command{
	Use:   "notifications",
	Short: "Manage notifications",
	Long:  `Commands for managing and testing notification channels (Slack, PagerDuty, webhooks).`,
}

var notificationsTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test notification channels",
	Long: `Send a test notification to verify Slack, PagerDuty, and webhook configurations.

This helps verify that notification channels are properly configured before
real security findings trigger alerts.

Example:
  cerebro notifications test
  cerebro notifications test --message "Testing from CI/CD"
  cerebro notifications test --severity critical`,
	RunE: runNotificationsTest,
}

var (
	testMessage  string
	testSeverity string
	testOutput   string
)

func init() {
	notificationsTestCmd.Flags().StringVar(&testMessage, "message", "Test notification from Cerebro CLI", "Custom message to send")
	notificationsTestCmd.Flags().StringVar(&testSeverity, "severity", "info", "Severity level (info, low, medium, high, critical)")
	notificationsTestCmd.Flags().StringVarP(&testOutput, "output", "o", "text", "Output format (text,json)")

	notificationsCmd.AddCommand(notificationsTestCmd)
}

func runNotificationsTest(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	defer func() { _ = application.Close() }()

	if application.Notifications == nil {
		if testOutput == FormatJSON {
			if jsonErr := JSONOutput(map[string]interface{}{
				"success":  false,
				"error":    "no notification channels configured",
				"channels": []string{},
			}); jsonErr != nil {
				return jsonErr
			}
			return fmt.Errorf("no notification channels configured")
		}
		return fmt.Errorf("no notification channels configured - set SLACK_WEBHOOK_URL, PAGERDUTY_ROUTING_KEY, or configure webhooks")
	}

	notifiers := application.Notifications.ListNotifiers()
	if len(notifiers) == 0 {
		if testOutput == FormatJSON {
			return JSONOutput(map[string]interface{}{
				"success":  false,
				"error":    "no notification channels configured",
				"channels": []string{},
			})
		}
		Warning("No notification channels configured")
		fmt.Println("\nTo configure notifications, set environment variables:")
		fmt.Println("  SLACK_WEBHOOK_URL      - Slack incoming webhook URL")
		fmt.Println("  PAGERDUTY_ROUTING_KEY  - PagerDuty Events API routing key")
		return nil
	}

	if testOutput != FormatJSON {
		Info("Testing %d notification channel(s)...", len(notifiers))
	}

	event := notifications.Event{
		Type:     "test",
		Title:    "Cerebro Test Notification",
		Message:  testMessage,
		Severity: testSeverity,
	}

	var spinner *Spinner
	if testOutput != FormatJSON {
		spinner = NewSpinner("Sending test notifications")
		spinner.Start()
	}

	err = application.Notifications.Send(ctx, event)
	if err != nil {
		if testOutput == FormatJSON {
			if jsonErr := JSONOutput(map[string]interface{}{
				"success":  false,
				"error":    err.Error(),
				"channels": notifiers,
			}); jsonErr != nil {
				return jsonErr
			}
			return err
		}
		spinner.Stop(false, fmt.Sprintf("Some notifications failed: %v", err))
		return err
	}

	if testOutput == FormatJSON {
		return JSONOutput(map[string]interface{}{
			"success":  true,
			"channels": notifiers,
			"count":    len(notifiers),
		})
	}

	spinner.Stop(true, fmt.Sprintf("Sent to %d channel(s): %v", len(notifiers), notifiers))
	fmt.Println()
	Success("All notification channels working")
	return nil
}
