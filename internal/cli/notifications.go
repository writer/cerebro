package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/notifications"
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

	runNotificationsTestDirectFn = runNotificationsTestDirect
)

func init() {
	notificationsTestCmd.Flags().StringVar(&testMessage, "message", "Test notification from Cerebro CLI", "Custom message to send")
	notificationsTestCmd.Flags().StringVar(&testSeverity, "severity", "info", "Severity level (info, low, medium, high, critical)")
	notificationsTestCmd.Flags().StringVarP(&testOutput, "output", "o", "text", "Output format (text,json)")

	notificationsCmd.AddCommand(notificationsTestCmd)
}

func runNotificationsTest(cmd *cobra.Command, args []string) error {
	ctx := commandContextOrBackground(cmd)
	mode, err := loadCLIExecutionMode()
	if err != nil {
		return err
	}

	if mode != cliExecutionModeDirect {
		apiClient, err := newCLIAPIClient()
		if err != nil {
			if mode == cliExecutionModeAPI {
				return err
			}
			Warning("API client configuration invalid; using direct mode: %v", err)
		} else {
			notifiers, err := apiClient.ListNotifiers(ctx, 0, 0)
			if err != nil {
				if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
					return fmt.Errorf("list notification channels via api: %w", err)
				}
				Warning("API unavailable; using direct mode: %v", err)
				return runNotificationsTestDirectFn(cmd, args)
			}
			if len(notifiers) == 0 {
				return renderNoNotificationChannels()
			}

			if testOutput != FormatJSON {
				Info("Testing %d notification channel(s)...", len(notifiers))
			}

			var spinner *Spinner
			if testOutput != FormatJSON {
				spinner = NewSpinner("Sending test notifications")
				spinner.Start()
			}

			resp, err := apiClient.TestNotifications(ctx, testMessage, testSeverity)
			if err != nil {
				if spinner != nil {
					spinner.Stop(false, fmt.Sprintf("Notification test via API failed: %v", err))
				}
				if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
					return fmt.Errorf("test notifications via api: %w", err)
				}
				Warning("API unavailable; using direct mode: %v", err)
				return runNotificationsTestDirectFn(cmd, args)
			}

			if resp != nil && strings.EqualFold(resp.Status, "partial") {
				err := fmt.Errorf("notification test failed: %s", resp.Error)
				if testOutput == FormatJSON {
					if jsonErr := JSONOutput(map[string]interface{}{
						"success":  false,
						"error":    resp.Error,
						"channels": notifiers,
					}); jsonErr != nil {
						return jsonErr
					}
					return err
				}
				if spinner != nil {
					spinner.Stop(false, fmt.Sprintf("Some notifications failed: %s", resp.Error))
				}
				return err
			}

			if testOutput == FormatJSON {
				return JSONOutput(map[string]interface{}{
					"success":  true,
					"channels": notifiers,
					"count":    len(notifiers),
				})
			}

			if spinner != nil {
				spinner.Stop(true, fmt.Sprintf("Sent to %d channel(s): %v", len(notifiers), notifiers))
			}
			fmt.Println()
			Success("All notification channels working")
			return nil
		}
	}

	return runNotificationsTestDirectFn(cmd, args)
}

func runNotificationsTestDirect(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	application, err := app.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	defer func() { _ = application.Close() }()

	if application.Notifications == nil {
		return renderNoNotificationChannels()
	}

	notifiers := application.Notifications.ListNotifiers()
	if len(notifiers) == 0 {
		return renderNoNotificationChannels()
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

func renderNoNotificationChannels() error {
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

	Warning("No notification channels configured")
	fmt.Println("\nTo configure notifications, set environment variables:")
	fmt.Println("  SLACK_WEBHOOK_URL      - Slack incoming webhook URL")
	fmt.Println("  PAGERDUTY_ROUTING_KEY  - PagerDuty Events API routing key")
	return nil
}
