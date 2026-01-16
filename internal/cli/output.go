package cli

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	FormatTable = "table"
	FormatJSON  = "json"
	FormatCSV   = "csv"
	FormatWide  = "wide"
)

// Colors for terminal output
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

var useColor = true

func init() {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		useColor = false
	}
}

func color(c, s string) string {
	if !useColor {
		return s
	}
	return c + s + colorReset
}

func bold(s string) string {
	return color(colorBold, s)
}

func severityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return color(colorRed+colorBold, severity)
	case "high":
		return color(colorRed, severity)
	case "medium":
		return color(colorYellow, severity)
	case "low":
		return color(colorBlue, severity)
	case "info":
		return color(colorGray, severity)
	default:
		return severity
	}
}

func statusColor(status string) string {
	switch strings.ToLower(status) {
	case "open", "failed", "failing":
		return color(colorRed, status)
	case "resolved", "passed", "passing", "healthy":
		return color(colorGreen, status)
	case "suppressed", "pending":
		return color(colorYellow, status)
	default:
		return status
	}
}

// TableWriter writes formatted table output
type TableWriter struct {
	w        io.Writer
	columns  []string
	widths   []int
	maxWidth int
	rows     [][]string
}

func NewTableWriter(w io.Writer, columns ...string) *TableWriter {
	widths := make([]int, len(columns))
	for i, col := range columns {
		widths[i] = len(col)
	}
	return &TableWriter{
		w:        w,
		columns:  columns,
		widths:   widths,
		maxWidth: 60,
	}
}

func (t *TableWriter) AddRow(values ...string) {
	row := make([]string, len(t.columns))
	for i := range t.columns {
		if i < len(values) {
			row[i] = values[i]
			if len(values[i]) > t.widths[i] {
				t.widths[i] = len(values[i])
			}
		}
	}
	t.rows = append(t.rows, row)
}

func (t *TableWriter) Render() {
	// Cap widths at maxWidth
	for i := range t.widths {
		if t.widths[i] > t.maxWidth {
			t.widths[i] = t.maxWidth
		}
	}

	// Header
	for i, col := range t.columns {
		_, _ = fmt.Fprintf(t.w, "%-*s  ", t.widths[i], bold(strings.ToUpper(col)))
	}
	_, _ = fmt.Fprintln(t.w)

	// Separator
	for i := range t.columns {
		_, _ = fmt.Fprint(t.w, strings.Repeat("-", t.widths[i])+"  ")
	}
	_, _ = fmt.Fprintln(t.w)

	// Rows
	for _, row := range t.rows {
		for i, val := range row {
			display := val
			// Strip ANSI codes for length calculation
			plainLen := len(stripANSI(val))
			if plainLen > t.maxWidth {
				// Truncate but preserve color codes
				display = truncate(val, t.maxWidth-3) + "..."
				plainLen = t.maxWidth
			}
			// Pad based on plain text length
			padding := t.widths[i] - plainLen
			if padding < 0 {
				padding = 0
			}
			_, _ = fmt.Fprintf(t.w, "%s%s  ", display, strings.Repeat(" ", padding))
		}
		_, _ = fmt.Fprintln(t.w)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	// Simple truncation - won't handle ANSI codes perfectly but works for most cases
	return s[:maxLen]
}

func stripANSI(s string) string {
	var result strings.Builder
	inEscape := false
	for _, r := range s {
		if r == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if r == 'm' {
				inEscape = false
			}
			continue
		}
		result.WriteRune(r)
	}
	return result.String()
}

// JSONOutput writes JSON to stdout
func JSONOutput(data interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

// CSVOutput writes CSV to stdout
func CSVOutput(columns []string, rows [][]string) error {
	w := csv.NewWriter(os.Stdout)
	if err := w.Write(columns); err != nil {
		return err
	}
	for _, row := range rows {
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

// Spinner for long-running operations
type Spinner struct {
	message string
	done    chan struct{}
	frames  []string
}

func NewSpinner(message string) *Spinner {
	return &Spinner{
		message: message,
		done:    make(chan struct{}),
		frames:  []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
	}
}

func (s *Spinner) Start() {
	if !useColor {
		fmt.Printf("%s...\n", s.message)
		return
	}
	go func() {
		i := 0
		for {
			select {
			case <-s.done:
				fmt.Print("\r\033[K") // Clear line
				return
			default:
				fmt.Printf("\r%s %s ", color(colorCyan, s.frames[i%len(s.frames)]), s.message)
				i++
				// Sleep handled by caller
			}
		}
	}()
}

func (s *Spinner) Stop(success bool, message string) {
	close(s.done)
	if !useColor {
		fmt.Println(message)
		return
	}
	icon := color(colorGreen, "✓")
	if !success {
		icon = color(colorRed, "✗")
	}
	fmt.Printf("\r%s %s\n", icon, message)
}

// Success prints a success message
func Success(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if useColor {
		fmt.Printf("%s %s\n", color(colorGreen, "✓"), msg)
	} else {
		fmt.Printf("[OK] %s\n", msg)
	}
}

// Error prints an error message
func Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if useColor {
		fmt.Fprintf(os.Stderr, "%s %s\n", color(colorRed, "✗"), msg)
	} else {
		fmt.Fprintf(os.Stderr, "[ERROR] %s\n", msg)
	}
}

// Warning prints a warning message
func Warning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if useColor {
		fmt.Printf("%s %s\n", color(colorYellow, "!"), msg)
	} else {
		fmt.Printf("[WARN] %s\n", msg)
	}
}

// Info prints an info message
func Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if useColor {
		fmt.Printf("%s %s\n", color(colorBlue, "ℹ"), msg)
	} else {
		fmt.Printf("[INFO] %s\n", msg)
	}
}
