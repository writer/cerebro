package reports

import "time"

const (
	defaultWeeklyCalibrationWindowDays = 7
	defaultWeeklyCalibrationTrendDays  = 14
)

// WeeklyCalibrationReportOptions controls weekly calibration report generation.
type WeeklyCalibrationReportOptions struct {
	Now              time.Time `json:"now,omitempty"`
	WindowDays       int       `json:"window_days,omitempty"`
	TrendDays        int       `json:"trend_days,omitempty"`
	Profile          string    `json:"profile,omitempty"`
	IncludeQueue     bool      `json:"include_queue,omitempty"`
	QueueLimit       int       `json:"queue_limit,omitempty"`
	SuggestThreshold float64   `json:"suggest_threshold,omitempty"`
}

// WeeklyCalibrationReport is the typed weekly calibration payload exposed by platform intelligence APIs.
type WeeklyCalibrationReport struct {
	GeneratedAt  time.Time                 `json:"generated_at"`
	WindowDays   int                       `json:"window_days"`
	TrendDays    int                       `json:"trend_days"`
	Profile      string                    `json:"profile,omitempty"`
	RiskFeedback OutcomeFeedbackReport     `json:"risk_feedback"`
	Identity     IdentityCalibrationReport `json:"identity"`
	Ontology     GraphOntologySLO          `json:"ontology"`
}

// BuildWeeklyCalibrationReport returns a typed weekly calibration slice across outcome, identity, and ontology quality.
func BuildWeeklyCalibrationReport(g *Graph, engine *RiskEngine, opts WeeklyCalibrationReportOptions) WeeklyCalibrationReport {
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	windowDays := opts.WindowDays
	if windowDays <= 0 {
		windowDays = defaultWeeklyCalibrationWindowDays
	}
	trendDays := opts.TrendDays
	if trendDays <= 0 {
		trendDays = defaultWeeklyCalibrationTrendDays
	}
	queueLimit := opts.QueueLimit
	if queueLimit <= 0 {
		queueLimit = 25
	}
	suggestThreshold := opts.SuggestThreshold
	if suggestThreshold <= 0 {
		suggestThreshold = 0.55
	}

	report := WeeklyCalibrationReport{
		GeneratedAt: now,
		WindowDays:  windowDays,
		TrendDays:   trendDays,
		Profile:     opts.Profile,
	}
	if g == nil {
		return report
	}
	if engine == nil {
		engine = NewRiskEngine(g)
	}

	report.RiskFeedback = engine.OutcomeFeedback(time.Duration(windowDays)*24*time.Hour, opts.Profile)
	report.Identity = BuildIdentityCalibrationReport(g, IdentityCalibrationOptions{
		Now:              now,
		IncludeQueue:     opts.IncludeQueue,
		QueueLimit:       queueLimit,
		SuggestThreshold: suggestThreshold,
	})
	report.Ontology = BuildGraphOntologySLO(g, now, trendDays)
	return report
}
