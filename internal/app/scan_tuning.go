package app

import (
	"time"

	"github.com/evalops/cerebro/internal/scanner"
)

type ScanTuning struct {
	TableTimeout         time.Duration
	RetryOptions         scanner.RetryOptions
	MaxConcurrent        int
	MinConcurrent        int
	AdaptiveConcurrency  bool
	SlowTableThreshold   time.Duration
	FastTableThreshold   time.Duration
	ProfileSlowThreshold time.Duration
	GraphWaitTimeout     time.Duration
}

const (
	defaultScanTableTimeout  = 30 * time.Minute
	defaultScanMaxConcurrent = 6
	defaultScanMinConcurrent = 2
	defaultScanRetryJitter   = 0.2
	defaultScanSlowThreshold = 2 * time.Minute
	defaultScanFastThreshold = 30 * time.Second
	defaultScanProfileSlow   = time.Minute
	defaultScanGraphWait     = 2 * time.Minute
)

func (a *App) ScanTuning() ScanTuning {
	tuning := ScanTuning{
		TableTimeout:         defaultScanTableTimeout,
		RetryOptions:         scanner.DefaultRetryOptions(),
		MaxConcurrent:        defaultScanMaxConcurrent,
		MinConcurrent:        defaultScanMinConcurrent,
		AdaptiveConcurrency:  true,
		SlowTableThreshold:   defaultScanSlowThreshold,
		FastTableThreshold:   defaultScanFastThreshold,
		ProfileSlowThreshold: defaultScanProfileSlow,
		GraphWaitTimeout:     defaultScanGraphWait,
	}
	if a == nil || a.Config == nil {
		return tuning
	}

	cfg := a.Config
	if cfg.ScanTableTimeout > 0 {
		tuning.TableTimeout = cfg.ScanTableTimeout
	}
	if cfg.ScanMaxConcurrent > 0 {
		tuning.MaxConcurrent = cfg.ScanMaxConcurrent
	}
	if cfg.ScanMinConcurrent > 0 {
		tuning.MinConcurrent = cfg.ScanMinConcurrent
	}
	if tuning.MinConcurrent > tuning.MaxConcurrent {
		tuning.MinConcurrent = tuning.MaxConcurrent
	}
	if !cfg.ScanAdaptiveConcurrency {
		tuning.AdaptiveConcurrency = false
	}
	if cfg.ScanRetryAttempts > 0 {
		tuning.RetryOptions.Attempts = cfg.ScanRetryAttempts
	}
	if cfg.ScanRetryBackoff > 0 {
		tuning.RetryOptions.BaseDelay = cfg.ScanRetryBackoff
	}
	if cfg.ScanRetryMaxBackoff > 0 {
		tuning.RetryOptions.MaxDelay = cfg.ScanRetryMaxBackoff
	}
	if tuning.RetryOptions.Jitter <= 0 {
		tuning.RetryOptions.Jitter = defaultScanRetryJitter
	}

	return tuning
}
