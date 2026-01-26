package dspm

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// ScanTarget represents a data store to scan
type ScanTarget struct {
	ID           string            `json:"id"`
	Type         string            `json:"type"`
	Provider     string            `json:"provider"`
	Account      string            `json:"account"`
	Region       string            `json:"region"`
	Name         string            `json:"name"`
	ARN          string            `json:"arn,omitempty"`
	Properties   map[string]any    `json:"properties,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	IsPublic     bool              `json:"is_public"`
	IsEncrypted  bool              `json:"is_encrypted"`
	LastModified time.Time         `json:"last_modified,omitempty"`
}

// ScanResult represents the result of scanning a data store
type ScanResult struct {
	TargetID        string                 `json:"target_id"`
	TargetType      string                 `json:"target_type"`
	TargetName      string                 `json:"target_name"`
	Provider        string                 `json:"provider"`
	ScanStartTime   time.Time              `json:"scan_start_time"`
	ScanEndTime     time.Time              `json:"scan_end_time"`
	SampleSize      int64                  `json:"sample_size"`
	ObjectsScanned  int                    `json:"objects_scanned"`
	Findings        []SensitiveDataFinding `json:"findings"`
	Classification  DataClassification     `json:"classification"`
	RiskScore       float64                `json:"risk_score"`
	ComplianceGaps  []ComplianceGap        `json:"compliance_gaps,omitempty"`
	Error           string                 `json:"error,omitempty"`
	Recommendations []string               `json:"recommendations,omitempty"`
}

// SensitiveDataFinding represents a finding of sensitive data
type SensitiveDataFinding struct {
	DataType       DataType              `json:"data_type"`
	Classification DataClassification    `json:"classification"`
	Confidence     float64               `json:"confidence"`
	MatchCount     int                   `json:"match_count"`
	Locations      []DataLocation        `json:"locations,omitempty"`
	Frameworks     []ComplianceFramework `json:"frameworks,omitempty"`
	Risk           string                `json:"risk"`
}

// DataLocation represents where sensitive data was found
type DataLocation struct {
	ObjectKey   string `json:"object_key,omitempty"`
	Path        string `json:"path,omitempty"`
	LineNumber  int    `json:"line_number,omitempty"`
	ColumnName  string `json:"column_name,omitempty"`
	TableName   string `json:"table_name,omitempty"`
	SampleValue string `json:"sample_value,omitempty"`
}

// ComplianceGap represents a compliance requirement gap
type ComplianceGap struct {
	Framework   ComplianceFramework `json:"framework"`
	Requirement string              `json:"requirement"`
	Description string              `json:"description"`
	Severity    string              `json:"severity"`
}

// DataFetcher interface for fetching data samples from cloud storage
type DataFetcher interface {
	FetchSample(ctx context.Context, target *ScanTarget, maxBytes int64) ([]DataSample, error)
	ListObjects(ctx context.Context, target *ScanTarget, maxObjects int) ([]ObjectInfo, error)
}

// DataSample represents a sample of data from a data store
type DataSample struct {
	ObjectKey    string    `json:"object_key,omitempty"`
	Path         string    `json:"path,omitempty"`
	ContentType  string    `json:"content_type,omitempty"`
	Size         int64     `json:"size"`
	Data         []byte    `json:"-"`
	LastModified time.Time `json:"last_modified,omitempty"`
}

// ObjectInfo represents metadata about an object in a data store
type ObjectInfo struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	ContentType  string    `json:"content_type,omitempty"`
	LastModified time.Time `json:"last_modified,omitempty"`
}

// Scanner performs DSPM scanning
type Scanner struct {
	classifiers []Classifier
	fetcher     DataFetcher
	logger      *slog.Logger
	config      ScannerConfig
	mu          sync.RWMutex
}

// ScannerConfig configures the scanner behavior
type ScannerConfig struct {
	MaxSampleSize    int64 `json:"max_sample_size"`
	MaxObjectsToScan int   `json:"max_objects_to_scan"`
	SamplePercentage int   `json:"sample_percentage"`
	TimeoutPerTarget time.Duration
	Concurrency      int
}

// DefaultScannerConfig returns sensible defaults
func DefaultScannerConfig() ScannerConfig {
	return ScannerConfig{
		MaxSampleSize:    10 * 1024 * 1024,
		MaxObjectsToScan: 100,
		SamplePercentage: 10,
		TimeoutPerTarget: 5 * time.Minute,
		Concurrency:      5,
	}
}

// NewScanner creates a new DSPM scanner
func NewScanner(fetcher DataFetcher, logger *slog.Logger, config ScannerConfig) *Scanner {
	if logger == nil {
		logger = slog.Default()
	}
	return &Scanner{
		classifiers: []Classifier{NewPatternClassifier()},
		fetcher:     fetcher,
		logger:      logger,
		config:      config,
	}
}

// AddClassifier adds a custom classifier
func (s *Scanner) AddClassifier(c Classifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.classifiers = append(s.classifiers, c)
}

// Scan performs a DSPM scan on the target
func (s *Scanner) Scan(ctx context.Context, target *ScanTarget) (*ScanResult, error) {
	startTime := time.Now()

	result := &ScanResult{
		TargetID:       target.ID,
		TargetType:     target.Type,
		TargetName:     target.Name,
		Provider:       target.Provider,
		ScanStartTime:  startTime,
		Classification: ClassificationPublic,
	}

	ctx, cancel := context.WithTimeout(ctx, s.config.TimeoutPerTarget)
	defer cancel()

	s.logger.Info("starting DSPM scan",
		"target_id", target.ID,
		"target_type", target.Type,
		"provider", target.Provider,
	)

	if s.fetcher == nil {
		result.Error = "no data fetcher configured"
		result.ScanEndTime = time.Now()
		return result, fmt.Errorf("no data fetcher configured")
	}

	samples, err := s.fetcher.FetchSample(ctx, target, s.config.MaxSampleSize)
	if err != nil {
		result.Error = "failed to fetch data samples"
		result.ScanEndTime = time.Now()
		s.logger.Error("DSPM fetch failed",
			"target_id", target.ID,
			"error", err,
		)
		return result, fmt.Errorf("fetch samples: %w", err)
	}

	result.ObjectsScanned = len(samples)
	for _, sample := range samples {
		result.SampleSize += sample.Size
	}

	findingsMap := make(map[DataType]*SensitiveDataFinding)

	s.mu.RLock()
	classifiers := s.classifiers
	s.mu.RUnlock()

	for _, sample := range samples {
		select {
		case <-ctx.Done():
			result.Error = "scan timeout"
			result.ScanEndTime = time.Now()
			return result, ctx.Err()
		default:
		}

		for _, classifier := range classifiers {
			classifications := classifier.Classify(ctx, sample.Data)

			for _, c := range classifications {
				if existing, ok := findingsMap[c.DataType]; ok {
					existing.MatchCount += c.MatchCount
					existing.Locations = append(existing.Locations, DataLocation{
						ObjectKey:   sample.ObjectKey,
						Path:        sample.Path,
						SampleValue: strings.Join(c.SampleMatches, ", "),
					})
				} else {
					findingsMap[c.DataType] = &SensitiveDataFinding{
						DataType:       c.DataType,
						Classification: c.Classification,
						Confidence:     c.Confidence,
						MatchCount:     c.MatchCount,
						Frameworks:     c.Frameworks,
						Risk:           classificationToRisk(c.Classification),
						Locations: []DataLocation{{
							ObjectKey:   sample.ObjectKey,
							Path:        sample.Path,
							SampleValue: strings.Join(c.SampleMatches, ", "),
						}},
					}
				}
			}
		}
	}

	for _, finding := range findingsMap {
		result.Findings = append(result.Findings, *finding)
		if finding.Classification > result.Classification {
			result.Classification = finding.Classification
		}
	}

	result.RiskScore = s.calculateRiskScore(target, result)
	result.ComplianceGaps = s.identifyComplianceGaps(target, result)
	result.Recommendations = s.generateRecommendations(target, result)
	result.ScanEndTime = time.Now()

	s.logger.Info("DSPM scan completed",
		"target_id", target.ID,
		"findings_count", len(result.Findings),
		"classification", result.Classification,
		"risk_score", result.RiskScore,
		"duration_ms", result.ScanEndTime.Sub(result.ScanStartTime).Milliseconds(),
	)

	return result, nil
}

// ScanBatch scans multiple targets concurrently
func (s *Scanner) ScanBatch(ctx context.Context, targets []*ScanTarget) ([]*ScanResult, error) {
	results := make([]*ScanResult, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Concurrency)

	for i, target := range targets {
		wg.Add(1)
		go func(idx int, t *ScanTarget) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			result, err := s.Scan(ctx, t)
			if err != nil {
				s.logger.Error("scan failed",
					"target_id", t.ID,
					"error", err,
				)
			}
			results[idx] = result
		}(i, target)
	}

	wg.Wait()
	return results, nil
}

func (s *Scanner) calculateRiskScore(target *ScanTarget, result *ScanResult) float64 {
	var score float64

	for _, finding := range result.Findings {
		switch finding.Classification {
		case ClassificationRestricted:
			score += 40.0
		case ClassificationConfidential:
			score += 25.0
		case ClassificationInternal:
			score += 10.0
		}
		score += finding.Confidence * 5.0
	}

	if target.IsPublic {
		score *= 2.0
	}

	if !target.IsEncrypted {
		score *= 1.5
	}

	if score > 100 {
		score = 100
	}

	return score
}

func (s *Scanner) identifyComplianceGaps(target *ScanTarget, result *ScanResult) []ComplianceGap {
	var gaps []ComplianceGap
	frameworksAffected := make(map[ComplianceFramework]bool)

	for _, finding := range result.Findings {
		for _, fw := range finding.Frameworks {
			frameworksAffected[fw] = true
		}
	}

	if frameworksAffected[FrameworkPCI] {
		if target.IsPublic {
			gaps = append(gaps, ComplianceGap{
				Framework:   FrameworkPCI,
				Requirement: "PCI DSS 3.4",
				Description: "Cardholder data found in publicly accessible storage",
				Severity:    "critical",
			})
		}
		if !target.IsEncrypted {
			gaps = append(gaps, ComplianceGap{
				Framework:   FrameworkPCI,
				Requirement: "PCI DSS 3.4",
				Description: "Cardholder data stored without encryption",
				Severity:    "critical",
			})
		}
	}

	if frameworksAffected[FrameworkHIPAA] {
		if target.IsPublic {
			gaps = append(gaps, ComplianceGap{
				Framework:   FrameworkHIPAA,
				Requirement: "164.312(e)(1)",
				Description: "PHI found in publicly accessible storage",
				Severity:    "critical",
			})
		}
		if !target.IsEncrypted {
			gaps = append(gaps, ComplianceGap{
				Framework:   FrameworkHIPAA,
				Requirement: "164.312(a)(2)(iv)",
				Description: "PHI stored without encryption at rest",
				Severity:    "high",
			})
		}
	}

	if frameworksAffected[FrameworkGDPR] {
		if target.IsPublic {
			gaps = append(gaps, ComplianceGap{
				Framework:   FrameworkGDPR,
				Requirement: "Article 32",
				Description: "Personal data exposed via public access",
				Severity:    "critical",
			})
		}
	}

	return gaps
}

func (s *Scanner) generateRecommendations(target *ScanTarget, result *ScanResult) []string {
	var recommendations []string

	if target.IsPublic && len(result.Findings) > 0 {
		recommendations = append(recommendations,
			"Remove public access from this data store immediately - sensitive data detected")
	}

	if !target.IsEncrypted && len(result.Findings) > 0 {
		recommendations = append(recommendations,
			"Enable encryption at rest for this data store")
	}

	for _, finding := range result.Findings {
		switch finding.DataType {
		case DataTypeAWSAccessKey, DataTypePrivateKey, DataTypeAPIKey:
			recommendations = append(recommendations,
				fmt.Sprintf("Rotate exposed %s credentials and remove from data store", finding.DataType))
		case DataTypeCreditCard:
			recommendations = append(recommendations,
				"Implement PCI-compliant tokenization for cardholder data")
		case DataTypeSSN:
			recommendations = append(recommendations,
				"Apply data masking or tokenization for SSN data")
		case DataTypeHealthRecord:
			recommendations = append(recommendations,
				"Review HIPAA compliance requirements for PHI storage")
		}
	}

	if len(result.Findings) > 5 {
		recommendations = append(recommendations,
			"Consider implementing a data loss prevention (DLP) solution")
	}

	return recommendations
}

func classificationToRisk(c DataClassification) string {
	switch c {
	case ClassificationRestricted:
		return "critical"
	case ClassificationConfidential:
		return "high"
	case ClassificationInternal:
		return "medium"
	default:
		return "low"
	}
}

// EnrichGraphNode returns properties to add to a graph node based on scan results
func (s *Scanner) EnrichGraphNode(result *ScanResult) map[string]any {
	props := make(map[string]any)

	if result == nil || len(result.Findings) == 0 {
		props["dspm_scanned"] = true
		props["contains_sensitive_data"] = false
		return props
	}

	props["dspm_scanned"] = true
	props["contains_sensitive_data"] = true
	props["data_classification"] = string(result.Classification)
	props["dspm_risk_score"] = result.RiskScore

	dataTypes := make([]string, 0, len(result.Findings))
	for _, f := range result.Findings {
		dataTypes = append(dataTypes, string(f.DataType))
	}
	props["sensitive_data_types"] = dataTypes

	frameworks := make(map[ComplianceFramework]bool)
	for _, f := range result.Findings {
		for _, fw := range f.Frameworks {
			frameworks[fw] = true
		}
	}
	fwList := make([]string, 0, len(frameworks))
	for fw := range frameworks {
		fwList = append(fwList, string(fw))
	}
	props["compliance_frameworks"] = fwList

	containsPII := false
	containsPHI := false
	containsPCI := false
	containsSecrets := false

	for _, f := range result.Findings {
		switch f.DataType {
		case DataTypeSSN, DataTypeEmail, DataTypeDateOfBirth, DataTypePassport, DataTypeDriverLicense:
			containsPII = true
		case DataTypeHealthRecord:
			containsPHI = true
		case DataTypeCreditCard, DataTypeBankAccount:
			containsPCI = true
		case DataTypeAWSAccessKey, DataTypePrivateKey, DataTypeAPIKey, DataTypePassword, DataTypeJWT:
			containsSecrets = true
		}
	}

	props["contains_pii"] = containsPII
	props["contains_phi"] = containsPHI
	props["contains_pci"] = containsPCI
	props["contains_secrets"] = containsSecrets

	return props
}
