package dspm

import (
	"context"
	"regexp"
	"strings"
	"sync"
)

// DataType represents a type of sensitive data
type DataType string

const (
	DataTypeSSN           DataType = "ssn"
	DataTypeEmail         DataType = "email"
	DataTypeCreditCard    DataType = "credit_card"
	DataTypePhoneNumber   DataType = "phone_number"
	DataTypeIPAddress     DataType = "ip_address"
	DataTypeAPIKey        DataType = "api_key"
	DataTypeAWSAccessKey  DataType = "aws_access_key"
	DataTypePrivateKey    DataType = "private_key"
	DataTypePassword      DataType = "password"
	DataTypeJWT           DataType = "jwt"
	DataTypeDateOfBirth   DataType = "date_of_birth"
	DataTypePassport      DataType = "passport"
	DataTypeDriverLicense DataType = "driver_license"
	DataTypeBankAccount   DataType = "bank_account"
	DataTypeHealthRecord  DataType = "health_record"
)

// DataClassification represents the classification level of data
type DataClassification string

const (
	ClassificationPublic       DataClassification = "public"
	ClassificationInternal     DataClassification = "internal"
	ClassificationConfidential DataClassification = "confidential"
	ClassificationRestricted   DataClassification = "restricted"
)

// ComplianceFramework represents a compliance framework
type ComplianceFramework string

const (
	FrameworkPCI   ComplianceFramework = "pci_dss"
	FrameworkHIPAA ComplianceFramework = "hipaa"
	FrameworkGDPR  ComplianceFramework = "gdpr"
	FrameworkSOC2  ComplianceFramework = "soc2"
	FrameworkCCPA  ComplianceFramework = "ccpa"
)

// ClassificationResult represents a classification finding
type ClassificationResult struct {
	DataType       DataType              `json:"data_type"`
	Confidence     float64               `json:"confidence"`
	MatchCount     int                   `json:"match_count"`
	SampleMatches  []string              `json:"sample_matches,omitempty"`
	LineNumbers    []int                 `json:"line_numbers,omitempty"`
	Classification DataClassification    `json:"classification"`
	Frameworks     []ComplianceFramework `json:"frameworks,omitempty"`
}

// Classifier interface for data classification
type Classifier interface {
	Classify(ctx context.Context, data []byte) []ClassificationResult
	SupportedTypes() []DataType
	Name() string
}

// PatternClassifier uses regex patterns to detect sensitive data
type PatternClassifier struct {
	patterns map[DataType]*patternConfig
	mu       sync.RWMutex
}

type patternConfig struct {
	regex          *regexp.Regexp
	classification DataClassification
	frameworks     []ComplianceFramework
	confidence     float64
	validator      func(string) bool
}

// NewPatternClassifier creates a new pattern-based classifier
func NewPatternClassifier() *PatternClassifier {
	pc := &PatternClassifier{
		patterns: make(map[DataType]*patternConfig),
	}
	pc.registerDefaultPatterns()
	return pc
}

func (pc *PatternClassifier) registerDefaultPatterns() {
	pc.patterns[DataTypeSSN] = &patternConfig{
		regex:          regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		classification: ClassificationRestricted,
		frameworks:     []ComplianceFramework{FrameworkGDPR, FrameworkCCPA, FrameworkSOC2},
		confidence:     0.95,
		validator:      validateSSN,
	}

	pc.patterns[DataTypeEmail] = &patternConfig{
		regex:          regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
		classification: ClassificationConfidential,
		frameworks:     []ComplianceFramework{FrameworkGDPR, FrameworkCCPA},
		confidence:     0.90,
	}

	pc.patterns[DataTypeCreditCard] = &patternConfig{
		regex:          regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b`),
		classification: ClassificationRestricted,
		frameworks:     []ComplianceFramework{FrameworkPCI},
		confidence:     0.85,
		validator:      validateCreditCard,
	}

	pc.patterns[DataTypePhoneNumber] = &patternConfig{
		regex:          regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`),
		classification: ClassificationConfidential,
		frameworks:     []ComplianceFramework{FrameworkGDPR, FrameworkCCPA},
		confidence:     0.80,
	}

	pc.patterns[DataTypeIPAddress] = &patternConfig{
		regex:          regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
		classification: ClassificationInternal,
		confidence:     0.95,
	}

	pc.patterns[DataTypeAWSAccessKey] = &patternConfig{
		regex:          regexp.MustCompile(`\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b`),
		classification: ClassificationRestricted,
		frameworks:     []ComplianceFramework{FrameworkSOC2},
		confidence:     0.99,
	}

	pc.patterns[DataTypePrivateKey] = &patternConfig{
		regex:          regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`),
		classification: ClassificationRestricted,
		frameworks:     []ComplianceFramework{FrameworkSOC2},
		confidence:     0.99,
	}

	pc.patterns[DataTypeJWT] = &patternConfig{
		regex:          regexp.MustCompile(`\beyJ[A-Za-z0-9-_]*\.eyJ[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\b`),
		classification: ClassificationRestricted,
		confidence:     0.95,
	}

	pc.patterns[DataTypeAPIKey] = &patternConfig{
		regex:          regexp.MustCompile(`\b(?:api[_-]?key|apikey|api[_-]?secret)["\s:=]+["']?([A-Za-z0-9_-]{20,64})["']?\b`),
		classification: ClassificationRestricted,
		frameworks:     []ComplianceFramework{FrameworkSOC2},
		confidence:     0.85,
	}

	pc.patterns[DataTypePassword] = &patternConfig{
		regex:          regexp.MustCompile(`(?i)(?:password|passwd|pwd)["\s:=]+["']?([^\s"']{8,64})["']?`),
		classification: ClassificationRestricted,
		confidence:     0.80,
	}

	pc.patterns[DataTypeDateOfBirth] = &patternConfig{
		regex:          regexp.MustCompile(`\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12][0-9]|3[01])[/-](?:19|20)\d{2}\b`),
		classification: ClassificationConfidential,
		frameworks:     []ComplianceFramework{FrameworkGDPR, FrameworkHIPAA},
		confidence:     0.75,
	}

	pc.patterns[DataTypePassport] = &patternConfig{
		regex:          regexp.MustCompile(`\b[A-Z]{1,2}[0-9]{6,9}\b`),
		classification: ClassificationRestricted,
		frameworks:     []ComplianceFramework{FrameworkGDPR},
		confidence:     0.70,
	}

	pc.patterns[DataTypeBankAccount] = &patternConfig{
		regex:          regexp.MustCompile(`\b[0-9]{8,17}\b`),
		classification: ClassificationRestricted,
		frameworks:     []ComplianceFramework{FrameworkPCI, FrameworkSOC2},
		confidence:     0.60,
		validator:      validateBankAccount,
	}

	pc.patterns[DataTypeHealthRecord] = &patternConfig{
		regex:          regexp.MustCompile(`(?i)\b(?:diagnosis|prescription|medical|patient|health|icd-?10|cpt|ndc|drg|medication|treatment|symptom|allergies|immunization)\b`),
		classification: ClassificationRestricted,
		frameworks:     []ComplianceFramework{FrameworkHIPAA},
		confidence:     0.70,
	}
}

// Classify analyzes data and returns classification results
func (pc *PatternClassifier) Classify(ctx context.Context, data []byte) []ClassificationResult {
	var results []ClassificationResult
	content := string(data)
	lines := strings.Split(content, "\n")

	pc.mu.RLock()
	defer pc.mu.RUnlock()

	for dataType, config := range pc.patterns {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		matches := config.regex.FindAllString(content, -1)
		if len(matches) == 0 {
			continue
		}

		validMatches := matches
		if config.validator != nil {
			validMatches = make([]string, 0, len(matches))
			for _, m := range matches {
				if config.validator(m) {
					validMatches = append(validMatches, m)
				}
			}
		}

		if len(validMatches) == 0 {
			continue
		}

		lineNums := findLineNumbers(lines, validMatches)

		sampleMatches := validMatches
		if len(sampleMatches) > 5 {
			sampleMatches = sampleMatches[:5]
		}
		for i := range sampleMatches {
			sampleMatches[i] = maskSensitiveData(sampleMatches[i], dataType)
		}

		results = append(results, ClassificationResult{
			DataType:       dataType,
			Confidence:     config.confidence,
			MatchCount:     len(validMatches),
			SampleMatches:  sampleMatches,
			LineNumbers:    lineNums,
			Classification: config.classification,
			Frameworks:     config.frameworks,
		})
	}

	return results
}

// SupportedTypes returns all supported data types
func (pc *PatternClassifier) SupportedTypes() []DataType {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	types := make([]DataType, 0, len(pc.patterns))
	for t := range pc.patterns {
		types = append(types, t)
	}
	return types
}

// Name returns the classifier name
func (pc *PatternClassifier) Name() string {
	return "pattern_classifier"
}

func findLineNumbers(lines []string, matches []string) []int {
	lineNums := make([]int, 0)
	matchSet := make(map[string]bool)
	for _, m := range matches {
		matchSet[m] = true
	}

	for i, line := range lines {
		for m := range matchSet {
			if strings.Contains(line, m) {
				lineNums = append(lineNums, i+1)
				break
			}
		}
		if len(lineNums) >= 10 {
			break
		}
	}
	return lineNums
}

func maskSensitiveData(data string, dataType DataType) string {
	if len(data) <= 4 {
		return "****"
	}

	switch dataType {
	case DataTypeSSN:
		return "***-**-" + data[len(data)-4:]
	case DataTypeCreditCard:
		return "****-****-****-" + data[len(data)-4:]
	case DataTypeEmail:
		atIdx := strings.Index(data, "@")
		if atIdx > 2 {
			return data[:2] + "***" + data[atIdx:]
		}
		return "***" + data[atIdx:]
	case DataTypeAWSAccessKey, DataTypeAPIKey, DataTypeJWT:
		return data[:4] + "****" + data[len(data)-4:]
	case DataTypePrivateKey:
		return "-----BEGIN ***PRIVATE KEY-----"
	case DataTypePassword:
		return "********"
	default:
		return data[:2] + "****" + data[len(data)-2:]
	}
}

func validateSSN(ssn string) bool {
	ssn = strings.ReplaceAll(ssn, "-", "")
	if len(ssn) != 9 {
		return false
	}
	if ssn[:3] == "000" || ssn[:3] == "666" || ssn[:3] >= "900" {
		return false
	}
	if ssn[3:5] == "00" || ssn[5:] == "0000" {
		return false
	}
	return true
}

func validateCreditCard(cc string) bool {
	cc = strings.ReplaceAll(cc, "-", "")
	cc = strings.ReplaceAll(cc, " ", "")
	if len(cc) < 13 || len(cc) > 19 {
		return false
	}
	for _, c := range cc {
		if c < '0' || c > '9' {
			return false
		}
	}
	return luhnCheck(cc)
}

func luhnCheck(number string) bool {
	var sum int
	alternate := false
	for i := len(number) - 1; i >= 0; i-- {
		n := int(number[i] - '0')
		if alternate {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alternate = !alternate
	}
	return sum%10 == 0
}

func validateBankAccount(account string) bool {
	account = strings.ReplaceAll(account, "-", "")
	account = strings.ReplaceAll(account, " ", "")
	if len(account) < 8 || len(account) > 17 {
		return false
	}
	for _, c := range account {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
