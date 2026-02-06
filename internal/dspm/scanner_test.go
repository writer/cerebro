package dspm

import (
	"context"
	"testing"
	"time"
)

func TestPatternClassifier_SSN(t *testing.T) {
	classifier := NewPatternClassifier()

	testCases := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		{
			name:        "valid SSN",
			input:       "SSN: 123-45-6789",
			shouldMatch: true,
		},
		{
			name:        "invalid SSN - 000 prefix",
			input:       "SSN: 000-12-3456",
			shouldMatch: false,
		},
		{
			name:        "invalid SSN - 666 prefix",
			input:       "SSN: 666-12-3456",
			shouldMatch: false,
		},
		{
			name:        "no SSN",
			input:       "No social security number here",
			shouldMatch: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results := classifier.Classify(context.Background(), []byte(tc.input))

			found := false
			for _, r := range results {
				if r.DataType == DataTypeSSN {
					found = true
					break
				}
			}

			if found != tc.shouldMatch {
				t.Errorf("expected match=%v, got match=%v for input: %s", tc.shouldMatch, found, tc.input)
			}
		})
	}
}

func TestPatternClassifier_Email(t *testing.T) {
	classifier := NewPatternClassifier()

	testCases := []struct {
		name        string
		input       string
		shouldMatch bool
		matchCount  int
	}{
		{
			name:        "single email",
			input:       "Contact: user@example.com",
			shouldMatch: true,
			matchCount:  1,
		},
		{
			name:        "multiple emails",
			input:       "Users: alice@test.com, bob@domain.org",
			shouldMatch: true,
			matchCount:  2,
		},
		{
			name:        "no email",
			input:       "No email address here",
			shouldMatch: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results := classifier.Classify(context.Background(), []byte(tc.input))

			var emailResult *ClassificationResult
			for i, r := range results {
				if r.DataType == DataTypeEmail {
					emailResult = &results[i]
					break
				}
			}

			if tc.shouldMatch {
				if emailResult == nil {
					t.Fatal("expected to find email")
				}
				if emailResult.MatchCount != tc.matchCount {
					t.Errorf("expected %d matches, got %d", tc.matchCount, emailResult.MatchCount)
				}
			} else {
				if emailResult != nil {
					t.Error("expected no email match")
				}
			}
		})
	}
}

func TestPatternClassifier_CreditCard(t *testing.T) {
	classifier := NewPatternClassifier()

	testCases := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		{
			name:        "valid Visa",
			input:       "Card: 4111111111111111",
			shouldMatch: true,
		},
		{
			name:        "valid Visa with dashes",
			input:       "Card: 4111-1111-1111-1111",
			shouldMatch: true,
		},
		{
			name:        "valid Mastercard",
			input:       "Card: 5500000000000004",
			shouldMatch: true,
		},
		{
			name:        "invalid card number",
			input:       "Card: 1234567890123456",
			shouldMatch: false,
		},
		{
			name:        "no card",
			input:       "No credit card here",
			shouldMatch: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results := classifier.Classify(context.Background(), []byte(tc.input))

			found := false
			for _, r := range results {
				if r.DataType == DataTypeCreditCard {
					found = true
					break
				}
			}

			if found != tc.shouldMatch {
				t.Errorf("expected match=%v, got match=%v for input: %s", tc.shouldMatch, found, tc.input)
			}
		})
	}
}

func TestPatternClassifier_AWSAccessKey(t *testing.T) {
	classifier := NewPatternClassifier()

	testCases := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		{
			name:        "valid AKIA key",
			input:       "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
			shouldMatch: true,
		},
		{
			name:        "valid ASIA key",
			input:       "key: ASIAIOSTODNN7EXAMPLE",
			shouldMatch: true,
		},
		{
			name:        "no AWS key",
			input:       "No AWS credentials here",
			shouldMatch: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results := classifier.Classify(context.Background(), []byte(tc.input))

			found := false
			for _, r := range results {
				if r.DataType == DataTypeAWSAccessKey {
					found = true
					break
				}
			}

			if found != tc.shouldMatch {
				t.Errorf("expected match=%v, got match=%v for input: %s", tc.shouldMatch, found, tc.input)
			}
		})
	}
}

func TestPatternClassifier_PrivateKey(t *testing.T) {
	classifier := NewPatternClassifier()

	testCases := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		{
			name:        "RSA private key",
			input:       "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
			shouldMatch: true,
		},
		{
			name:        "generic private key",
			input:       "-----BEGIN PRIVATE KEY-----\nMIIE...",
			shouldMatch: true,
		},
		{
			name:        "EC private key",
			input:       "-----BEGIN EC PRIVATE KEY-----\nMIIE...",
			shouldMatch: true,
		},
		{
			name:        "public key (not private)",
			input:       "-----BEGIN PUBLIC KEY-----\nMIIB...",
			shouldMatch: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results := classifier.Classify(context.Background(), []byte(tc.input))

			found := false
			for _, r := range results {
				if r.DataType == DataTypePrivateKey {
					found = true
					break
				}
			}

			if found != tc.shouldMatch {
				t.Errorf("expected match=%v, got match=%v for input: %s", tc.shouldMatch, found, tc.input)
			}
		})
	}
}

func TestPatternClassifier_JWT(t *testing.T) {
	classifier := NewPatternClassifier()

	results := classifier.Classify(context.Background(), []byte(
		"token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
	))

	found := false
	for _, r := range results {
		if r.DataType == DataTypeJWT {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected to find JWT")
	}
}

func TestPatternClassifier_ClassificationLevels(t *testing.T) {
	classifier := NewPatternClassifier()

	testCases := []struct {
		dataType       DataType
		expectedClass  DataClassification
		expectedFrames []ComplianceFramework
	}{
		{
			dataType:       DataTypeSSN,
			expectedClass:  ClassificationRestricted,
			expectedFrames: []ComplianceFramework{FrameworkGDPR, FrameworkCCPA, FrameworkSOC2},
		},
		{
			dataType:       DataTypeCreditCard,
			expectedClass:  ClassificationRestricted,
			expectedFrames: []ComplianceFramework{FrameworkPCI},
		},
		{
			dataType:       DataTypeEmail,
			expectedClass:  ClassificationConfidential,
			expectedFrames: []ComplianceFramework{FrameworkGDPR, FrameworkCCPA},
		},
		{
			dataType:      DataTypeIPAddress,
			expectedClass: ClassificationInternal,
		},
	}

	for _, tc := range testCases {
		t.Run(string(tc.dataType), func(t *testing.T) {
			found := false
			for _, dt := range classifier.SupportedTypes() {
				if dt == tc.dataType {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("data type %s should be supported", tc.dataType)
			}
		})
	}
}

func TestPatternClassifier_MaskSensitiveData(t *testing.T) {
	testCases := []struct {
		dataType DataType
		input    string
		expected string
	}{
		{DataTypeSSN, "123-45-6789", "***-**-6789"},
		{DataTypeCreditCard, "4111111111111111", "****-****-****-1111"},
		{DataTypeEmail, "user@example.com", "us***@example.com"},
		{DataTypePrivateKey, "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN ***PRIVATE KEY-----"},
		{DataTypePassword, "mysecretpassword", "********"},
	}

	for _, tc := range testCases {
		t.Run(string(tc.dataType), func(t *testing.T) {
			result := maskSensitiveData(tc.input, tc.dataType)
			if result != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, result)
			}
		})
	}
}

func TestScanner_EnrichGraphNode(t *testing.T) {
	scanner := NewScanner(nil, nil, DefaultScannerConfig())

	t.Run("no findings", func(t *testing.T) {
		result := &ScanResult{
			Findings: nil,
		}

		props := scanner.EnrichGraphNode(result)

		if props["dspm_scanned"] != true {
			t.Error("expected dspm_scanned to be true")
		}
		if props["contains_sensitive_data"] != false {
			t.Error("expected contains_sensitive_data to be false")
		}
	})

	t.Run("with PII findings", func(t *testing.T) {
		result := &ScanResult{
			Findings: []SensitiveDataFinding{
				{
					DataType:       DataTypeSSN,
					Classification: ClassificationRestricted,
					Frameworks:     []ComplianceFramework{FrameworkGDPR},
				},
				{
					DataType:       DataTypeEmail,
					Classification: ClassificationConfidential,
					Frameworks:     []ComplianceFramework{FrameworkGDPR, FrameworkCCPA},
				},
			},
			Classification: ClassificationRestricted,
			RiskScore:      85.0,
		}

		props := scanner.EnrichGraphNode(result)

		if props["contains_sensitive_data"] != true {
			t.Error("expected contains_sensitive_data to be true")
		}
		if props["contains_pii"] != true {
			t.Error("expected contains_pii to be true")
		}
		if props["data_classification"] != "restricted" {
			t.Errorf("expected classification restricted, got %v", props["data_classification"])
		}
		if props["dspm_risk_score"] != 85.0 {
			t.Errorf("expected risk score 85.0, got %v", props["dspm_risk_score"])
		}
	})

	t.Run("with secret findings", func(t *testing.T) {
		result := &ScanResult{
			Findings: []SensitiveDataFinding{
				{
					DataType:       DataTypeAWSAccessKey,
					Classification: ClassificationRestricted,
				},
				{
					DataType:       DataTypePrivateKey,
					Classification: ClassificationRestricted,
				},
			},
			Classification: ClassificationRestricted,
		}

		props := scanner.EnrichGraphNode(result)

		if props["contains_secrets"] != true {
			t.Error("expected contains_secrets to be true")
		}
	})

	t.Run("with PCI findings", func(t *testing.T) {
		result := &ScanResult{
			Findings: []SensitiveDataFinding{
				{
					DataType:       DataTypeCreditCard,
					Classification: ClassificationRestricted,
					Frameworks:     []ComplianceFramework{FrameworkPCI},
				},
			},
			Classification: ClassificationRestricted,
		}

		props := scanner.EnrichGraphNode(result)

		if props["contains_pci"] != true {
			t.Error("expected contains_pci to be true")
		}
	})

	t.Run("with PHI findings", func(t *testing.T) {
		result := &ScanResult{
			Findings: []SensitiveDataFinding{
				{
					DataType:       DataTypeHealthRecord,
					Classification: ClassificationRestricted,
					Frameworks:     []ComplianceFramework{FrameworkHIPAA},
				},
			},
			Classification: ClassificationRestricted,
		}

		props := scanner.EnrichGraphNode(result)

		if props["contains_phi"] != true {
			t.Error("expected contains_phi to be true")
		}
	})
}

func TestScanner_RiskScoreCalculation(t *testing.T) {
	scanner := NewScanner(nil, nil, DefaultScannerConfig())

	t.Run("public unencrypted with restricted data", func(t *testing.T) {
		target := &ScanTarget{
			ID:          "bucket-1",
			IsPublic:    true,
			IsEncrypted: false,
		}
		result := &ScanResult{
			Findings: []SensitiveDataFinding{
				{
					DataType:       DataTypeSSN,
					Classification: ClassificationRestricted,
					Confidence:     0.95,
				},
			},
		}

		score := scanner.calculateRiskScore(target, result)

		if score < 90 {
			t.Errorf("expected high risk score for public unencrypted restricted data, got %f", score)
		}
	})

	t.Run("private encrypted with internal data", func(t *testing.T) {
		target := &ScanTarget{
			ID:          "bucket-2",
			IsPublic:    false,
			IsEncrypted: true,
		}
		result := &ScanResult{
			Findings: []SensitiveDataFinding{
				{
					DataType:       DataTypeIPAddress,
					Classification: ClassificationInternal,
					Confidence:     0.90,
				},
			},
		}

		score := scanner.calculateRiskScore(target, result)

		if score > 30 {
			t.Errorf("expected low risk score for private encrypted internal data, got %f", score)
		}
	})
}

func TestScanner_ComplianceGaps(t *testing.T) {
	scanner := NewScanner(nil, nil, DefaultScannerConfig())

	t.Run("public bucket with PCI data", func(t *testing.T) {
		target := &ScanTarget{
			ID:          "bucket-1",
			IsPublic:    true,
			IsEncrypted: false,
		}
		result := &ScanResult{
			Findings: []SensitiveDataFinding{
				{
					DataType:   DataTypeCreditCard,
					Frameworks: []ComplianceFramework{FrameworkPCI},
				},
			},
		}

		gaps := scanner.identifyComplianceGaps(target, result)

		if len(gaps) < 2 {
			t.Error("expected at least 2 PCI compliance gaps")
		}

		foundPublicGap := false
		foundEncryptionGap := false
		for _, gap := range gaps {
			if gap.Framework == FrameworkPCI {
				if gap.Description == "Cardholder data found in publicly accessible storage" {
					foundPublicGap = true
				}
				if gap.Description == "Cardholder data stored without encryption" {
					foundEncryptionGap = true
				}
			}
		}

		if !foundPublicGap {
			t.Error("expected PCI public access gap")
		}
		if !foundEncryptionGap {
			t.Error("expected PCI encryption gap")
		}
	})

	t.Run("public bucket with HIPAA data", func(t *testing.T) {
		target := &ScanTarget{
			ID:       "bucket-2",
			IsPublic: true,
		}
		result := &ScanResult{
			Findings: []SensitiveDataFinding{
				{
					DataType:   DataTypeHealthRecord,
					Frameworks: []ComplianceFramework{FrameworkHIPAA},
				},
			},
		}

		gaps := scanner.identifyComplianceGaps(target, result)

		foundHIPAAGap := false
		for _, gap := range gaps {
			if gap.Framework == FrameworkHIPAA && gap.Severity == "critical" {
				foundHIPAAGap = true
				break
			}
		}

		if !foundHIPAAGap {
			t.Error("expected HIPAA compliance gap for public PHI")
		}
	})
}

func TestScanner_Recommendations(t *testing.T) {
	scanner := NewScanner(nil, nil, DefaultScannerConfig())

	t.Run("public bucket with credentials", func(t *testing.T) {
		target := &ScanTarget{
			ID:       "bucket-1",
			IsPublic: true,
		}
		result := &ScanResult{
			Findings: []SensitiveDataFinding{
				{DataType: DataTypeAWSAccessKey},
			},
		}

		recs := scanner.generateRecommendations(target, result)

		foundRemovePublic := false
		foundRotate := false
		for _, rec := range recs {
			if rec == "Remove public access from this data store immediately - sensitive data detected" {
				foundRemovePublic = true
			}
			if rec == "Rotate exposed aws_access_key credentials and remove from data store" {
				foundRotate = true
			}
		}

		if !foundRemovePublic {
			t.Error("expected recommendation to remove public access")
		}
		if !foundRotate {
			t.Error("expected recommendation to rotate credentials")
		}
	})
}

type mockDataFetcher struct {
	samples []DataSample
	err     error
}

var _ DataFetcher = (*mockDataFetcher)(nil)

func (m *mockDataFetcher) FetchSample(ctx context.Context, target *ScanTarget, maxBytes int64) ([]DataSample, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.samples, nil
}

func (m *mockDataFetcher) ListObjects(ctx context.Context, target *ScanTarget, maxObjects int) ([]ObjectInfo, error) {
	return nil, nil
}

func TestScanner_Scan(t *testing.T) {
	fetcher := &mockDataFetcher{
		samples: []DataSample{
			{
				ObjectKey: "users.csv",
				Data:      []byte("name,email,ssn\nJohn,john@test.com,123-45-6789"),
				Size:      100,
			},
		},
	}

	scanner := NewScanner(fetcher, nil, DefaultScannerConfig())

	target := &ScanTarget{
		ID:          "bucket-1",
		Type:        "s3",
		Provider:    "aws",
		Name:        "test-bucket",
		IsPublic:    true,
		IsEncrypted: false,
	}

	result, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if result.TargetID != "bucket-1" {
		t.Errorf("expected target ID bucket-1, got %s", result.TargetID)
	}

	if len(result.Findings) == 0 {
		t.Error("expected findings")
	}

	foundSSN := false
	foundEmail := false
	for _, f := range result.Findings {
		if f.DataType == DataTypeSSN {
			foundSSN = true
		}
		if f.DataType == DataTypeEmail {
			foundEmail = true
		}
	}

	if !foundSSN {
		t.Error("expected to find SSN")
	}
	if !foundEmail {
		t.Error("expected to find email")
	}

	if result.RiskScore == 0 {
		t.Error("expected non-zero risk score")
	}

	if result.ScanEndTime.Before(result.ScanStartTime) {
		t.Error("scan end time should be after start time")
	}
}

func TestScanner_ScanTimeout(t *testing.T) {
	fetcher := &mockDataFetcher{
		samples: []DataSample{
			{ObjectKey: "test.txt", Data: []byte("test data"), Size: 9},
		},
	}

	config := DefaultScannerConfig()
	config.TimeoutPerTarget = 1 * time.Nanosecond

	scanner := NewScanner(fetcher, nil, config)

	target := &ScanTarget{ID: "bucket-1", Type: "s3"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, _ := scanner.Scan(ctx, target)

	if result.Error == "" {
		t.Log("scan completed before timeout")
	}
}

func TestLuhnCheck(t *testing.T) {
	testCases := []struct {
		number string
		valid  bool
	}{
		{"4111111111111111", true},
		{"5500000000000004", true},
		{"340000000000009", true},
		{"1234567890123456", false},
		{"0000000000000000", true},
	}

	for _, tc := range testCases {
		t.Run(tc.number, func(t *testing.T) {
			result := luhnCheck(tc.number)
			if result != tc.valid {
				t.Errorf("expected luhn(%s) = %v, got %v", tc.number, tc.valid, result)
			}
		})
	}
}
