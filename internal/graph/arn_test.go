package graph

import (
	"testing"
)

func TestParseARN(t *testing.T) {
	tests := []struct {
		input    string
		expected *ARN
		wantErr  bool
	}{
		{
			input: "arn:aws:s3:::my-bucket",
			expected: &ARN{
				Partition: "aws",
				Service:   "s3",
				Region:    "",
				Account:   "",
				Resource:  "my-bucket",
			},
		},
		{
			input: "arn:aws:iam::123456789012:user/alice",
			expected: &ARN{
				Partition: "aws",
				Service:   "iam",
				Region:    "",
				Account:   "123456789012",
				Resource:  "user/alice",
			},
		},
		{
			input: "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
			expected: &ARN{
				Partition: "aws",
				Service:   "ec2",
				Region:    "us-east-1",
				Account:   "123456789012",
				Resource:  "instance/i-1234567890abcdef0",
			},
		},
		{
			input: "*",
			expected: &ARN{
				Partition: "*",
				Service:   "*",
				Region:    "*",
				Account:   "*",
				Resource:  "*",
			},
		},
		{
			input:   "invalid-arn",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseARN(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got.Partition != tt.expected.Partition ||
				got.Service != tt.expected.Service ||
				got.Region != tt.expected.Region ||
				got.Account != tt.expected.Account ||
				got.Resource != tt.expected.Resource {
				t.Errorf("got %+v, want %+v", got, tt.expected)
			}
		})
	}
}

func TestARN_MatchesPattern(t *testing.T) {
	tests := []struct {
		arn     string
		pattern string
		want    bool
	}{
		// Exact match
		{"arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket", true},
		// Wildcard resource
		{"arn:aws:s3:::my-bucket", "arn:aws:s3:::*", true},
		// Full wildcard
		{"arn:aws:s3:::my-bucket", "*", true},
		// Partial wildcard
		{"arn:aws:s3:::my-bucket", "arn:aws:s3:::my-*", true},
		{"arn:aws:s3:::my-bucket-prod", "arn:aws:s3:::*-prod", true},
		// Non-matching
		{"arn:aws:s3:::my-bucket", "arn:aws:s3:::other-bucket", false},
		{"arn:aws:s3:::my-bucket", "arn:aws:ec2:::*", false},
	}

	for _, tt := range tests {
		t.Run(tt.arn+" vs "+tt.pattern, func(t *testing.T) {
			arn, _ := ParseARN(tt.arn)
			pattern, _ := ParseARN(tt.pattern)

			got := arn.MatchesPattern(pattern)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractAccountFromARN(t *testing.T) {
	tests := []struct {
		arn  string
		want string
	}{
		{"arn:aws:iam::123456789012:user/alice", "123456789012"},
		{"arn:aws:s3:::my-bucket", ""},
		{"arn:aws:ec2:us-east-1:987654321098:instance/i-123", "987654321098"},
	}

	for _, tt := range tests {
		t.Run(tt.arn, func(t *testing.T) {
			got := ExtractAccountFromARN(tt.arn)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestARNMatcher_MatchesAny(t *testing.T) {
	patterns := []string{
		"arn:aws:s3:::*",
		"arn:aws:iam::123456789012:*",
	}
	matcher := NewARNMatcher(patterns)

	tests := []struct {
		arn  string
		want bool
	}{
		{"arn:aws:s3:::my-bucket", true},
		{"arn:aws:iam::123456789012:user/alice", true},
		{"arn:aws:ec2:us-east-1:123456789012:instance/i-123", false},
		{"arn:aws:iam::987654321098:user/bob", false},
	}

	for _, tt := range tests {
		t.Run(tt.arn, func(t *testing.T) {
			got := matcher.MatchesAny(tt.arn)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
