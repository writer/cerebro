package sourcehttp

import (
	"strings"
	"testing"
)

func TestNormalizeBaseURLRejectsUnsafeHosts(t *testing.T) {
	for _, raw := range []string{
		"http://169.254.169.254",
		"https://127.0.0.1",
		"https://localhost",
		"https://10.0.0.1",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, _, err := NormalizeBaseURL("test_source", raw, false); err == nil {
				t.Fatal("NormalizeBaseURL() error = nil, want unsafe host error")
			}
		})
	}
}

func TestSameOriginAbsoluteURLRejectsHostChanges(t *testing.T) {
	if _, err := SameOriginAbsoluteURL("test_source", "https://api.example.com", "https://metadata.google.internal/latest"); err == nil {
		t.Fatal("SameOriginAbsoluteURL() error = nil, want host mismatch")
	}
	if got, err := SameOriginAbsoluteURL("test_source", "https://api.example.com", "https://api.example.com/v1/page?$skiptoken=1"); err != nil || got == "" {
		t.Fatalf("SameOriginAbsoluteURL() = %q, %v; want same-host URL", got, err)
	}
}

func TestReadLimitedBodyRejectsOversizedResponse(t *testing.T) {
	_, err := ReadLimitedBody(strings.NewReader(strings.Repeat("x", MaxBodyBytes+1)))
	if err == nil {
		t.Fatal("ReadLimitedBody() error = nil, want oversized response error")
	}
}

func TestReadLimitedBodyWithLimitRejectsCustomOversizedResponse(t *testing.T) {
	_, err := ReadLimitedBodyWithLimit(strings.NewReader("abcdef"), 5)
	if err == nil {
		t.Fatal("ReadLimitedBodyWithLimit() error = nil, want oversized response error")
	}
}
