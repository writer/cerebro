package sourcecdk

import (
	"errors"
	"testing"
)

func TestDecodeAPIErrorPrefersFirstPresentMessageKey(t *testing.T) {
	body := []byte(`{"error_description":"bad request","error":"ignored"}`)
	err := DecodeAPIError("Test API", 400, body, "Bad Request", "message", "error_description", "error", "detail")
	var statusErr *HTTPStatusError
	ok := errors.As(err, &statusErr)
	if !ok {
		t.Fatalf("error type = %T, want *HTTPStatusError", err)
	}
	if statusErr.Code != 400 {
		t.Fatalf("Code = %d, want 400", statusErr.Code)
	}
	if want := "Test API returned 400: bad request"; statusErr.Message != want {
		t.Fatalf("Message = %q, want %q", statusErr.Message, want)
	}
}

func TestDecodeAPIErrorFallsBackToRawBody(t *testing.T) {
	err := DecodeAPIError("Test API", 503, []byte("upstream unavailable"), "Service Unavailable", "message")
	var statusErr *HTTPStatusError
	errors.As(err, &statusErr)
	if want := "Test API returned 503: upstream unavailable"; statusErr.Message != want {
		t.Fatalf("Message = %q, want %q", statusErr.Message, want)
	}
}

func TestDecodeAPIErrorFallsBackToFallbackMessageForEmptyBody(t *testing.T) {
	err := DecodeAPIError("Test API", 500, nil, "Internal Server Error", "message")
	var statusErr *HTTPStatusError
	errors.As(err, &statusErr)
	if want := "Test API returned 500: Internal Server Error"; statusErr.Message != want {
		t.Fatalf("Message = %q, want %q", statusErr.Message, want)
	}
}

func TestDecodeAPIErrorIsRetryableAndUnauthorizedClassifiable(t *testing.T) {
	err := DecodeAPIError("Test API", 429, nil, "Too Many Requests")
	if !IsRetryableHTTPStatus(err) {
		t.Fatal("IsRetryableHTTPStatus() = false, want true for 429")
	}
	if IsHTTPStatus(err, 401) {
		t.Fatal("IsHTTPStatus(401) = true, want false for a 429 error")
	}
	unauthorized := DecodeAPIError("Test API", 401, nil, "Unauthorized")
	if !IsHTTPStatus(unauthorized, 401) {
		t.Fatal("IsHTTPStatus(401) = false, want true")
	}
}
