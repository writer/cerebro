package client

import (
	"errors"
	"net/http"
	"net/url"
	"testing"
)

func TestNew_ValidatesBaseURL(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("expected error when base URL is empty")
	}

	_, err = New(Config{BaseURL: "://bad"})
	if err == nil {
		t.Fatal("expected error for invalid base URL")
	}

	c, err := New(Config{BaseURL: "https://api.example.com/"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := c.endpointURL("/api/v1/findings", nil); got != "https://api.example.com/api/v1/findings" {
		t.Fatalf("unexpected endpoint URL: %s", got)
	}
}

func TestIsAPIErrorStatus(t *testing.T) {
	err := &APIError{StatusCode: http.StatusNotFound, Message: "missing", Code: "not_found"}
	if !IsAPIErrorStatus(err, http.StatusNotFound) {
		t.Fatal("expected status matcher to return true")
	}
	if IsAPIErrorStatus(err, http.StatusUnauthorized) {
		t.Fatal("expected status matcher to return false for different status")
	}
}

func TestIsTransportError(t *testing.T) {
	if !IsTransportError(&url.Error{Op: "Get", URL: "http://127.0.0.1:1", Err: errors.New("dial")}) {
		t.Fatal("expected url error to be treated as transport error")
	}
	if IsTransportError(&APIError{StatusCode: http.StatusUnauthorized, Message: "nope"}) {
		t.Fatal("expected API status error not to be treated as transport error")
	}
}
