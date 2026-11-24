package vulnfetch

import (
	"context"
	"errors"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestGetErrorRedactsQueryCredentials(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()

	fetcher := New(Options{SourceID: "vulnerability-pull", Timeout: 2 * time.Second, MaxBodyBytes: 1024, AllowLoopback: true})
	_, _, err = fetcher.Get(context.Background(), "http://"+address+"/findings?api_key=query-secret-value&page=2", "", "")
	if err == nil {
		t.Fatal("expected a connection error")
	}
	// *url.Error renders the full request URL, query included.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		t.Fatalf("error keeps the request URL: %q", err)
	}
}
