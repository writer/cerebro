package integration

import "testing"

func TestExtractNATSURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		line    string
		wantURL string
		wantOK  bool
	}{
		{
			name:    "listener announcement",
			line:    "[12345] [INF] Listening for client connections on 127.0.0.1:4222",
			wantURL: "nats://127.0.0.1:4222",
			wantOK:  true,
		},
		{
			name:   "unrelated line",
			line:   "[12345] [INF] Server is ready",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotURL, gotOK := extractNATSURL(tt.line)
			if gotOK != tt.wantOK {
				t.Fatalf("extractNATSURL() ok = %v, want %v", gotOK, tt.wantOK)
			}
			if gotURL != tt.wantURL {
				t.Fatalf("extractNATSURL() url = %q, want %q", gotURL, tt.wantURL)
			}
		})
	}
}
