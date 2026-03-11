package api

import (
	"net/http/httptest"
	"testing"
)

func TestQueryPositiveInt(t *testing.T) {
	tests := []struct {
		name         string
		rawQuery     string
		defaultValue int
		want         int
	}{
		{
			name:         "missing value uses default",
			rawQuery:     "",
			defaultValue: 100,
			want:         100,
		},
		{
			name:         "empty value uses default",
			rawQuery:     "limit=",
			defaultValue: 100,
			want:         100,
		},
		{
			name:         "invalid value uses default",
			rawQuery:     "limit=abc",
			defaultValue: 100,
			want:         100,
		},
		{
			name:         "zero uses default",
			rawQuery:     "limit=0",
			defaultValue: 100,
			want:         100,
		},
		{
			name:         "negative uses default",
			rawQuery:     "limit=-5",
			defaultValue: 100,
			want:         100,
		},
		{
			name:         "valid positive value",
			rawQuery:     "limit=25",
			defaultValue: 100,
			want:         25,
		},
		{
			name:         "whitespace value",
			rawQuery:     "limit=%2025%20",
			defaultValue: 100,
			want:         25,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/"
			if tt.rawQuery != "" {
				url += "?" + tt.rawQuery
			}
			req := httptest.NewRequest("GET", url, nil)

			if got := queryPositiveInt(req, "limit", tt.defaultValue); got != tt.want {
				t.Fatalf("queryPositiveInt(...): got %d, want %d", got, tt.want)
			}
		})
	}
}
