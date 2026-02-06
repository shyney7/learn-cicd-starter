package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	h := make(http.Header)
	h.Set("Authorization", "ApiKey abc123")

	got, err := GetAPIKey(h)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != "abc123" {
		t.Fatalf("expected api key %q, got %q", "abc123", got)
	}
}

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	h := make(http.Header)

	got, err := GetAPIKey(h)
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty api key, got %q", got)
	}
}

func TestGetAPIKey_MalformedAuthHeader(t *testing.T) {
	tests := []struct {
		name string
		val  string
	}{
		{"WrongScheme", "Bearer abc123"},
		{"MissingToken", "ApiKey"},
		{"EmptyValue", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := make(http.Header)
			if tc.val != "" {
				h.Set("Authorization", tc.val)
			}

			got, err := GetAPIKey(h)

			// EmptyValue is actually the "no header included" path in your implementation.
			if tc.name == "EmptyValue" {
				if !errors.Is(err, ErrNoAuthHeaderIncluded) {
					t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
				}
				if got != "" {
					t.Fatalf("expected empty api key, got %q", got)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected error, got nil (api key = %q)", got)
			}
			if got != "" {
				t.Fatalf("expected empty api key on error, got %q", got)
			}
		})
	}
}
