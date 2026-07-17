package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFoundationRouterHealth(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/livez", "/readyz"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodGet, path, nil)
			response := httptest.NewRecorder()

			NewFoundationRouter("test-version").ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
			}
			if !strings.Contains(response.Body.String(), `"version":"test-version"`) {
				t.Fatalf("body = %q, want version", response.Body.String())
			}
		})
	}
}

func TestFoundationRouterDoesNotExposeAccessAPI(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodPost, "/v1/access-requests", nil)
	response := httptest.NewRecorder()
	NewFoundationRouter("test-version").ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}
