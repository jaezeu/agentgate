package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDashboardServesAssetsAndSPAFallback(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "assets"), 0o700); err != nil {
		t.Fatalf("create assets directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("dashboard"), 0o600); err != nil {
		t.Fatalf("write dashboard index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "assets", "app.js"), []byte("asset"), 0o600); err != nil {
		t.Fatalf("write dashboard asset: %v", err)
	}
	handler, err := withDashboard(http.NotFoundHandler(), root)
	if err != nil {
		t.Fatalf("create dashboard handler: %v", err)
	}

	for path, expected := range map[string]string{
		"/":              "dashboard",
		"/requests/123":  "dashboard",
		"/assets/app.js": "asset",
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != expected {
			t.Fatalf("%s = %d %q", path, response.Code, response.Body.String())
		}
		if response.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s omitted static security headers", path)
		}
	}
}

func TestDashboardPreservesAPIRouting(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("dashboard"), 0o600); err != nil {
		t.Fatalf("write dashboard index: %v", err)
	}
	apiHandler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusTeapot)
	})
	handler, err := withDashboard(apiHandler, root)
	if err != nil {
		t.Fatalf("create dashboard handler: %v", err)
	}

	for _, testCase := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/v1/requests"},
		{method: http.MethodGet, path: "/livez"},
		{method: http.MethodGet, path: "/readyz"},
		{method: http.MethodPost, path: "/requests/123"},
	} {
		request := httptest.NewRequest(testCase.method, testCase.path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusTeapot {
			t.Fatalf("%s %s bypassed API handler: %d", testCase.method, testCase.path, response.Code)
		}
	}
}

func TestDashboardRequiresIndex(t *testing.T) {
	t.Parallel()
	if _, err := withDashboard(http.NotFoundHandler(), t.TempDir()); err == nil {
		t.Fatal("dashboard without index was accepted")
	}
}

func TestDashboardRejectsTraversal(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("dashboard"), 0o600); err != nil {
		t.Fatalf("write dashboard index: %v", err)
	}
	handler, err := withDashboard(http.NotFoundHandler(), root)
	if err != nil {
		t.Fatalf("create dashboard handler: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.URL.Path = "/../outside"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("traversal status = %d, want 400", response.Code)
	}
}
