package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func withDashboard(apiHandler http.Handler, directory string) (http.Handler, error) {
	if apiHandler == nil {
		return nil, errors.New("API handler is required")
	}
	if strings.TrimSpace(directory) == "" {
		return apiHandler, nil
	}
	root, err := filepath.Abs(strings.TrimSpace(directory))
	if err != nil {
		return nil, errors.New("resolve dashboard directory")
	}
	indexPath := filepath.Join(root, "index.html")
	indexInfo, err := os.Stat(indexPath)
	if err != nil || !indexInfo.Mode().IsRegular() {
		return nil, errors.New("dashboard index is required")
	}

	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if isAPIPath(request.URL.Path) ||
			request.Method != http.MethodGet && request.Method != http.MethodHead {
			apiHandler.ServeHTTP(response, request)
			return
		}
		for _, segment := range strings.Split(request.URL.Path, "/") {
			if segment == ".." {
				http.Error(response, "invalid dashboard path", http.StatusBadRequest)
				return
			}
		}

		relativePath := filepath.Clean(strings.TrimPrefix(request.URL.Path, "/"))
		if relativePath == "." {
			relativePath = "index.html"
		}
		requestedPath := filepath.Join(root, relativePath)
		relativeToRoot, err := filepath.Rel(root, requestedPath)
		if err != nil || relativeToRoot == ".." ||
			strings.HasPrefix(relativeToRoot, ".."+string(filepath.Separator)) {
			http.Error(response, "invalid dashboard path", http.StatusBadRequest)
			return
		}
		info, statErr := os.Stat(requestedPath)
		switch {
		case statErr == nil && info.Mode().IsRegular():
		case statErr == nil && info.IsDir():
			requestedPath = filepath.Join(requestedPath, "index.html")
			if nestedInfo, nestedErr := os.Stat(requestedPath); nestedErr != nil ||
				!nestedInfo.Mode().IsRegular() {
				requestedPath = indexPath
			}
		case errors.Is(statErr, os.ErrNotExist) && filepath.Ext(relativePath) == "":
			requestedPath = indexPath
		case errors.Is(statErr, os.ErrNotExist):
			http.NotFound(response, request)
			return
		default:
			http.Error(response, "dashboard unavailable", http.StatusInternalServerError)
			return
		}

		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("Referrer-Policy", "no-referrer")
		if requestedPath == indexPath {
			response.Header().Set("Cache-Control", "no-store")
		} else if strings.HasPrefix(relativePath, "assets"+string(filepath.Separator)) {
			response.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		http.ServeFile(response, request, requestedPath)
	}), nil
}

func isAPIPath(path string) bool {
	return path == "/v1" ||
		strings.HasPrefix(path, "/v1/") ||
		path == "/livez" ||
		path == "/readyz"
}
