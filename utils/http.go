package utils

import (
	"strings"
	"fmt"
	"net/http"
	"io"
)

// TODO: Sanitize
func GetIDFromURL(url string, idx int, enforceDepth bool) (string, error) {
	parts := strings.Split(url, "/")
	if enforceDepth && len(parts) != (idx + 1) {
		return "", fmt.Errorf("Enforced depth doesn't match\nExpected %v, but found %v", (idx + 1), len(parts))
	}
	if len(parts) > idx && parts[idx] != "" {
		return parts[idx], nil
	}
	return "", fmt.Errorf("No ID found at %v", idx)
}

func HandleErrAndSendHttp(w http.ResponseWriter, err error, msg string, status int) bool {
	if err != nil {
		// TODO: Replace with a log or something
		fmt.Printf("Unexpected error: %w", err)
		http.Error(w, msg, status)
		return true
	}
	return false
}

func ReturnMethodNotAllowed(w http.ResponseWriter) {
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func DecodePayloadHandleError(w http.ResponseWriter, body io.ReadCloser, payload interface{}) bool {
	return HandleErrAndSendHttp(
		w, 
		DecodePayload(body, payload),
		"Invalid request body",
		http.StatusBadRequest,
	)
}