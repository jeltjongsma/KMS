package utils

import (
	"strings"
	"fmt"
	"strconv"
	"net/http"
)

func GetIDFromURL(url string, idx int, enforceDepth bool) (int, error) {
	parts := strings.Split(url, "/")
	if enforceDepth && len(parts) != (idx + 1) {
		return 0, fmt.Errorf("Enforced depth doesn't match\nExpected %v, but found %v", (idx + 1), len(parts))
	}
	if len(parts) > idx && parts[idx] != "" {
		id, err := strconv.Atoi(parts[idx])
		if err != nil {
			return 0, fmt.Errorf("Targeted index of wrong type\nExpected integer, but found %T", parts[idx])
		}
		return id, nil
	}
	return 0, fmt.Errorf("No ID found at %v", idx)
}

func HandleHttpErr(w http.ResponseWriter, err error, msg string, status int) bool {
	if err != nil {
		http.Error(w, msg, status)
		return true
	}
	return false
}