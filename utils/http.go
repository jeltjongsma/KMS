package utils

import (
	"strings"
	"fmt"
	"net/http"
	"io"
	"kms/utils/kmsErrors"
	"encoding/json"
)

func WriteStatus(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
}

func WriteJSON(w http.ResponseWriter, src interface{}) *kmsErrors.AppError {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(src); err != nil {
		return kmsErrors.NewAppError(err, "Failed to generate response", 500)
	}
	return nil
}