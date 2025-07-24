package http

import (
	"net/http"
	"encoding/json"
	kmsErrors "kms/pkg/errors"
)

func WriteJSON(w http.ResponseWriter, src interface{}) *kmsErrors.AppError {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(src); err != nil {
		return kmsErrors.NewAppError(err, "Failed to generate response", 500)
	}
	return nil
}