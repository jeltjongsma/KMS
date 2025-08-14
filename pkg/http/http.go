package http

import (
	"encoding/json"
	kmsErrors "kms/pkg/errors"
	"net/http"
)

func WriteJSON(w http.ResponseWriter, src interface{}) *kmsErrors.AppError {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(src); err != nil {
		return kmsErrors.NewInternalServerError(err)
	}
	return nil
}

func WriteHeader(w http.ResponseWriter, key, value string) *kmsErrors.AppError {
	w.Header().Set(key, value)
	return nil
}

func WriteStatus(w http.ResponseWriter, status int) *kmsErrors.AppError {
	w.WriteHeader(status)
	return nil
}
