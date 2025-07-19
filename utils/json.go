package utils

import (
	"encoding/json"
	"io"
	"net/http"
)

func DecodePayload(body io.ReadCloser, payload interface{}) error {
	defer body.Close()
	return json.NewDecoder(body).Decode(payload)
}

func SendEncodedJSON(w http.ResponseWriter, payload interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(payload)
}

func ParseJSONBody(body io.ReadCloser, dst interface{}) error {
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields() // Fails silently

	if err := decoder.Decode(dst); err != nil {
		return err
	}

	return nil
}