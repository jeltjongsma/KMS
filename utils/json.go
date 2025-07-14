package utils

import (
	"encoding/json"
	"io"
	"net/http"
)

func DecodePayload(body io.ReadCloser, payload interface{}) error {
	return json.NewDecoder(body).Decode(payload)
}

func SendEncodedJSON(w http.ResponseWriter, payload interface{}) error {
	return json.NewEncoder(w).Encode(payload)
}