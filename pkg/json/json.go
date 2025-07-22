package json

import (
	"encoding/json"
	"io"
)

func ParseBody(body io.ReadCloser, dst interface{}) error {
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields() // Fails silently

	if err := decoder.Decode(dst); err != nil {
		return err
	}

	return nil
}