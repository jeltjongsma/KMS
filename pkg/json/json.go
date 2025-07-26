package json

import (
	"encoding/json"
	"fmt"
	"io"
)

func ParseBody(body io.ReadCloser, dst interface{}) error {
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields() // Fails silently

	if err := decoder.Decode(dst); err != nil {
		return err
	}

	var extra interface{}
	err := decoder.Decode(&extra)
	if err == nil {
		return fmt.Errorf("extra JSON after first object")
	}
	if err != io.EOF {
		// some other error (e.g. syntax), bubble it up
		return err
	}

	return nil
}
