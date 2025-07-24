package id

import (
	"io"
	"crypto/rand"
	// "encoding/hex"
	"fmt"
)

func GenerateUUID() (string, error) {
	// 16 random bytes
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}

	// UUID version (4) and RFC 4122 variant bits
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant is 10xxxxxx

	// Hex-encode to a 36-char string with dashes
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16],
	), nil
}