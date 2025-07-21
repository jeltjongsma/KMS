package hashing

import (
	"golang.org/x/crypto/bcrypt"
	b64 "encoding/base64"
	"crypto/sha256"
	"crypto/hmac"
)

func HashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", err
	}
	return string(hashedBytes[:]), nil
}

func CheckPassword(storedPassword string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
}

func HashHS256ToB64(plain, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write(plain)
	hash := h.Sum(nil)
	return b64.RawURLEncoding.EncodeToString(hash)
}