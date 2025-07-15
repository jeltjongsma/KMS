package hashing

import (
	"golang.org/x/crypto/bcrypt"
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