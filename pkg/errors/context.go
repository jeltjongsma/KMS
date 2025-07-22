package errors

import (
	"fmt"
	"errors"
)

type AppError struct {
	Err 		error
	Message 	string
	Code 		int
}

func NewAppError(err error, msg string, code int) *AppError {
	return &AppError{
		Err: err,
		Message: msg,
		Code: code,
	}
}

var ErrNoRowsAffected = errors.New("No rows affected")
var ErrInvalidToken = errors.New("Invalid token")
var ErrRepoEncryption = errors.New("Database encryption wrapper failed")

func WrapError(err error, data map[string]interface{}) error {
	return fmt.Errorf("%w: %v", err, data)
}

func NewInternalServerError(err error) *AppError {
	return NewAppError(err, "Internal server error", 500)
} 

func NewInvalidBodyError(err error) *AppError {
	return NewAppError(err, "Invalid request body", 400)
}

func NewMissingCredentialsError(err error) *AppError {
	return NewAppError(err, "Missing credentials", 400)
}