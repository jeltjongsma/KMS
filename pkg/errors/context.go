package errors

import (
	"errors"
	"fmt"
)

type AppError struct {
	Err     error
	Message string
	Code    int
}

func NewAppError(err error, msg string, code int) *AppError {
	return &AppError{
		Err:     err,
		Message: msg,
		Code:    code,
	}
}

var ErrNoRowsAffected = errors.New("no rows affected")
var ErrInvalidToken = errors.New("invalid token")
var ErrRepoEncryption = errors.New("database encryption wrapper failed")

func WrapError(err error, data map[string]interface{}) error {
	return fmt.Errorf("%w: %v", err, data)
}

func LiftToAppError(err error) *AppError {
	return NewAppError(err, "An error occurred", 500)
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
