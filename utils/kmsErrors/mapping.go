package kmsErrors

import (
	"errors"
	"github.com/lib/pq"
	"database/sql"
	"golang.org/x/crypto/bcrypt"
)

func MapRepoErr(err error) *AppError {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrNoRowsAffected) {
		return NewAppError(err, "Entity not found", 404)
	}

	if pqErr, ok := err.(*pq.Error); ok {
		switch pqErr.Code {
		case "23505": // Unique constraint
			return NewAppError(err, "Resource already exists", 409)
		case "23503": // FK violation
			return NewAppError(err, "Invalid foreign key", 400)
		case "23502": // Not null violation
			return NewAppError(err, "Missing required value", 400)
		case "22001": // Input too long
			return NewAppError(err, "Value too long", 400)
		case "42703", "42P01", "42601": // Undefined column, undefined table, SQL syntax
			return NewAppError(err, "Internal server error", 500)
		}
	}

	return NewInternalServerError(err)
}

func MapHashErr(err error) *AppError {
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword ) {
		return NewAppError(err, "Incorrect email or password", 401)
	}
	
	return NewInternalServerError(err)
}

func MapVerifyTokenErr(err error) *AppError {
	if errors.Is(err, ErrInvalidToken) {
		return NewAppError(err, "Invalid token", 401)
	}

	return NewInternalServerError(err)
}