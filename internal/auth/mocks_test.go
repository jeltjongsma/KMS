package auth

import (
	"errors"
	kmsErrors "kms/pkg/errors"
)

type AuthServiceMock struct {
	LoginFunc  func(credentials *Credentials) (string, *kmsErrors.AppError)
	SignupFunc func(credentials *SignupCredentials) (string, *kmsErrors.AppError)
}

func NewAuthServiceMock() *AuthServiceMock {
	return &AuthServiceMock{}
}

func (m *AuthServiceMock) Login(credentials *Credentials) (string, *kmsErrors.AppError) {
	if m.LoginFunc != nil {
		return m.LoginFunc(credentials)
	}
	return "", kmsErrors.LiftToAppError(errors.New("LoginFunc not implemented in mock"))
}

func (m *AuthServiceMock) Signup(credentials *SignupCredentials) (string, *kmsErrors.AppError) {
	if m.SignupFunc != nil {
		return m.SignupFunc(credentials)
	}
	return "", kmsErrors.LiftToAppError(errors.New("SignupFunc not implemented in mock"))
}
