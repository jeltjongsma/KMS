package admin

import (
	"errors"
	"kms/internal/users"
	kmsErrors "kms/pkg/errors"
)

// Repository mock for Admin operations
type AdminRepositoryMock struct {
	GetAdminFunc func(id int) (*users.User, error)
}

func NewAdminRepositoryMock() *AdminRepositoryMock {
	return &AdminRepositoryMock{}
}

func (m *AdminRepositoryMock) GetAdmin(id int) (*users.User, error) {
	if m.GetAdminFunc != nil {
		return m.GetAdminFunc(id)
	}
	return nil, errors.New("GetAdminFunc not implemented in mock")
}

// Service mock for Admin operations
type AdminServiceMock struct {
	UpdateRoleFunc          func(userId int, role string, adminId string) *kmsErrors.AppError
	MeFunc                  func(id int) (*users.User, *kmsErrors.AppError)
	GenerateSignupTokenFunc func(body *GenerateSignupTokenRequest, adminId string) (string, *kmsErrors.AppError)
}

func NewAdminServiceMock() *AdminServiceMock {
	return &AdminServiceMock{}
}

func (m *AdminServiceMock) UpdateRole(userId int, role string, adminId string) *kmsErrors.AppError {
	if m.UpdateRoleFunc != nil {
		return m.UpdateRoleFunc(userId, role, adminId)
	}
	return kmsErrors.LiftToAppError(errors.New("UpdateRoleFunc not implemented in mock"))
}

func (m *AdminServiceMock) Me(userId int) (*users.User, *kmsErrors.AppError) {
	if m.MeFunc != nil {
		return m.MeFunc(userId)
	}
	return nil, kmsErrors.LiftToAppError(errors.New("MeFunc not implemented in mock"))
}

func (m *AdminServiceMock) GenerateSignupToken(body *GenerateSignupTokenRequest, adminId string) (string, *kmsErrors.AppError) {
	if m.GenerateSignupTokenFunc != nil {
		return m.GenerateSignupTokenFunc(body, adminId)
	}
	return "", kmsErrors.LiftToAppError(errors.New("GenerateSignupTokenFunc not implemented in mock"))
}
