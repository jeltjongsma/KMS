package admin

import (
	"errors"
	"kms/internal/clients"
	kmsErrors "kms/pkg/errors"
)

// Repository mock for Admin operations
type AdminRepositoryMock struct {
	GetAdminFunc func(id int) (*clients.Client, error)
}

func NewAdminRepositoryMock() *AdminRepositoryMock {
	return &AdminRepositoryMock{}
}

func (m *AdminRepositoryMock) GetAdmin(id int) (*clients.Client, error) {
	if m.GetAdminFunc != nil {
		return m.GetAdminFunc(id)
	}
	return nil, errors.New("GetAdminFunc not implemented in mock")
}

// Service mock for Admin operations
type AdminServiceMock struct {
	UpdateRoleFunc          func(clientId int, role string, adminId string) *kmsErrors.AppError
	MeFunc                  func(id int) (*clients.Client, *kmsErrors.AppError)
	GenerateSignupTokenFunc func(body *GenerateSignupTokenRequest, adminId string) (string, *kmsErrors.AppError)
	GetClientsFunc          func() ([]clients.Client, *kmsErrors.AppError)
	DeleteClientFunc        func(clientId int) *kmsErrors.AppError
}

func NewAdminServiceMock() *AdminServiceMock {
	return &AdminServiceMock{}
}

func (m *AdminServiceMock) UpdateRole(clientId int, role string, adminId string) *kmsErrors.AppError {
	if m.UpdateRoleFunc != nil {
		return m.UpdateRoleFunc(clientId, role, adminId)
	}
	return kmsErrors.LiftToAppError(errors.New("UpdateRoleFunc not implemented in mock"))
}

func (m *AdminServiceMock) Me(clientId int) (*clients.Client, *kmsErrors.AppError) {
	if m.MeFunc != nil {
		return m.MeFunc(clientId)
	}
	return nil, kmsErrors.LiftToAppError(errors.New("MeFunc not implemented in mock"))
}

func (m *AdminServiceMock) GenerateSignupToken(body *GenerateSignupTokenRequest, adminId string) (string, *kmsErrors.AppError) {
	if m.GenerateSignupTokenFunc != nil {
		return m.GenerateSignupTokenFunc(body, adminId)
	}
	return "", kmsErrors.LiftToAppError(errors.New("GenerateSignupTokenFunc not implemented in mock"))
}

func (m *AdminServiceMock) GetClients() ([]clients.Client, *kmsErrors.AppError) {
	if m.GetClientsFunc != nil {
		return m.GetClientsFunc()
	}
	return nil, kmsErrors.LiftToAppError(errors.New("GetClientsFunc not implemented in mock"))
}

func (m *AdminServiceMock) DeleteClient(clientId int) *kmsErrors.AppError {
	if m.DeleteClientFunc != nil {
		return m.DeleteClientFunc(clientId)
	}
	return kmsErrors.LiftToAppError(errors.New("DeleteClientFunc not implemented in mock"))
}
