package users

import (
	"errors"
	kmsErrors "kms/pkg/errors"
)

// Repository mock for User operations
type UserRepositoryMock struct {
	CreateUserFunc           func(user *User) (int, error)
	GetUserFunc              func(id int) (*User, error)
	GetAllFunc               func() ([]User, error)
	FindByHashedUsernameFunc func(email string) (*User, error)
	UpdateRoleFunc           func(id int, role string) error
	GetRoleFunc              func(id int) (string, error)
}

func NewUserRepositoryMock() *UserRepositoryMock {
	return &UserRepositoryMock{}
}

func (m *UserRepositoryMock) CreateUser(user *User) (int, error) {
	if m.CreateUserFunc != nil {
		return m.CreateUserFunc(user)
	}
	return 0, errors.New("CreateUserFunc not implemented in mock")
}

func (m *UserRepositoryMock) GetUser(id int) (*User, error) {
	if m.GetUserFunc != nil {
		return m.GetUserFunc(id)
	}
	return nil, nil
}

func (m *UserRepositoryMock) GetAll() ([]User, error) {
	if m.GetAllFunc != nil {
		return m.GetAllFunc()
	}
	return nil, errors.New("GetAllFunc not implemented in mock")
}

func (m *UserRepositoryMock) FindByHashedUsername(email string) (*User, error) {
	if m.FindByHashedUsernameFunc != nil {
		return m.FindByHashedUsernameFunc(email)
	}
	return nil, errors.New("FindByHashedUsernameFunc not implemented in mock")
}

func (m *UserRepositoryMock) UpdateRole(id int, role string) error {
	if m.UpdateRoleFunc != nil {
		return m.UpdateRoleFunc(id, role)
	}
	return errors.New("UpdateRoleFunc not implemented in mock")
}

func (m *UserRepositoryMock) GetRole(id int) (string, error) {
	if m.GetRoleFunc != nil {
		return m.GetRoleFunc(id)
	}
	return "", errors.New("GetRoleFunc not implemented in mock")
}

// Service mock for User operations
type UserServiceMock struct {
	GetAllFunc func() ([]User, *kmsErrors.AppError)
}

func NewUserServiceMock() *UserServiceMock {
	return &UserServiceMock{}
}

func (m *UserServiceMock) GetAll() ([]User, *kmsErrors.AppError) {
	if m.GetAllFunc != nil {
		return m.GetAllFunc()
	}
	return nil, kmsErrors.LiftToAppError(errors.New("GetAll not implemented in mock"))
}
