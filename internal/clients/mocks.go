package clients

import (
	"errors"
	kmsErrors "kms/pkg/errors"
)

// Repository mock for Client operations
type ClientRepositoryMock struct {
	CreateClientFunc           func(client *Client) (int, error)
	GetClientFunc              func(id int) (*Client, error)
	GetAllFunc                 func() ([]Client, error)
	DeleteFunc                 func(clientId int) error
	FindByHashedClientnameFunc func(email string) (*Client, error)
	UpdateRoleFunc             func(id int, role string) error
	GetRoleFunc                func(id int) (string, error)
}

func NewClientRepositoryMock() *ClientRepositoryMock {
	return &ClientRepositoryMock{}
}

func (m *ClientRepositoryMock) CreateClient(client *Client) (int, error) {
	if m.CreateClientFunc != nil {
		return m.CreateClientFunc(client)
	}
	return 0, errors.New("CreateClientFunc not implemented in mock")
}

func (m *ClientRepositoryMock) GetClient(id int) (*Client, error) {
	if m.GetClientFunc != nil {
		return m.GetClientFunc(id)
	}
	return nil, nil
}

func (m *ClientRepositoryMock) GetAll() ([]Client, error) {
	if m.GetAllFunc != nil {
		return m.GetAllFunc()
	}
	return nil, errors.New("GetAllFunc not implemented in mock")
}

func (m *ClientRepositoryMock) Delete(clientId int) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(clientId)
	}
	return errors.New("DeleteFunc not implemented in mock")
}

func (m *ClientRepositoryMock) FindByHashedClientname(email string) (*Client, error) {
	if m.FindByHashedClientnameFunc != nil {
		return m.FindByHashedClientnameFunc(email)
	}
	return nil, errors.New("FindByHashedClientnameFunc not implemented in mock")
}

func (m *ClientRepositoryMock) UpdateRole(id int, role string) error {
	if m.UpdateRoleFunc != nil {
		return m.UpdateRoleFunc(id, role)
	}
	return errors.New("UpdateRoleFunc not implemented in mock")
}

func (m *ClientRepositoryMock) GetRole(id int) (string, error) {
	if m.GetRoleFunc != nil {
		return m.GetRoleFunc(id)
	}
	return "", errors.New("GetRoleFunc not implemented in mock")
}

// Service mock for Client operations
type ClientServiceMock struct {
	GetAllFunc func() ([]Client, *kmsErrors.AppError)
}

func NewClientServiceMock() *ClientServiceMock {
	return &ClientServiceMock{}
}

func (m *ClientServiceMock) GetAll() ([]Client, *kmsErrors.AppError) {
	if m.GetAllFunc != nil {
		return m.GetAllFunc()
	}
	return nil, kmsErrors.LiftToAppError(errors.New("GetAll not implemented in mock"))
}
