package keys

import (
	"errors"
	kmsErrors "kms/pkg/errors"
)

// Repository mock for Key operations
type KeyRepositoryMock struct {
	GetKeyFunc       func(id int, keyReference string, version int) (*Key, error)
	GetLatestKeyFunc func(id int, keyReference string) (*Key, error)
	CreateKeyFunc    func(key *Key) (*Key, error)
	UpdateKeyFunc    func(clientId int, keyReference string, version int, state string) error
	DeleteFunc       func(clientId int, keyReference string) (int, error)
	GetAllFunc       func() ([]Key, error)
}

func NewKeyRepositoryMock() *KeyRepositoryMock {
	return &KeyRepositoryMock{}
}

func (m *KeyRepositoryMock) GetKey(id int, keyReference string, version int) (*Key, error) {
	if m.GetKeyFunc != nil {
		return m.GetKeyFunc(id, keyReference, version)
	}
	return nil, errors.New("GetKey not implemented")
}

func (m *KeyRepositoryMock) GetLatestKey(id int, keyReference string) (*Key, error) {
	if m.GetLatestKeyFunc != nil {
		return m.GetLatestKeyFunc(id, keyReference)
	}
	return nil, errors.New("GetKey not implemented")
}

func (m *KeyRepositoryMock) CreateKey(key *Key) (*Key, error) {
	if m.CreateKeyFunc != nil {
		return m.CreateKeyFunc(key)
	}
	return nil, errors.New("CreateKey not implemented")
}

func (m *KeyRepositoryMock) UpdateKey(clientId int, keyReference string, version int, state string) error {
	if m.UpdateKeyFunc != nil {
		return m.UpdateKeyFunc(clientId, keyReference, version, state)
	}
	return errors.New("UpdateKey not implemented")
}

func (m *KeyRepositoryMock) Delete(clientId int, keyReference string) (int, error) {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(clientId, keyReference)
	}
	return 0, errors.New("UpdateKey not implemented")
}

func (m *KeyRepositoryMock) GetAll() ([]Key, error) {
	if m.GetAllFunc != nil {
		return m.GetAllFunc()
	}
	return nil, errors.New("GetAll not implemented")
}

// Service mock for Key operations
type KeyServiceMock struct {
	GetKeyFunc    func(clientId int, keyReference string, version int) (*Key, *Key, *kmsErrors.AppError)
	CreateKeyFunc func(clientId int, keyReference string, version int) (*Key, *kmsErrors.AppError)
	RotateKeyFunc func(clientId int, keyReference string) (*Key, *kmsErrors.AppError)
	DeleteKeyFunc func(clientId int, keyReference string) *kmsErrors.AppError
	GetAllFunc    func() ([]Key, *kmsErrors.AppError)
}

func NewKeyServiceMock() *KeyServiceMock {
	return &KeyServiceMock{}
}

func (m *KeyServiceMock) GetKey(clientId int, keyReference string, version int) (*Key, *Key, *kmsErrors.AppError) {
	if m.GetKeyFunc != nil {
		return m.GetKeyFunc(clientId, keyReference, version)
	}
	return nil, nil, kmsErrors.LiftToAppError(errors.New("GetKey not implemented in mock"))
}

func (m *KeyServiceMock) CreateKey(clientId int, keyReference string, version int) (*Key, *kmsErrors.AppError) {
	if m.CreateKeyFunc != nil {
		return m.CreateKeyFunc(clientId, keyReference, version)
	}
	return nil, kmsErrors.LiftToAppError(errors.New("CreateKey not implemented in mock"))
}

func (m *KeyServiceMock) RotateKey(clientId int, keyReference string) (*Key, *kmsErrors.AppError) {
	if m.RotateKeyFunc != nil {
		return m.RotateKeyFunc(clientId, keyReference)
	}
	return nil, kmsErrors.LiftToAppError(errors.New("RotateKey not implemented in mock"))
}

func (m *KeyServiceMock) DeleteKey(clientId int, keyReference string) *kmsErrors.AppError {
	if m.DeleteKeyFunc != nil {
		return m.DeleteKeyFunc(clientId, keyReference)
	}
	return kmsErrors.LiftToAppError(errors.New("RotateKey not implemented in mock"))
}

func (m *KeyServiceMock) GetAll() ([]Key, *kmsErrors.AppError) {
	if m.GetAllFunc != nil {
		return m.GetAllFunc()
	}
	return nil, kmsErrors.LiftToAppError(errors.New("GetAll not implemented in mock"))
}
