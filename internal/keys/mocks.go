package keys

import (
	"errors"
	kmsErrors "kms/pkg/errors"
)

// Repository mock for Key operations
type KeyRepositoryMock struct {
	GetKeyFunc    func(id int, keyReference string) (*Key, error)
	CreateKeyFunc func(key *Key) (*Key, error)
	UpdateKeyFunc func(userId int, keyReference, newKey string) (*Key, error)
	GetAllFunc    func() ([]Key, error)
}

func NewKeyRepositoryMock() *KeyRepositoryMock {
	return &KeyRepositoryMock{}
}

func (m *KeyRepositoryMock) GetKey(id int, keyReference string) (*Key, error) {
	if m.GetKeyFunc != nil {
		return m.GetKeyFunc(id, keyReference)
	}
	return nil, errors.New("GetKey not implemented")
}

func (m *KeyRepositoryMock) CreateKey(key *Key) (*Key, error) {
	if m.CreateKeyFunc != nil {
		return m.CreateKeyFunc(key)
	}
	return nil, errors.New("CreateKey not implemented")
}

func (m *KeyRepositoryMock) UpdateKey(userId int, keyReference, newKey string) (*Key, error) {
	if m.UpdateKeyFunc != nil {
		return m.UpdateKeyFunc(userId, keyReference, newKey)
	}
	return nil, errors.New("UpdateKey not implemented")
}

func (m *KeyRepositoryMock) GetAll() ([]Key, error) {
	if m.GetAllFunc != nil {
		return m.GetAllFunc()
	}
	return nil, errors.New("GetAll not implemented")
}

// Service mock for Key operations
type KeyServiceMock struct {
	GetKeyFunc    func(userId int, keyReference string) (*Key, *kmsErrors.AppError)
	CreateKeyFunc func(userId int, keyReference string) (*Key, *kmsErrors.AppError)
	RenewKeyFunc  func(userId int, keyReference string) (*Key, *kmsErrors.AppError)
	GetAllFunc    func() ([]Key, *kmsErrors.AppError)
}

func NewKeyServiceMock() *KeyServiceMock {
	return &KeyServiceMock{}
}

func (m *KeyServiceMock) GetKey(userId int, keyReference string) (*Key, *kmsErrors.AppError) {
	if m.GetKeyFunc != nil {
		return m.GetKeyFunc(userId, keyReference)
	}
	return nil, kmsErrors.LiftToAppError(errors.New("GetKey not implemented in mock"))
}

func (m *KeyServiceMock) CreateKey(userId int, keyReference string) (*Key, *kmsErrors.AppError) {
	if m.CreateKeyFunc != nil {
		return m.CreateKeyFunc(userId, keyReference)
	}
	return nil, kmsErrors.LiftToAppError(errors.New("CreateKey not implemented in mock"))
}

func (m *KeyServiceMock) RenewKey(userId int, keyReference string) (*Key, *kmsErrors.AppError) {
	if m.RenewKeyFunc != nil {
		return m.RenewKeyFunc(userId, keyReference)
	}
	return nil, kmsErrors.LiftToAppError(errors.New("RenewKey not implemented in mock"))
}

func (m *KeyServiceMock) GetAll() ([]Key, *kmsErrors.AppError) {
	if m.GetAllFunc != nil {
		return m.GetAllFunc()
	}
	return nil, kmsErrors.LiftToAppError(errors.New("GetAll not implemented in mock"))
}
