package bootstrap

import (
	b64 "encoding/base64"
	"fmt"
	c "kms/internal/bootstrap/context"
)

type StaticKeyManager struct {
	JwtKey_    []byte
	SignupKey_ []byte
	KEK_       []byte
	DBKey_     []byte
	HashKeys_  map[string][]byte
}

func InitStaticKeyManager(cfg c.KmsConfig) (*StaticKeyManager, error) {
	jwtKey, err := b64.RawURLEncoding.DecodeString(cfg["JWT_SECRET"])
	if err != nil {
		return nil, err
	}
	signupKey, err := b64.RawURLEncoding.DecodeString(cfg["SIGNUP_SECRET"])
	if err != nil {
		return nil, err
	}
	kek, err := b64.RawURLEncoding.DecodeString(cfg["KEK"])
	if err != nil {
		return nil, err
	}
	dbKey, err := b64.RawURLEncoding.DecodeString(cfg["DB_SECRET"])
	if err != nil {
		return nil, err
	}
	keyRefKey, err := b64.RawURLEncoding.DecodeString(cfg["KEY_REF_SECRET"])
	if err != nil {
		return nil, err
	}
	usernameKey, err := b64.RawURLEncoding.DecodeString(cfg["USERNAME_SECRET"])
	if err != nil {
		return nil, err
	}

	hashKeys := map[string][]byte{
		"keyReference": keyRefKey,
		"username":     usernameKey,
	}

	return &StaticKeyManager{
		JwtKey_:    jwtKey,
		SignupKey_: signupKey,
		KEK_:       kek,
		DBKey_:     dbKey,
		HashKeys_:  hashKeys,
	}, nil
}

func (m *StaticKeyManager) JWTKey() []byte {
	return m.JwtKey_
}

func (m *StaticKeyManager) SignupKey() []byte {
	return m.SignupKey_
}

func (m *StaticKeyManager) KEK() []byte {
	return m.KEK_
}

func (m *StaticKeyManager) DBKey() []byte {
	return m.DBKey_
}

func (m *StaticKeyManager) HashKey(kind string) ([]byte, error) {
	key, ok := m.HashKeys_[kind]
	if !ok {
		return nil, fmt.Errorf("hash key '%s' not found", kind)
	}
	return key, nil
}
