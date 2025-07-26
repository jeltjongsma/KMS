package mocks

type KeyManagerMock struct {
	JWTKeyFunc    func() []byte
	SignupKeyFunc func() []byte
	KEKFunc       func() []byte
	DBKeyFunc     func() []byte
	HashKeyFunc   func(kind string) ([]byte, error)
}

func NewKeyManagerMock() *KeyManagerMock {
	return &KeyManagerMock{}
}

func (m *KeyManagerMock) JWTKey() []byte {
	if m.JWTKeyFunc != nil {
		return m.JWTKeyFunc()
	}
	return nil
}

func (m *KeyManagerMock) SignupKey() []byte {
	if m.SignupKeyFunc != nil {
		return m.SignupKeyFunc()
	}
	return nil
}

func (m *KeyManagerMock) KEK() []byte {
	if m.KEKFunc != nil {
		return m.KEKFunc()
	}
	return nil
}

func (m *KeyManagerMock) DBKey() []byte {
	if m.DBKeyFunc != nil {
		return m.DBKeyFunc()
	}
	return nil
}

func (m *KeyManagerMock) HashKey(kind string) ([]byte, error) {
	if m.HashKeyFunc != nil {
		return m.HashKeyFunc(kind)
	}
	return nil, nil
}
