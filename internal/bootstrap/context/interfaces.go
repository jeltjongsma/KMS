package context

type KeyManager interface {
	JWTKey() []byte
	SignupKey() []byte
	KEK() []byte
	DBKey() []byte
	HashKey(kind string) ([]byte, error)
}