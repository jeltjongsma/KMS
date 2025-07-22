package bootstrap

type KeyManager interface {
	JWTKey() []byte
	SignupKey() []byte
	KEK() []byte
	HashKey(kind string) []byte 
}

type StaticKeyManager struct {
	jwtKey		[]byte
	signupKey 	[]byte
	kek 		[]byte
	hashKeys	map[string][]byte
}
