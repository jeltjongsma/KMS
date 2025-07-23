package context

type KeyManager interface {
	JWTKey() []byte
	SignupKey() []byte
	KEK() []byte
	DBKey() []byte
	HashKey(kind string) ([]byte, error)
}

type Logger interface {
	Debug(string, ...any)
	Info(string, ...any)
	Notice(string, ...any)
	Warn(string, ...any)
	Warn(string, ...any)
	Error(string, ...any)
	Critical(string, ...any)
	Emergency(string, ...any)
}