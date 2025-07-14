package storage

type KeyRepository interface {
	CreateKey(key *Key) (string, error)
	GetKey(id string) (Key, error)
	GetAll() ([]Key, error)
}