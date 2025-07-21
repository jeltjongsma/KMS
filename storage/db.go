package storage

type KeyRepository interface {
	CreateKey(key *Key) (*Key, error)
	GetKey(id int, keyReference string) (*Key, error)
	GetAll() ([]Key, error)
}

type UserRepository interface {
	CreateUser(user *User) (int, error)
	GetUser(id int) (*User, error)
	GetAll() ([]User, error)
	FindByEmail(email string) (*User, error)
	UpdateRole(id int, role string) error
	GetRole(id int) (string, error)
}

type AdminRepository interface {
	GetAdmin(id int) (*User, error)
}
