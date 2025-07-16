package storage

type KeyRepository interface {
	CreateKey(key *Key) (string, error)
	GetKey(id string) (Key, error)
	GetAll() ([]Key, error)
}

type UserRepository interface {
	CreateUser(user *User) (int, error)
	GetUser(id int) (User, error)
	GetAll() ([]User, error)
	FindByEmail(email string) (User, error)
}

type AdminRepository interface {
	GetAdmin(id int) (User, error)
}
