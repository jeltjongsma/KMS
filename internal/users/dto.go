package users

type User struct {
	ID             int    `json:"id"`
	Username       string `json:"username" encrypt:"true"`
	HashedUsername string `json:"hashedUsername"`
	Password       string `json:"password"`
	Role           string `json:"role" encrypt:"true"`
}
