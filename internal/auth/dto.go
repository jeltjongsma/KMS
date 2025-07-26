package auth

import (
	"fmt"
	"kms/internal/users"
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c *Credentials) Lift() *users.User {
	var user users.User
	user.Username = c.Username
	user.Password = c.Password
	return &user
}

type SignupCredentials struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (c *SignupCredentials) Validate() error {
	if c.Token == "" || c.Password == "" {
		return fmt.Errorf("token and password should be non-empty")
	}
	return nil
}

func (c *Credentials) Validate() error {
	if c.Username != "" && c.Password != "" {
		return nil
	}
	return fmt.Errorf("username and password should be non-empty")
}
