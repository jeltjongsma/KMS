package dto

import (
	"kms/storage"
	"fmt"
)

type Validatable interface {
	Validate() error
}

type Credentials struct {
	Username 	string 	`json:"username"`
	Password	string 	`json:"password"`
}

func (c *Credentials) Lift() *storage.User {
	var user storage.User
	user.Username = c.Username
	user.Password = c.Password
	return &user
}

type SignupCredentials struct {
	Token 		string 	`json:"token"`
	Password	string 	`json:"password"`
}

func (c *SignupCredentials) Validate() error {
	if c.Token == "" || c.Password == "" {
		return fmt.Errorf("Token and password should be non-empty")
	}
	return nil
}

func (c* Credentials) Validate() error {
	if c.Username != "" && c.Password != "" {return nil}
	return fmt.Errorf("Username and password should be non-empty\n")
}

type TokenResponse struct {
	Token 		string 	`json:"token"`
}