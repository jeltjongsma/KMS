package dto

import (
	"kms/storage"
	"fmt"
)

type Validatable interface {
	Validate() error
}

type Credentials struct {
	Email 		string 	`json:"email"`
	Password	string 	`json:"password"`
}

func (c *Credentials) Lift() storage.User {
	var user storage.User
	user.Email = c.Email
	user.Password = c.Password
	return user
}

func (c* Credentials) Validate() error {
	if c.Email != "" && c.Password != "" {return nil}
	return fmt.Errorf("Email and password should be non-empty\n")
}

type JWTResponse struct {
	JWT 		string 	`json:"jwt"`
}