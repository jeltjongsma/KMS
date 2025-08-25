package auth

import (
	"fmt"
	"kms/internal/clients"
)

type Credentials struct {
	Clientname string `json:"clientname"`
	Password   string `json:"password"`
}

func (c *Credentials) Lift() *clients.Client {
	var client clients.Client
	client.Clientname = c.Clientname
	client.Password = c.Password
	return &client
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
	if c.Clientname != "" && c.Password != "" {
		return nil
	}
	return fmt.Errorf("clientname and password should be non-empty")
}
