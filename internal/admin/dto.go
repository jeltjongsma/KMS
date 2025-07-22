package admin

import (
	"fmt"
)

type GenerateSignupTokenRequest struct {
	Username 		string	`json:"username"`
	Ttl 			int64	`json:"ttl"`
}

func (r *GenerateSignupTokenRequest) Validate() error {
	if r.Username == "" || r.Ttl == 0 {
		return fmt.Errorf("Username and ttl should be non-empty")
	}
	return nil
}

type UpdateRoleRequest struct {
	Role 	string 	`json:"role"`
}

func (r *UpdateRoleRequest) Validate() error {
	if r.Role != "" {return nil}
	return fmt.Errorf("Role should be non-empty\n")
}


