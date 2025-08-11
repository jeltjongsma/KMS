package admin

import (
	"fmt"
)

type GenerateSignupTokenRequest struct {
	Clientname string `json:"clientname"`
	Ttl        int64  `json:"ttl"`
}

func (r *GenerateSignupTokenRequest) Validate() error {
	if r.Clientname == "" || r.Ttl == 0 {
		return fmt.Errorf("clientname and ttl should be non-empty")
	}
	return nil
}

type UpdateRoleRequest struct {
	Role string `json:"role"`
}

func (r *UpdateRoleRequest) Validate() error {
	if r.Role != "client" && r.Role != "admin" {
		return fmt.Errorf("role must be 'client' or 'admin'")
	}
	return nil
}
