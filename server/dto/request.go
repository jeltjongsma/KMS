package dto

import (
	"fmt"
)

type UpdateRoleRequest struct {
	Role 	string 	`json:"role"`
}

func (r *UpdateRoleRequest) Validate() error {
	if r.Role != "" {return nil}
	return fmt.Errorf("Role should be non-empty\n")
}