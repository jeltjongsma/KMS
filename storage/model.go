package storage

type Key struct {
	ID 				int 	`json:"id"`
	KeyReference	string 	`json:"keyReference"` // TODO: Store deterministic hash to keep loopup functionality
	DEK 			string 	`json:"dek" encrypt:"true" encoded:"true"`
	UserId			int		`json:"userId"`
	Encoding 		string 	`json:"encoding" encrypt:"true"`
}

type User struct {
	ID 			int		`json:"id"`
	Username	string 	`json:"username"` // TODO: Store deterministic hash to keep lookup functionality
	Password	string 	`json:"password"`
	Role 		string 	`json:"role" encrypt:"true"`
}
