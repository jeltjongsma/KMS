package storage

type Key struct {
	ID 				int 	`json:"id"`
	KeyReference	string 	`json:"keyReference"` 
	DEK 			string 	`json:"dek" encrypt:"true" encoded:"true"`
	UserId			int		`json:"userId"`
	Encoding 		string 	`json:"encoding" encrypt:"true"`
}

type User struct {
	ID 				int		`json:"id"`
	Username		string 	`json:"username" encrypt:"true"` 
	HashedUsername 	string 	`json:"hashedUsername"`
	Password		string 	`json:"password"`
	Role 			string 	`json:"role" encrypt:"true"`
}
