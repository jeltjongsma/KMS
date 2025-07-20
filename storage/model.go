package storage

type Key struct {
	ID 				int 	`json:"id"`
	KeyReference	string 	`json:"keyReference"`
	DEK 			string 	`json:"dek" encrypt:"true" encoded:"true"`
	UserId			int		`json:"userId"`
	Encoding 		string 	`json:"encoding" encrypt:"true"`
}

type User struct {
	ID 			int		`json:"id"`
	Email		string 	`json:"email"				encrypt:"true"`
	Password	string 	`json:"password"`
	Role 		string 	`json:"role"				encrypt:"true"`
}
