package storage

type Key struct {
	ID 				int 	`json:"id"`
	KeyReference	string 	`json:"keyReference"`
	DEK 			string 	`json:"dek"`
	UserId			int		`json:"userId"`
	Encoding 		string 	`json:"encoding"`
}

type User struct {
	ID 			int		`json:"id"`
	Email		string 	`json:"email"`
	Password	string 	`json:"password"`
	Role 		string 	`json:"role"`
}
