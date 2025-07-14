package storage

type Key struct {
	ID		string 	`json:"id"`
	DEK 	string 	`json:"dek"`
	UserId	int32	`json:"userId"`
}

type User struct {
	ID 			int		`json:"id"`
	Email		string 	`json:"email"`
	FName		string	`json:"fname"`
	LName		string	`json:"lname"`
	Password	string 	`json:"password"`
}