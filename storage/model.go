package storage

type Key struct {
	ID		string 	`json:"id"`
	DEK 	string 	`json:"dek"`
	UserId	int32	`json:"userId"`
}