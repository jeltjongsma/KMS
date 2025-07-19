package dto

type KeyReponse struct {
	DEK			string 	`json:"dek"`
	Encoding 	string 	`json:"encoding"`
}

type UserResponse struct {
	Email 		string 	`json:"email"`
	Role 		string 	`json:"role"`
}