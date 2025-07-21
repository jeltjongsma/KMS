package dto

type KeyReponse struct {
	DEK			string 	`json:"dek"`
	Encoding 	string 	`json:"encoding"`
}

type UserResponse struct {
	Username	string 	`json:"username"`
	Role 		string 	`json:"role"`
}