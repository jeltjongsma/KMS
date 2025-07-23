package keys

type Key struct {
	ID 				int 	`json:"id"`
	KeyReference	string 	`json:"keyReference"` 
	DEK 			string 	`json:"dek" encrypt:"true" encoded:"true" key:"kek"`
	UserId			int		`json:"userId"`
	Encoding 		string 	`json:"encoding" encrypt:"true"`
}

type GenerateKeyRequest struct {
	KeyReference 	string 	`json:"keyReference"`
}

type KeyReponse struct {
	DEK			string 	`json:"dek"`
	Encoding 	string 	`json:"encoding"`
}
