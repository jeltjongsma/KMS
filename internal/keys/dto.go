package keys

type Key struct {
	ID           int    `json:"id"`
	KeyReference string `json:"keyReference"`
	DEK          string `json:"dek" encrypt:"true" encoded:"true" key:"kek"`
	ClientId     int    `json:"clientId"`
	Encoding     string `json:"encoding" encrypt:"true"`
}

type GenerateKeyRequest struct {
	KeyReference string `json:"keyReference"`
}

type KeyResponse struct {
	DEK      string `json:"dek"`
	Encoding string `json:"encoding"`
}
