package keys

const (
	StateInUse      = "in-use"
	StateDeprecated = "deprecated"
	StateRetired    = "retired"
)

type Key struct {
	ID           int    `json:"id"`
	ClientId     int    `json:"clientId"`
	KeyReference string `json:"keyReference"`
	Version      int    `json:"version"`
	DEK          string `json:"dek" encrypt:"true" encoded:"true" key:"kek"`
	State        string `json:"state" encrypt:"true"`
	Encoding     string `json:"encoding" encrypt:"true"`
}

type GenerateKeyRequest struct {
	KeyReference string `json:"keyReference"`
}

type KeyResponse struct {
	DEK      string `json:"dek"`
	Version  int    `json:"version"`
	Encoding string `json:"encoding"`
}

func BuildKeyResponse(k *Key) *KeyResponse {
	return &KeyResponse{
		DEK:      k.DEK,
		Version:  k.Version,
		Encoding: k.Encoding,
	}
}
