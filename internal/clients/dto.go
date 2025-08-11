package clients

type Client struct {
	ID               int    `json:"id"`
	Clientname       string `json:"clientname" encrypt:"true"`
	HashedClientname string `json:"hashedClientname"`
	Password         string `json:"password"`
	Role             string `json:"role" encrypt:"true"`
}
