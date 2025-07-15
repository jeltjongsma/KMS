package auth

import (
	"encoding/json"
	b64 "encoding/base64"
	"crypto/sha256"
	"crypto/hmac"
	"strings"
	"strconv"
	"fmt"
	"time"
)

type Token struct {
	Header 		*TokenHeader
	Payload 	*TokenPayload
}

type TokenHeader struct {
	// Alg 	string	`json:"alg"`
	// Typ 	string 	`json:"type"`
	Ver 	string	`json:"ver"`
}

type TokenPayload struct {
	Sub 	int		`json:"sub"`
	Ttl 	int		`json:"ttl"`
	Iat 	int64	`json:"iat"`
	// Scp 	[]string	`json:"scp"`
}

func GenerateJWT(cfg map[string]string, userId int) (string, error) {
	header := TokenHeader{
		Ver: "1",
	}
	ttl, err := strconv.Atoi(cfg["JWT_TTL"])
	if err != nil {
		return "", err
	}
	payload := TokenPayload{
		Sub: userId,
		Ttl: ttl,
		Iat: time.Now().UnixMilli(),
	}

	token := Token{
		Header: &header,
		Payload: &payload,
	}

	return GenerateToken(token, []byte(cfg["JWT_SECRET"]))
}

func GenerateToken(token Token, secret []byte) (string, error) {
	headerBytes, err := json.Marshal(*token.Header)
	if err != nil {
		return "", err
	}
	headerB64 := b64.RawURLEncoding.EncodeToString(headerBytes)

	payloadBytes, err := json.Marshal(*token.Payload)
	if err != nil {
		return "", err
	}
	payloadB64 := b64.RawURLEncoding.EncodeToString(payloadBytes)

	message := headerB64 + "." + payloadB64

	signature := signHMAC([]byte(message), secret)
	return message + "." + signature, nil
} 

func signHMAC(message, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write(message)
	signature := h.Sum(nil)
	return b64.RawURLEncoding.EncodeToString(signature)
}

func VerifyToken(jwt string, secret []byte) (Token, error) {
	var token Token
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {return token, fmt.Errorf("Not a JWT")}

	message := parts[0] + "." + parts[1]
	signature := parts[2]

	if verifyHMAC([]byte(message), []byte(signature), secret) {
		decodedHeader, err := b64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return token, err
		}
		var header TokenHeader
		if err := json.Unmarshal(decodedHeader, &header); err != nil {
			return token, err
		}

		decodedPayload, err := b64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return token, err
		}
		var payload TokenPayload
		if err := json.Unmarshal(decodedPayload, &payload); err != nil {
			return token, err
		}

		return Token{
			Header: &header,
			Payload: &payload,
		}, nil
	}
	return token, fmt.Errorf("MACs don't match")
}

func verifyHMAC(message, signature, secret []byte) bool {
	h := hmac.New(sha256.New, secret) 
	h.Write(message)
	expectedMAC := h.Sum(nil)
	return hmac.Equal(signature, expectedMAC)
}

