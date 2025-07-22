package auth

import (
	"encoding/json"
	b64 "encoding/base64"
	"crypto/sha256"
	"crypto/hmac"
	"strings"
	"time"
	"strconv"
	"kms/internal/users"
	"kms/pkg/hashing"
	kmsErrors "kms/pkg/errors"
)

type Token struct {
	Header 		*TokenHeader
	Payload 	*TokenPayload
}

type TokenHeader struct {
	// Alg 	string	`json:"alg"`
	Typ 	string 	`json:"type"`
	Ver 	string	`json:"ver"`
}

type TokenPayload struct {
	Sub 	string	`json:"sub"`
	Ttl 	int64	`json:"ttl"`
	Iat 	int64	`json:"iat"`
	// Scp 	[]string	`json:"scp"`
}

type TokenGenInfo struct {
	Ttl		int64
	Secret 	[]byte
	Typ 	string
}

func GenerateJWT(genInfo *TokenGenInfo, user *users.User) (string, error) {
	header := TokenHeader{
		Ver: "1",
		Typ: genInfo.Typ,
	}

	payload := TokenPayload{
		Sub: strconv.Itoa(user.ID),
		Ttl: genInfo.Ttl,
		Iat: time.Now().UnixMilli(),
	}

	token := Token{
		Header: &header,
		Payload: &payload,
	}

	return GenerateToken(&token, genInfo.Secret)
}

func GenerateSignupToken(genInfo *TokenGenInfo, username string) (string, error) {
	header := TokenHeader{
		Ver: "1",
		Typ: genInfo.Typ,
	}

	payload := TokenPayload{
		Sub: username,
		Ttl: genInfo.Ttl,
		Iat: time.Now().UnixMilli(),
	}

	token := Token{
		Header: &header,
		Payload: &payload,
	}

	return GenerateToken(&token, genInfo.Secret)
}

func GenerateToken(token *Token, secret []byte) (string, error) {
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

	signature := hashing.HashHS256ToB64([]byte(message), secret)
	return message + "." + signature, nil
} 



// TODO: Check if token has been revoked (logout, invalidation)
// TODO: Invalidate tokens when server restarts
func VerifyToken(jwt string, secret []byte) (Token, error) {
	var token Token
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return token, kmsErrors.WrapError(kmsErrors.ErrInvalidToken, map[string]interface{}{
			"msg": "Not a JWT",
			"jwt": jwt,
		})
	}

	message := parts[0] + "." + parts[1]
	decodedSignature, err := b64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return token, err
	}

	if !verifyHMAC([]byte(message), decodedSignature, secret) {
		return token, kmsErrors.WrapError(kmsErrors.ErrInvalidToken, map[string]interface{}{
			"msg": "MACs don't match",
			"jwt": jwt,
		})
	}

	decodedPayload, err := b64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return token, err
	}
	var payload TokenPayload
	if err := json.Unmarshal(decodedPayload, &payload); err != nil {
		return token, err
	}

	if !verifyStillValid(&payload) {
		return token, kmsErrors.WrapError(kmsErrors.ErrInvalidToken, map[string]interface{}{
			"msg": "TTL has passed",
			"jwt": jwt,
		})
	}

	decodedHeader, err := b64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return token, err
	}
	var header TokenHeader
	if err := json.Unmarshal(decodedHeader, &header); err != nil {
		return token, err
	}

	return Token{
		Header: &header,
		Payload: &payload,
	}, nil
}

func verifyHMAC(message, signature, secret []byte) bool {
	h := hmac.New(sha256.New, secret) 
	h.Write(message)
	expectedMAC := h.Sum(nil)
	return hmac.Equal(signature, expectedMAC)
}

func verifyStillValid(payload *TokenPayload) bool {
	now := time.Now().UnixMilli()
	if now < (payload.Ttl + payload.Iat) {
		return true
	}
	return false
}
