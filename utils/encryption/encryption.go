package encryption

import (
	"crypto/rand"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"fmt"
)

func Encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func Decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("Ciphertext too short\n")
	}

	nonce := ciphertext[:nonceSize]
	ciphertextOnly := ciphertext[nonceSize:]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertextOnly, nil) 
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func GenerateKey(nBytes int) ([]byte, error) {
	buf := make([]byte, nBytes)
	_, err := rand.Read(buf)
	return buf, err
}
