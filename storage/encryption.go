package storage

import (
	"kms/utils/encryption"
	"reflect"
	b64 "encoding/base64"
	"fmt"
	"strings"
)

type EncryptedKeyRepo struct {
	KeyRepo 	KeyRepository 
	KEK 		[]byte
}

func NewEncryptedKeyRepo(keyRepo KeyRepository, kek []byte) *EncryptedKeyRepo {
	return &EncryptedKeyRepo{
		KeyRepo: keyRepo,
		KEK: kek,
	}
}

func (r *EncryptedKeyRepo) CreateKey(key *Key) (*Key, error) {
	encKey := &Key{}
	if err := encryptFields(encKey, key, r.KEK); err != nil {
		return nil, err
	}
	stored, err := r.KeyRepo.CreateKey(encKey)
	if err != nil {
		return nil, err
	}
	retKey := &Key{}
	if err := decryptFields(retKey, stored, r.KEK); err != nil {
		return nil, err
	}
	return retKey, nil
}

func (r *EncryptedKeyRepo) GetKey(id int, keyReference string) (*Key, error) {
	key, err := r.KeyRepo.GetKey(id, keyReference) 
	if err != nil {
		return nil, err
	}

	retKey := &Key{}
	if err := decryptFields(retKey, key, r.KEK); err != nil {
		return nil, err
	}

	return retKey, nil
}

func (r *EncryptedKeyRepo) GetAll() ([]Key, error) {
	return r.KeyRepo.GetAll()
}

func encryptFields(dst, src *Key, kek []byte) error {
	vSrc := reflect.ValueOf(src).Elem()
	vDst := reflect.ValueOf(dst).Elem()
	tSrc := vSrc.Type()

	for i := 0; i < tSrc.NumField(); i++ {
		vSrcField := vSrc.Field(i)
		vDstField := vDst.Field(i)
		tSrcField := tSrc.Field(i)

		if !vDstField.CanSet() {
			return fmt.Errorf("Unable to set field: %v", tSrcField.Name)
		}

		if tSrcField.Tag.Get("encrypt") == "true" {
			isEncoded := tSrcField.Tag.Get("encoded") == "true"
						
			toEncrypt, ok := vSrcField.Interface().(string)
			if !ok {
				return fmt.Errorf("Field %s marked for encryption but is not a string", tSrcField.Name)
			}

			// Only decode to base64 if decrypted value is encoded in base64
			var decoded []byte
			var err error
			if isEncoded {
				decoded, err = b64.RawURLEncoding.DecodeString(toEncrypt)
				if err != nil {
					return fmt.Errorf("Failed to decode field %s: %w", tSrcField.Name, err)
				}
			} else {
				decoded = []byte(toEncrypt)
			}

			encrypted, err := encryption.Encrypt(decoded, kek)
			if err != nil {
				return fmt.Errorf("Failed to encrypt field %s: %w", tSrcField.Name, err)
			}

			// Always encode encrypted values
			encoded := b64.RawURLEncoding.EncodeToString(encrypted)

			vDstField.SetString(encoded)
		} else {
			vDstField.Set(vSrcField)
		}	
	}

	return nil
}

func decryptFields(dst, src *Key, kek []byte) error {
	vSrc := reflect.ValueOf(src).Elem()
	vDst := reflect.ValueOf(dst).Elem()
	tSrc := vSrc.Type()

	for i := 0; i < tSrc.NumField(); i++ {
		vSrcField := vSrc.Field(i)
		vDstField := vDst.Field(i)
		tSrcField := tSrc.Field(i)

		if !vDstField.CanSet() {
			return fmt.Errorf("Unable to set field: %v", tSrcField.Name)
		}

		if tSrcField.Tag.Get("encrypt") == "true" {
			isEncoded := tSrcField.Tag.Get("encoded") == "true"

			toDecrypt, ok := vSrcField.Interface().(string)
			if !ok {
				return fmt.Errorf("Field %s marked for decryption but is not a string", tSrcField.Name)
			}

			// Always decode encrypted values
			decoded, err := b64.RawURLEncoding.DecodeString(toDecrypt)
			if err != nil {
				return fmt.Errorf("Failed to decode field %s: %w", tSrcField.Name, err)
			}

			decrypted, err := encryption.Decrypt(decoded, kek)
			if err != nil {
				return fmt.Errorf("Failed to decrypt field %s: %w", tSrcField.Name, err)
			}

			// Only encode to base64 if decrypted is base64
			var encoded string
			if isEncoded {
				encoded = b64.RawURLEncoding.EncodeToString(decrypted)
			} else {
				encoded = string(decrypted)
			}
			
			vDstField.SetString(encoded)
		} else {
			vDstField.Set(vSrcField)
		}	
	}

	return nil
}
