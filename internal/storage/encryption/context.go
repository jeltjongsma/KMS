package encryption

import (
	"reflect"
	b64 "encoding/base64"
	kmsErrors "kms/pkg/errors"
	"kms/pkg/encryption"
	c "kms/internal/bootstrap/context"
)


func EncryptFields(dst, src any, keyManager c.KeyManager) error {
	vSrc := reflect.ValueOf(src)
	vDst := reflect.ValueOf(dst)
	if vSrc.Kind() != reflect.Ptr || vDst.Kind() != reflect.Ptr {
		return kmsErrors.WrapError(kmsErrors.ErrRepoEncryption, map[string]interface{}{
			"msg": "src and dst must be pointers",
		})
	}

	vSrc = vSrc.Elem()
	vDst = vDst.Elem()
	if vSrc.Kind() != reflect.Struct || vDst.Kind() != reflect.Struct {
		return kmsErrors.WrapError(kmsErrors.ErrRepoEncryption, map[string]interface{}{
			"msg": "src and dst must point to structs",
		})
	}

	if vSrc.Type() != vDst.Type() {
		return kmsErrors.WrapError(kmsErrors.ErrRepoEncryption, map[string]interface{}{
			"msg": "src and dst must be the same struct type",
		})
	}

	tSrc := vSrc.Type()

	for i := 0; i < tSrc.NumField(); i++ {
		vSrcField := vSrc.Field(i)
		vDstField := vDst.Field(i)
		tSrcField := tSrc.Field(i)

		if !vDstField.CanSet() {
			return kmsErrors.WrapError(kmsErrors.ErrRepoEncryption, map[string]interface{}{
				"msg": "Unable to set field",
				"field": vDstField,
			})
		}

		if tSrcField.Tag.Get("encrypt") == "true" {
			isEncoded := tSrcField.Tag.Get("encoded") == "true"
						
			toEncrypt, ok := vSrcField.Interface().(string)
			if !ok {
				return kmsErrors.WrapError(kmsErrors.ErrRepoEncryption, map[string]interface{}{
					"msg": "Field marked for encryption but is not a string",
					"field": tSrcField.Name,
				})
			}

			// Only decode to base64 if decrypted value is encoded in base64
			var decoded []byte
			var err error
			if isEncoded {
				decoded, err = b64.RawURLEncoding.DecodeString(toEncrypt)
				if err != nil {
					return kmsErrors.WrapError(kmsErrors.ErrRepoEncryption, map[string]interface{}{
						"msg": "Failed to decode field",
						"field": tSrcField.Name,
						"err": err,
					})
				}
			} else {
				decoded = []byte(toEncrypt)
			}

			var encrypted []byte
			if tSrcField.Tag.Get("key") == "kek" {
				encrypted, err = encryption.Encrypt(decoded, keyManager.KEK())
			} else {
				encrypted, err = encryption.Encrypt(decoded, keyManager.DBKey())
			}
			if err != nil {
				return kmsErrors.WrapError(kmsErrors.ErrRepoEncryption, map[string]interface{}{
					"msg": "Failed to encrypt field",
					"field": tSrcField.Name,
					"err": err,
				})
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

func DecryptFields(dst, src any, keyManager c.KeyManager) error {
	vSrc := reflect.ValueOf(src)
	vDst := reflect.ValueOf(dst)
	if vSrc.Kind() != reflect.Ptr || vDst.Kind() != reflect.Ptr {
		return kmsErrors.WrapError(kmsErrors.ErrRepoEncryption, map[string]interface{}{
			"msg": "src and dst must be pointers",
		})
	}

	vSrc = vSrc.Elem()
	vDst = vDst.Elem()
	if vSrc.Kind() != reflect.Struct || vDst.Kind() != reflect.Struct {
		return kmsErrors.WrapError(kmsErrors.ErrRepoEncryption, map[string]interface{}{
			"msg": "src and dst must point to structs",
		})
	}

	if vSrc.Type() != vDst.Type() {
		return kmsErrors.WrapError(kmsErrors.ErrRepoEncryption, map[string]interface{}{
			"msg": "src and dst must be the same struct type",
		})
	}

	tSrc := vSrc.Type()

	for i := 0; i < tSrc.NumField(); i++ {
		vSrcField := vSrc.Field(i)
		vDstField := vDst.Field(i)
		tSrcField := tSrc.Field(i)

		if !vDstField.CanSet() {
			return kmsErrors.WrapError(kmsErrors.ErrRepoEncryption, map[string]interface{}{
				"msg": "Unable to set field",
				"field": vDstField,
			})
		}

		if tSrcField.Tag.Get("encrypt") == "true" {
			isEncoded := tSrcField.Tag.Get("encoded") == "true"

			toDecrypt, ok := vSrcField.Interface().(string)
			if !ok {
				return kmsErrors.WrapError(kmsErrors.ErrRepoEncryption, map[string]interface{}{
					"msg": "Field marked for decryption but is not a string",
					"field": tSrcField.Name,
				})
			}
			// Always decode encrypted values
			decoded, err := b64.RawURLEncoding.DecodeString(toDecrypt)
			if err != nil {
				return kmsErrors.WrapError(kmsErrors.ErrRepoEncryption, map[string]interface{}{
					"msg": "Failed to decode field",
					"field": tSrcField.Name,
					"err": err,
				})
			}

			var decrypted []byte
			if tSrcField.Tag.Get("key") == "kek" {
				decrypted, err = encryption.Decrypt(decoded, keyManager.KEK())
			} else {
				decrypted, err = encryption.Decrypt(decoded, keyManager.DBKey())
			}
			if err != nil {
				return kmsErrors.WrapError(kmsErrors.ErrRepoEncryption, map[string]interface{}{
					"msg": "Failed to decrypt field",
					"field": tSrcField.Name,
					"err": err,
				})
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

func EncryptString(str string, key []byte) (string, error) {
	encrypted, err := encryption.Encrypt([]byte(str), key)
	if err != nil {
		return "", err
	}
	return b64.RawURLEncoding.EncodeToString(encrypted), nil
}

func DecryptString(str string, key []byte) (string, error) {
	decoded, err := b64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return "", err
	}
	decrypted, err := encryption.Decrypt(decoded, key)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}