package handlers

import (
	"net/http"
	"kms/storage"
	"kms/server/dto"
	"kms/server/router"
	"kms/utils"
	"kms/server/auth"
	"kms/utils/encryption"
	b64 "encoding/base64"
	"unicode"
)

func MakeGenerateKeyHandler(keyRepo storage.KeyRepository, KEK []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := auth.ExtractToken(r.Context())
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var searchableId dto.GenerateKeyRequest
		if utils.DecodePayloadAndHandleError(w, r.Body, &searchableId) {return}

		if !validateSearchableId(searchableId.SearchableId) {
			http.Error(w, "Key should only contain [0-9a-Z\\-]", http.StatusBadRequest)
			return
		}

		DEKBytes, err := encryption.GenerateKey(32)
		if utils.HandleErrAndSendHttp(w, err, "Failed to generate key", http.StatusInternalServerError) {return}

		encryptedDEKBytes, err := encryption.Encrypt(DEKBytes, KEK)
		if utils.HandleErrAndSendHttp(w, err, "Failed to encrypt DEK", http.StatusInternalServerError) {return}

		DEKB64 := b64.RawURLEncoding.EncodeToString(DEKBytes)

		key := &storage.Key{
		SearchableId: searchableId.SearchableId,
			DEK: b64.RawURLEncoding.EncodeToString(encryptedDEKBytes),
			UserId: token.Payload.Sub,
			Encoding: "base64url (RFC 4648)",
		}
		_, err = keyRepo.CreateKey(key)
		if utils.HandleRepoErr(w, err, "Failed to store key") {return}

		reponse := &dto.KeyReponse{
			DEK: DEKB64,
			Encoding: key.Encoding,
		}

		utils.SendEncodedJSON(w, reponse)
		return
	}
}

// Allow 0-9, a-Z and '-' in custom key reference
func validateSearchableId(searchableId string) bool {
	for _, r := range searchableId {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-') {
			return false
		}
	}
	return true
}

func MakeGetKeyHandler(keyRepo storage.KeyRepository, KEK []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := auth.ExtractToken(r.Context())
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		searchableId, ok := router.GetRouteParam(r.Context(), "searchableId")
		if !ok {
			http.Error(w, "ID missing from path", http.StatusBadRequest)
			return
		}

		key, err := keyRepo.GetKey(token.Payload.Sub, searchableId)
		if utils.HandleRepoErr(w, err, "Failed to retrieve key") {return}

		DEKBytes, err := b64.RawURLEncoding.DecodeString(key.DEK)
		if utils.HandleErrAndSendHttp(w, err, "Failed to decode DEK", http.StatusInternalServerError) {return}

		DEK, err := encryption.Decrypt(DEKBytes, KEK)
		if utils.HandleErrAndSendHttp(w, err, "Failed to decrypt DEK", http.StatusInternalServerError) {return}

		response := &dto.KeyReponse{
			DEK: b64.RawURLEncoding.EncodeToString(DEK),
			Encoding: key.Encoding,
		}

		utils.SendEncodedJSON(w, response)
		return
	}
}

func MakeKeyHandler(keyRepo storage.KeyRepository) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
		switch r.Method {

		case http.MethodPost:
			var newKey storage.Key
			if utils.DecodePayloadAndHandleError(w, r.Body, &newKey) {return}

			id, err := keyRepo.CreateKey(&newKey)
			if utils.HandleRepoErr(w, err, "Failed to create key") {return}

			newKey.ID = id

			utils.SendEncodedJSON(w, &newKey)

		case http.MethodGet:
			keys, err := keyRepo.GetAll()
			if utils.HandleErrAndSendHttp(w, err, "Failed to retrieve keys", http.StatusInternalServerError) {return}

			utils.SendEncodedJSON(w, keys)
			return

		default:
			utils.ReturnMethodNotAllowed(w)
		}
	}
}
