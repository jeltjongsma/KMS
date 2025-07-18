package auth

import (
	"kms/utils"
	"net/http"
	"context"
	"strings"	
	"kms/storage"
)

type contextKey string

const TokenCtxKey contextKey = "token"

func Authorize(jwtSecret []byte) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			bearer := strings.TrimSpace(r.Header.Get("Authorization"))
			if bearer == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			parts := strings.Split(bearer, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			tokenStr := strings.TrimSpace(parts[1])
			token, err := VerifyToken(tokenStr, jwtSecret)
			if err != nil {
				utils.HandleErrAndSendHttp(
					w,
					err,
					"Unauthorized",
					http.StatusUnauthorized,
				)
				return
			}

			ctx := context.WithValue(r.Context(), TokenCtxKey, token)

			next(w, r.WithContext(ctx))
			return
		}
	}
}

func RequireAdmin(userRepo storage.UserRepository) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token, ok := ExtractToken(r.Context())

			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			role, err := userRepo.GetRole(token.Payload.Sub)
			if utils.HandleRepoErr(w, err, "Failed to retrieve role") {return}

			if role != "admin" {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next(w, r)
		}
	}
}

func ExtractToken(ctx context.Context) (Token, bool) {
	tokenStr := ctx.Value(TokenCtxKey)
	token, ok := tokenStr.(Token)
	return token, ok
}