package middleware 

import (
	"net/http"
	"context"
	"strings"	
	"fmt"
	"strconv"
	"kms/internal/httpctx"
	"kms/internal/users"
	kmsErrors "kms/pkg/errors"
	"kms/internal/auth"
)


func Authorize(jwtSecret []byte) func(httpctx.AppHandler) httpctx.AppHandler {
	return func(next httpctx.AppHandler) httpctx.AppHandler {
		return func(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
			bearer := strings.TrimSpace(r.Header.Get("Authorization"))
			if bearer == "" {
				return kmsErrors.NewAppError(
					fmt.Errorf("Bearer token missing\n"),
					"Unauthorized",
					401,
				)
			}

			parts := strings.Split(bearer, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				return kmsErrors.NewAppError(
					fmt.Errorf("Invalid bearer token: %v\n", bearer),
					"Unauthorized",
					401,
				)
			}

			tokenStr := strings.TrimSpace(parts[1])
			token, err := auth.VerifyToken(tokenStr, jwtSecret)
			if err != nil {
				return kmsErrors.MapVerifyTokenErr(err)
			}

			if token.Header.Typ != "jwt" {
				return kmsErrors.NewAppError(
					kmsErrors.WrapError(kmsErrors.ErrInvalidToken, map[string]interface{}{
						"msg": "Token should be of type 'jwt'",
						"typ": token.Header.Typ,
					}),
					"Unauthorized", 
					401,
				)
			}

			ctx := context.WithValue(r.Context(), httpctx.TokenCtxKey, token)

			return next(w, r.WithContext(ctx))
		}
	}
}

func RequireAdmin(userRepo users.UserRepository) func(httpctx.AppHandler) httpctx.AppHandler {
	return func(next httpctx.AppHandler) httpctx.AppHandler {
		return func(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
			token, err := httpctx.ExtractToken(r.Context())
			if err != nil {
				return kmsErrors.NewInternalServerError(err)
			}

			userId, err := strconv.Atoi(token.Payload.Sub)
			if err != nil {
				return kmsErrors.NewInternalServerError(err)
			}

			role, err := userRepo.GetRole(userId)
			if err != nil {
				return kmsErrors.MapRepoErr(err)
			}

			if role != "admin" {
				return kmsErrors.NewAppError(
					fmt.Errorf("Forbidden role (%v)\n", role),
					"Forbidden",
					403,
				)
			}

			return next(w, r)
		}
	}
}
