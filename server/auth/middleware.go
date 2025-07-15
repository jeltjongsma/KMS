package auth

import (
	"kms/utils"
	"net/http"
	"strings"
	"log"
)

type AuthorizedHandlerFunc func(http.ResponseWriter, *http.Request, Token) 

func Authorize(cfg map[string]string, next AuthorizedHandlerFunc) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request) {
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
		token, err := VerifyToken(tokenStr, []byte(cfg["JWT_SECRET"]))
		if err != nil {
			utils.HandleErrAndSendHttp(
				w,
				err,
				"Unauthorized",
				http.StatusUnauthorized,
			)
			return
		}

		next(w, r, token)
	}
}