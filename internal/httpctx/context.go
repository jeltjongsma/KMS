package httpctx

import (
	"net/http"
	"log"
	kmsErrors "kms/pkg/errors"
	"context"
	"fmt"
	"kms/internal/auth"
)

type contextKey string
const RouteParamsCtxKey contextKey = "routeParams"
const TokenCtxKey contextKey = "token"

type AppHandler func(http.ResponseWriter, *http.Request) *kmsErrors.AppError

func (fn AppHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if appErr := fn(w, r); appErr != nil {
		log.Printf("Error:\n\tHTTP [%d] %v\n\t%v\n", appErr.Code, appErr.Message, appErr.Err)
		http.Error(w, appErr.Message, appErr.Code)
	}
}

func GetRouteParam(ctx context.Context, key string) (string, error) {
	params, ok := ctx.Value(RouteParamsCtxKey).(map[string]string)
	if !ok {
		return "", fmt.Errorf("No route params in context")
	}

	val, found := params[key]
	if !found {
		return "", fmt.Errorf("Param (%v) not in path", key)
	}
	return val, nil
}

func ExtractToken(ctx context.Context) (*auth.Token, error) {
	tokenStr := ctx.Value(TokenCtxKey)
	token, ok := tokenStr.(auth.Token)
	if !ok {
		return nil, fmt.Errorf("No token in context")
	}
	return &token, nil
}