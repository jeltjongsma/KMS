package httpctx

import (
	"net/http"
	kmsErrors "kms/pkg/errors"
	"context"
	"fmt"
	"kms/internal/auth"
	c "kms/internal/bootstrap/context"
)

type contextKey string
const RouteParamsCtxKey contextKey = "routeParams"
const TokenCtxKey contextKey = "token"

type AppHandler func(http.ResponseWriter, *http.Request) *kmsErrors.AppError

func WithLogging(logger c.Logger) func(AppHandler) http.Handler {
	return func(handler AppHandler) http.Handler {
		return NewAppHandler(logger, handler)
	}
}

func NewAppHandler(logger c.Logger, handler AppHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if appErr := handler(w, r); appErr != nil {
			entry := []any{
				"path", r.URL.Path,
				"code", appErr.Code,
				"message", appErr.Message,
				"error", appErr.Err,
			}
			if appErr.Code >= 500 {
				logger.Error("HTTP handler", entry...)
			} else {
				logger.Warn("HTTP handler", entry...)
			}
			http.Error(w, appErr.Message, appErr.Code)
		}
	})	
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