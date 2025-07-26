package httpctx

import (
	"context"
	"fmt"
	"kms/internal/auth"
	c "kms/internal/bootstrap/context"
	kmsErrors "kms/pkg/errors"
	"kms/pkg/id"
	"net/http"
	"time"
)

type contextKey string

const RouteParamsCtxKey contextKey = "routeParams"
const TokenCtxKey contextKey = "token"
const RequestIDKey contextKey = "requestId"

type AppHandler func(http.ResponseWriter, *http.Request) *kmsErrors.AppError

func GlobalAppHandler(logger c.Logger) func(AppHandler) http.Handler {
	return func(handler AppHandler) http.Handler {
		return NewAppHandler(logger, handler)
	}
}

func NewAppHandler(logger c.Logger, handler AppHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate UUID for request and set response header
		reqID, err := id.GenerateUUID()
		if err != nil {
			logger.Error("HTTP handler", "message", "Failed to generate UUID for request", "error", err)
			http.Error(w, "Internal server error", 500)
			return
		}
		w.Header().Set("X-Request-ID", reqID)

		// Add UUID to request context
		ctx := context.WithValue(r.Context(), RequestIDKey, reqID)
		r = r.WithContext(ctx)

		// Log request start
		start := time.Now()
		logger.Info("HTTP request start",
			"requestId", reqID,
			"method", r.Method,
			"path", r.URL.Path,
		)

		rec := newStatusRecorder(w)

		// Handle error
		if appErr := handler(rec, r); appErr != nil {
			entry := []any{
				"requestId", reqID,
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
			return
		}

		// Log request finished
		logger.Info("HTTP request finished",
			"requestId", reqID,
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.statusCode,
			"durationMs", time.Since(start).Milliseconds(),
		)
	})
}

func GetRouteParam(ctx context.Context, key string) (string, error) {
	params, ok := ctx.Value(RouteParamsCtxKey).(map[string]string)
	if !ok {
		return "", fmt.Errorf("no route params in context")
	}

	val, found := params[key]
	if !found {
		return "", fmt.Errorf("param (%v) not in path", key)
	}
	return val, nil
}

func ExtractToken(ctx context.Context) (*auth.Token, error) {
	tokenStr := ctx.Value(TokenCtxKey)
	token, ok := tokenStr.(auth.Token)
	if !ok {
		return nil, fmt.Errorf("no token in context")
	}
	return &token, nil
}
