package middleware

import (
	"context"
	"errors"
	"fmt"
	"kms/internal/httpctx"
	kmsErrors "kms/pkg/errors"
	"net/http"
	"strings"
)

type Route struct {
	Method  string
	Pattern string
	Handler httpctx.AppHandler
}

func NewRoute(method, pattern string, handler httpctx.AppHandler) *Route {
	return &Route{
		Method:  method,
		Pattern: pattern,
		Handler: handler,
	}
}

func MakeRouter(routes []*Route) httpctx.AppHandler {
	return func(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
		for _, route := range routes {
			params, err := matchPattern(route, r)
			if err != nil {
				if strings.Contains(err.Error(), "method not allowed") {
					return kmsErrors.NewAppError(err, "Method not allowed", 405)
				}
				continue
			}
			ctx := context.WithValue(r.Context(), httpctx.RouteParamsCtxKey, params)
			return route.Handler(w, r.WithContext(ctx))
		}
		return kmsErrors.NewAppError(
			fmt.Errorf("path does not exist: [%v] %v", r.Method, r.URL.Path),
			"Not found",
			404,
		)
	}
}

// FIXME: Allows GET "/keys/generate" (POST-only path) to fall through to GET "/keys/{keyReference}"
func matchPattern(route *Route, r *http.Request) (map[string]string, error) {
	methodMatch := true
	if r.Method != route.Method {
		methodMatch = false
	}

	routeParts := strings.Split(strings.Trim(route.Pattern, "/"), "/")
	reqParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")

	if len(reqParts) != len(routeParts) {
		return nil, errors.New("lengths don't match")
	}

	params := make(map[string]string)
	for idx, routePart := range routeParts {
		// Check if param
		if strings.HasPrefix(routePart, "{") && strings.HasSuffix(routePart, "}") {
			params[strings.Trim(routePart, "{}")] = reqParts[idx]
			continue
		}
		// Compare
		if routePart == reqParts[idx] {
			continue
		}
		return nil, errors.New("paths don't match")
	}
	if !methodMatch {
		return nil, errors.New("method not allowed")
	}
	return params, nil
}
