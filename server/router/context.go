package router

import (
	"net/http"
)

type contextKey string
const RouteParamsCtxKey contextKey = "routeParams"

func GetRouteParam(r *http.Request, key string) (string, bool) {
	params, ok := r.Context().Value(RouteParamsCtxKey).(map[string]string)
	if !ok {
		return "", false
	}

	val, found := params[key]
	return val, found
}