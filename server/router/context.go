package router

import (
	"context"
)

type contextKey string
const RouteParamsCtxKey contextKey = "routeParams"

func GetRouteParam(ctx context.Context, key string) (string, bool) {
	params, ok := ctx.Value(RouteParamsCtxKey).(map[string]string)
	if !ok {
		return "", false
	}

	val, found := params[key]
	return val, found
}