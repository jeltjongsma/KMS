package router

import (
	"context"
	"fmt"
)

type contextKey string
const RouteParamsCtxKey contextKey = "routeParams"

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