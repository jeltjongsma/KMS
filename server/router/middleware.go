package router
import (
	"net/http"
	"strings"
	"context"
	"kms/server/httpkit"
	"kms/utils/kmsErrors"
	"fmt"
)


type Route struct {
	Method 	string
	Pattern	string
	Handler httpkit.AppHandler
}

func NewRoute(method, pattern string, handler httpkit.AppHandler) *Route {
	return &Route{
		Method: method,
		Pattern: pattern,
		Handler: handler,
	}
} 

func MakeRouter(routes []*Route) httpkit.AppHandler {
	return func(w http.ResponseWriter, r *http.Request) *kmsErrors.AppError {
		for _, route := range routes {
			if params, ok := matchPattern(route, r); ok {
				ctx := context.WithValue(r.Context(), RouteParamsCtxKey, params)
				return route.Handler(w, r.WithContext(ctx))
			} 
		}
		return kmsErrors.NewAppError(
			fmt.Errorf("Path does not exist: [%v] %v\n", r.Method, r.URL.Path),
			"Not found",
			404,
		)
	}
}

func matchPattern(route *Route, r *http.Request) (map[string]string, bool) {
	if r.Method != route.Method {
		return nil, false
	}

	routeParts := strings.Split(strings.Trim(route.Pattern, "/"), "/")
	reqParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")

	if len(reqParts) != len(routeParts) {
		return nil, false
	}

	params := make(map[string]string)
	for idx, routePart := range routeParts {
		// Compare
		if routePart == reqParts[idx] {
			continue
		}
		// Check if param
		if strings.HasPrefix(routePart, "{") && strings.HasSuffix(routePart, "}") {
			params[strings.Trim(routePart, "{}")] = reqParts[idx]
			continue
		} 	
		return nil, false
	}
	return params, true
}
