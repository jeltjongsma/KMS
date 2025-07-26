package httpctx

import (
	"net/http"
)

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func newStatusRecorder(w http.ResponseWriter) *statusRecorder {
	return &statusRecorder{
		ResponseWriter: w,
		statusCode:     200,
	}
}

func (rec *statusRecorder) WriteHeader(code int) {
	rec.statusCode = code
	rec.ResponseWriter.WriteHeader(code)
}
