package httpkit

import (
	"net/http"
	"kms/utils/kmsErrors"
	"log"
)

type AppHandler func(http.ResponseWriter, *http.Request) *kmsErrors.AppError

func (fn AppHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if appErr := fn(w, r); appErr != nil {
		log.Printf("Error: %v\n", appErr)
		http.Error(w, appErr.Message, appErr.Code)
	}
}