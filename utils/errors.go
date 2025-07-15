package utils

import (
	"log"
	"errors"
	"database/sql"
	"net/http"
    "github.com/lib/pq"
)

func HandleErr(err error, msg string) {
	if err != nil {
		log.Printf("%v: %v\n", msg, err)
	}
}

func HandleRepoErr(w http.ResponseWriter, err error, msg string) bool {
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "Entity not found", http.StatusNotFound)
		return true
	}
	if pqErr, ok := err.(*pq.Error); ok {
		if pqErr.Code == "23505" {
			http.Error(w, "Unique constraint violated", http.StatusConflict)
			return true
		}
	}
	if HandleErrAndSendHttp(w, err, msg, http.StatusInternalServerError) {return true}
	return false
}