package utils

import (
	"errors"
	"database/sql"
	"net/http"
    "github.com/lib/pq"
	"fmt"
)

var ErrNoRowsAffected = errors.New("No rows affected")

func HandleRepoErr(w http.ResponseWriter, err error, msg string) bool {
	if errors.Is(err, sql.ErrNoRows) {
		fmt.Println("SQL No rows error: ", err)
		http.Error(w, "Entity not found", http.StatusNotFound)
		return true
	}
	if pqErr, ok := err.(*pq.Error); ok {
		if pqErr.Code == "23505" {
			fmt.Println("Unique constraint violated: ", err)
			http.Error(w, "Unique constraint violated", http.StatusConflict)
			return true
		}
	}
	if errors.Is(err, ErrNoRowsAffected) {
		fmt.Println("No rows affected: ", err)
		http.Error(w, "User not found", http.StatusNotFound)
	}
	if HandleErrAndSendHttp(w, err, msg, http.StatusInternalServerError) {return true}
	return false
}