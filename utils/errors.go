package utils

import (
	"log"
)

func HandleErr(err error, msg string) {
	if err != nil {
		log.Printf("%v: %v\n", msg, err)
	}
}
