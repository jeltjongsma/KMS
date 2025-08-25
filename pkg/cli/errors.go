package cli

import (
	"fmt"
	"os"
)

func HandleUnexpectedError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "unexpected error: %v\n", err)
		os.Exit(1)
	}
}

func HandleFailedRequest(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		os.Exit(1)
	}
}
