package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "signup":
		runSignup(os.Args[2:])
	case "generate":
		runGenerate(os.Args[2:])
	case "rotate":
		runRotate(os.Args[2:])
	case "delete":
		runDelete(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `kms-cli commands:
	signup --token <signup token>
	generate --ref <key reference> 
	rotate --ref <key reference>
	delete --ref <key reference>
	`)
}
