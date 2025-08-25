package cli

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

func RequireName() (string, error) {
	fmt.Println("Enter name:")
	var name string
	_, err := fmt.Scanln(&name)
	if err != nil {
		return "", fmt.Errorf("error reading name: %w", err)
	}
	if name == "" {
		return "", fmt.Errorf("name cannot be empty")
	}
	return name, nil
}

func RequirePassword() (string, error) {
	fmt.Println("Enter password:")
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", fmt.Errorf("error reading password: %w", err)
	}
	password := string(passBytes)
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	return password, nil
}

func RequirePasswordTwice() (string, error) {
	fmt.Println("Enter password:")
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", fmt.Errorf("error reading password: %w", err)
	}
	password := string(passBytes)

	fmt.Println("Enter password again:")
	passBytes, err = term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", fmt.Errorf("error reading password: %w", err)
	}
	passwordRepeated := string(passBytes)

	if password != passwordRepeated {
		return "", fmt.Errorf("passwords do not match")
	}

	return password, nil
}
