package main

import (
	"encoding/json"
	"fmt"
	"kms/pkg/sdk"
	"log"

	"github.com/joho/godotenv"
)

// Example: Fetch a key from the KMS
//
// Prequisites:
//   - A running KMS instance
//   - A user created in the KMS
//   - A key created in the KMS using the kms-client CLI tool
//   - The following environment variables set (e.g., in a .env file):
//     KMS_BASE_URL: The base URL of the KMS instance (e.g., https://localhost:8443)
//     KMS_USER: The username of the user created in the KMS
//     KMS_PASS: The password of the user created in the KMS
//     (Optional) KMS_INSECURE_SKIP_VERIFY: Set to "true" to skip TLS verification (for self-signed certificates)
//
// Run the example:
//
//	go run example/getkey/main.go
func main() {
	if err := godotenv.Load("./example/.env"); err != nil {
		log.Printf("No .env file found or error loading it: %v", err)
	}

	// Create a new KMS client
	client, err := sdk.NewClient()
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	// Fetch the key with reference "example-key" and version 1
	bundle, err := client.GetKey("example-key", 1)
	if err != nil {
		log.Fatalf("failed to get key: %v", err)
	}

	b, _ := json.MarshalIndent(bundle, "", "  ")
	fmt.Println(string(b))
}
