# Go KMS SDK
A lightweight Go SDK for interacting with the [KMS](../../README.md).
Currently only supports key retrieval.

## Installation
```bash
go get github.com/jeltjongsma/KMS/sdk
```

## Usage
See [examples/getkey](../../examples/getkey/) for a runnable example using the SDK.

Basic flow:
1. Set the following environment variables (e.g., in a .env file)
    - `KMS_BASE_URL` The base URL of the KMS instance
    - `KMS_USER` The username of the client created in the KMS
    - `KMS_PASS` The password of the client created in the KMS
    - (Optional) `KMS_INSECURE_SKIP_VERIFY` Set to "true" to skip TLS verification (for self-signed certificates)
2. Create a new client `NewClient()`
3. Retrieve key by reference and version `(*Client).GetKey(reference, version)`

## Features
- Handles authentication (login + JWT) internally
- Provides a `GetKey(ref, version)` method 
- Manages token reuse between requests (cached until expiry)

## Future work
- Support for full key usage (e.g., `Encrypt(*KeyBundle)`, `Decrypt(*KeyBundle)`)
- SDKs in other languages (e.g., Java, Python)