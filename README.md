# Go Key Management System (KMS)
A lightweight, self-hosted Key Management System designed for use within a single organisation, built to explore API design and security best practices. 

## Overview
This KMS provides secure creation, storage, retrieval, and basic lifecycle management of Data Encryption Keys (DEKs) using Key Encryption Keys (KEKs). It includes JWT-based authentication, Role-Based Access Control (RBAC), an admin CLI for KMS management, and a client CLI for key management.

In this documentation "client" refers to **service account** — a non-human service within the same organisation that authenticates to the KMS.

## Features
- Client signup/login with JWT authentication
- DEK storage encrypted with KEK
- Deterministically hashed key references for secure lookups
- Admin-generated client signup tokens
- Workflow-oriented API design
- DEK rotation and versioning (`in-use | deprecated`)
- Admin CLI (`kms-admin`) for generating signup tokens, which must be run locally on the KMS host
- Client CLI (`kms-client`) for key lifecycle management
- Lightweight [Go SDK](./pkg/sdk/README.md) for key retrieval  

## Workflows 
### Client registration and authentication
1. Generate client signup token -> `/auth/signup/generate` || `kms-admin generate_signup --name <client name> [--ttl <token's time-to-live in ms]`
2. Register using signup token -> `/auth/signup` || `kms-client signup --token <signup token>`
3. Login to get JWT -> `/auth/login`

*Note:* `/auth/signup/generate` *was implemented first to get a working system. 
The* `kms-admin` *CLI was added later to reduce the attack surface by restricting admin operations to local use on the host machine. 
I kept both to demonstrate my progression from a minimal working system toward a more secure design.*

### Key management
1. Generate -> `/keys/actions/generate` || `kms-client generate --ref <key reference>`
2. Retrieve -> `/keys/{keyReference}/{version}` || `client.GetKey(ref, version)`
3. Rotate -> `/keys/{keyReference}/actions/rotate` || `kms-client rotate --ref <key reference>`
4. Delete -> `/keys/{keyReference}/actions/delete` || `kms-client delete --ref <key reference>`

## Installation and setup
```bash
# Clone the repo
git clone https://github.com/jeltjongsma/KMS.git

cd kms

# Copy variables from .env.example into .env and define them
# Keys should be 32 bytes, encoded with base64url (RFC 4648)
cp .env.example .env

# Run the application
go run ./cmd/kms/main.go
```

## Testing
Unit and integration tests are included for core functionality (auth, key management, encryption).
```bash
# Run all tests
go test ./...

# Skip integration tests
go test ./... -short
```

## Background
This project was developed as a learning exercise in secure API design and key management. 
My focus was on building a production-ready system with a strong security model while exploring Go, PostgreSQL, and encryption best practices.

To deepen my understanding, I deliberately avoided third-party libraries wherever possible and implemented almost everything myself. 
This includes JWT handling, encryption wrappers, simple migrations and logging, routing, and database transactions.
In a production system, these would typically be provided by well-tested libraries, but my goal was to explore the underlying implementations.

AI was used as a brainstorming and troubleshooting tool, with all architecture, design decisions, and implementation completed manually.

## Future work
This project was scoped as a learning exercise, so not all features of a production-grade KMS are implemented.
Possible future improvements could include:
- Full DEK lifecycle (`in-use | deprecated | retired`)  
- Automatic DEK rotation  
- Support for (automatic) KEK rotation and versioning  
- Audit logging and monitoring
- Support for full key usage in Go SDK (e.g., `Encrypt(*KeyBundle)`, `Decrypt(*KeyBundle)`)
- SDKs in other languages (e.g., Java, Python)  

## License
This project is licensed under the MIT license - see the [LICENSE](LICENSE) file for details.