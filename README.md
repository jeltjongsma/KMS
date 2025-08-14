# Go Key Management System (KMS)
A lightweight, self-hosted Key Management System designed for use within a single organisation, built to explore API design and security best practices. 

## Overview
This KMS provides secure creation, storage, retrieval, and basic lifecycle management of Data Encryption Keys (DEKs) using Key Encryption Keys (KEKs), with planned support for key versioning and rotation. It includes JWT-based authentication, Role-Based Access Control (RBAC), and custom key lookup through deterministically hashed references.

In this documentation "client" refers to **service account** — a non-human service within the same organisation that authenticates to the KMS.

## Features
- Client signup/login with JWT authentication
- DEK storage encrypted with KEK
- Deterministically hashed key references for lookups
- Admin-generated client signup tokens
- Workflow-oriented API design
- DEK rotation 

## Planned
- DEK and KEK versioning and rotation
- Admin CLI for client signup token generation
- Client CLI for initial setup and DEK rotation

## Workflows 
### Client registration and authentication
1. Admin generates client signup token -> `/auth/signup/generate`
2. Client registers using signup token -> `/auth/signup`
3. Client logs in to get JWT -> ```/auth/login```

### Key management
1. Generate new DEK -> `/keys/actions/generate`
2. Retrieve DEK by reference -> `/keys/{keyReference}`
3. Rotate key -> `/keys/{keyReference}/actions/rotate`

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

## Background
This project was developed as a learning exercise in secure API design and key management. My focus was on building a production-ready system with a strong security model while exploring Go, PostgreSQL, and encryption best practices.
AI was used as a brainstorming and troubleshooting tool, with all architecture, design decisions, and implementation completed manually.

## License
This project is licensed under the MIT license - see the [LICENSE](LICENSE) file for details.