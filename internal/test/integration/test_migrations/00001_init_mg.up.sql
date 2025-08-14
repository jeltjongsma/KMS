CREATE TABLE IF NOT EXISTS keys (
    id SERIAL PRIMARY KEY,
    clientId INTEGER NOT NULL,
    keyReference VARCHAR(64) NOT NULL,
    version INTEGER NOT NULL,
    dek VARCHAR(80) NOT NULL,
    state VARCHAR(52) NOT NULL,
    encoding VARCHAR(64) NOT NULL,
    UNIQUE(clientId, keyReference, version)
);

CREATE TABLE IF NOT EXISTS clients (
    id SERIAL PRIMARY KEY,
    clientname VARCHAR(128) UNIQUE NOT NULL,
    hashedClientname VARCHAR(44) UNIQUE NOT NULL,
    password CHAR(60) NOT NULL,
    role VARCHAR(46) NOT NULL DEFAULT 'client'
);