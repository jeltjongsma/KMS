package infra

import (
	"database/sql"
)

type AppContext struct {
	Cfg		 		KmsConfig
	JWTSecret 		[]byte
	KEK				[]byte
	KeyRefSecret	[]byte
	DB 				*sql.DB
}