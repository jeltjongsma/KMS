package postgres 

import (
	"fmt"
	"database/sql"
	"strings"
	"log"
)

type TableSchema struct {
	Name	string 
	Fields 	map[string]string
	Keys 	[]string
}

func createTable(db *sql.DB, schema *TableSchema) error {
	var builder strings.Builder
	stdStr := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %v (", schema.Name)
	builder.WriteString(stdStr)

	for idx, key := range schema.Keys {
		column := fmt.Sprintf("%v %v", key, schema.Fields[key])
		builder.WriteString(column)
		if idx < len(schema.Keys) - 1 {
			builder.WriteString(",")
		}
	}
	builder.WriteString(")")

	_, err := db.Exec(builder.String())
	return err
}

func dropTable(db *sql.DB, name string) error {
	query := fmt.Sprintf("DROP TABLE %v", name)
	_, err := db.Exec(query)
	return err
}

func InitSchema(db *sql.DB, schemas []TableSchema, clearTables bool) error {
	if clearTables {
		for _, schema := range schemas {
			if err := dropTable(db, schema.Name); err != nil {
				log.Println("Failed to drop table: ", err)
			}
		}
	}
	for _, schema := range schemas {
		if err := createTable(db, &schema); err != nil {
			return err
		}
	}
	return nil
}