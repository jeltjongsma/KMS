package server

import (
	"database/sql"
	"net/http"
	"kms/server/handlers"
)

func RegisterRoutes(db *sql.DB) {

	http.HandleFunc("/keys", handlers.MakeKeyHandler(db))
	http.HandleFunc("/keys/", handlers.MakeKeyByIDHandler(db))
	
	// http.HandleFunc("/keys/add", func (w http.ResponseWriter, req *http.Request) {
	// 	defer req.Body.Close()
		
	// 	var payload Test
	// 	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
	// 		http.Error(w, "Invalid request", http.StatusBadRequest)
	// 		return
	// 	}

	// 	err := db.QueryRow(
	// 		"INSERT INTO users (name, age) VALUES ($1, $2) RETURNING id", 
	// 		&payload.Name, &payload.Age,
	// 	).Scan(&payload.ID)
	// 	handleErr(err, "Insert failed")

	// 	w.Header().Set("Content-Type", "application/json")

	// 	json.NewEncoder(w).Encode(&payload)
	// })

	// http.HandleFunc("/users/", func (w http.ResponseWriter, r *http.Request) {
	// 	if r.Method != "GET" {
	// 		http.Error(w, "Wrong method", http.StatusBadRequest)
	// 		return 
	// 	}
	// 	path := r.URL.Path
	// 	parts := strings.Split(path, "/")
	// 	log.Println(path)
	// 	log.Println(parts)
	// 	log.Println(len(parts))
	// 	if len(parts) == 3 && parts[2] != "" {
	// 		log.Println("Reached ID getter")
	// 		id := parts[2]
	// 		log.Println(id)
	// 		row := db.QueryRow("SELECT * FROM users WHERE id = $1", id)

	// 		var person Test
	// 		err := row.Scan(&person.ID, &person.Name, &person.Age)
	// 		if errors.Is(err, sql.ErrNoRows) {
	// 			http.Error(w, "User not found", http.StatusNotFound)
	// 			return
	// 		}
	// 		handleErr(err, "Couldn't parse row to person")

	// 		w.Header().Set("Content-Type", "application/json")
	// 		json.NewEncoder(w).Encode(&person)
	// 	} else {
	// 		http.Error(w, "Missing ID parameter\nExpected usage: /users/{id}", http.StatusBadRequest)
	// 	}
	// })

	// http.HandleFunc("/users", func (w http.ResponseWriter, req *http.Request) {
	// 	if req.Method != "GET" {
	// 		http.Error(w, "Wrong method", http.StatusBadRequest)
	// 		return 
	// 	}

	// 	var people []Test

	// 	rows, err := db.Query("SELECT * FROM users")
	// 	handleErr(err, "Select failed")
	// 	defer rows.Close()

	// 	for rows.Next() {
	// 		var person Test
	// 		err := rows.Scan(&person.ID, &person.Name, &person.Age)
	// 		handleErr(err, "Failed to read row")
	// 		people = append(people, person)
	// 	}

	// 	w.Header().Set("Content-Type", "application/json")

	// 	json.NewEncoder(w).Encode(&people)
	// })
}