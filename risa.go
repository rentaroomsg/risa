package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"time"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("RISA_COOKIE_SECRET")))
var dbString = os.Getenv("RISA_PG_URL")
var allowedOrigin = os.Getenv("RISA_ALLOW_ORIGIN")
var secret = os.Getenv("RISA_SECRET")

var db *sql.DB
var err error

func main() {
	fmt.Println(dbString)
	db, err = sql.Open("postgres", dbString)
	if err != nil {
		log.Fatal(err)
	}
	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/track", TrackEvent).Methods("GET")
	fmt.Println("listening")
	log.Fatal(http.ListenAndServe(":8080", r))
}

type Event struct {
	SessionKey string
	Category   string
	Action     string
}

// Records an event for the current client and parameters
// eg. /track?c=user&a=login
//
// If RISA_SECRET env var is set, then the 's' signature must also match
func TrackEvent(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if ok := checkSignature(query); !ok {
		w.WriteHeader(403)
		return
	}

	category := query.Get("c")
	action := query.Get("a")
	if sessionKey := getSessionKey(w, r); sessionKey != "" {
		event := Event{
			SessionKey: sessionKey,
			Category:   category,
			Action:     action,
		}
		go storeEvent(event)
	}
	if allowedOrigin != "" {
		w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Vary", "Origin")
	}
	w.WriteHeader(http.StatusOK)
}

// checks the query params with the given signature
func checkSignature(query url.Values) bool {
	if secret == "" {
		return true
	}

	var strToSig string

	sig := query.Get("s")
	if sig == "" {
		return false
	}
	mk := make([]string, len(query))

	i := 0
	for k, _ := range query {
		if k != "s" {
			mk[i] = k
		}
		i++
	}
	sort.Strings(mk)
	for _, key := range mk {
		strToSig += key
		strToSig += query.Get(key)
	}

	hash := computeHmac256(strToSig, secret)
	return (hash == sig)
}

// returns a session key for the user. creates a new session (and sets cookie) if one doesn't already exists
func getSessionKey(w http.ResponseWriter, r *http.Request) string {
	session, err := store.Get(r, "_risa")
	var session_key string
	if err != nil {
		return ""
	} else {
		val, ok := session.Values["session_key"]
		if ok {
			session_key = val.(string)
		} else {
			session_key = storeSession(session, r)
			session.Values["session_key"] = session_key
			session.Save(r, w)
		}
		return session_key
	}
}

// records a new session in the database
func storeSession(sess *sessions.Session, r *http.Request) string {
	var id int64
	err := db.QueryRow(
		"INSERT INTO risa_sessions (user_agent, start_time) VALUES ($1, $2) RETURNING id", r.UserAgent(), time.Now(),
	).Scan(&id)
	if err != nil {
		return ""
	}
	return strconv.FormatInt(id, 10)
}

// writes a new event to the database
func storeEvent(event Event) {
	db.Exec(
		"INSERT INTO risa_events (risa_session_id, category, action, event_time) VALUES ($1, $2, $3, $4)",
		event.SessionKey,
		event.Category,
		event.Action,
		time.Now(),
	)
}

func computeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
