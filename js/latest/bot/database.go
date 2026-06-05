package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func InitDB() {
	var err error
	db, err = sql.Open("sqlite3", "./data.db")
	if err != nil {
		log.Printf("database disabled: open sqlite failed: %v", err)
		db = nil
		return
	}

	if err := db.Ping(); err != nil {
		log.Printf("database disabled: sqlite ping failed: %v", err)
		db = nil
		return
	}

	if err := createTables(); err != nil {
		log.Printf("database disabled: init tables failed: %v", err)
		db = nil
		return
	}

	log.Println("database initialized")
}

func createTables() error {
	if db == nil {
		return fmt.Errorf("database is nil")
	}

	detectionQuery := `
CREATE TABLE IF NOT EXISTS bot_detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_token TEXT,
    ip TEXT,
    score INTEGER,
    is_bot BOOLEAN,
    reasons TEXT,
    timestamp TEXT
);`

	groupQuery := `
CREATE TABLE IF NOT EXISTS fingerprint_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vector_json TEXT,
    created_at TEXT
);`

	fingerprintQuery := `
CREATE TABLE IF NOT EXISTS device_fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER,
    session_token TEXT,
    remote_ip TEXT,
    webrtc_ips TEXT,
    is_proxy TEXT,
    raw_json TEXT,
    timestamp TEXT,
    FOREIGN KEY(group_id) REFERENCES fingerprint_groups(id)
);`

	honeypotQuery := `
CREATE TABLE IF NOT EXISTS honeypot_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    trap_path TEXT,
    user_agent TEXT,
    timestamp TEXT
);`

	sshTableQuery := `
CREATE TABLE IF NOT EXISTS ssh_attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    username TEXT,
    password TEXT,
    client_version TEXT,
    raw_log TEXT,
    timestamp TEXT
);`

	if _, err := db.Exec(sshTableQuery); err != nil {
		return fmt.Errorf("create ssh_attacks failed: %w", err)
	}
	if _, err := db.Exec(honeypotQuery); err != nil {
		return fmt.Errorf("create honeypot_events failed: %w", err)
	}
	if _, err := db.Exec(detectionQuery); err != nil {
		return fmt.Errorf("create bot_detections failed: %w", err)
	}
	if _, err := db.Exec(groupQuery); err != nil {
		return fmt.Errorf("create fingerprint_groups failed: %w", err)
	}
	if _, err := db.Exec(fingerprintQuery); err != nil {
		return fmt.Errorf("create device_fingerprints failed: %w", err)
	}

	return nil
}
