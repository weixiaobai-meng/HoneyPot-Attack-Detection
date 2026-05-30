package main

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func InitDB() {
	var err error
	db, err = sql.Open("sqlite3", "./data.db")
	if err != nil {
		log.Fatal("无法连接数据库:", err)
	}
	createTables()
}

func createTables() {
	// 1. 行为检测表 (保持不变)
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

	// 2. ✅【新增】指纹组表 (存储硬件基准画像)
	groupQuery := `
	CREATE TABLE IF NOT EXISTS fingerprint_groups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		vector_json TEXT,     -- 核心硬件特征
		created_at TEXT
	);`

	// 3. ✅【修改】设备指纹表 (增加 group_id)
	// 注意：如果你已有 data.db，建议删除文件重建
	fingerprintQuery := `
	CREATE TABLE IF NOT EXISTS device_fingerprints (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		group_id INTEGER,         -- 关联 fingerprint_groups
		session_token TEXT,
		remote_ip TEXT,
		webrtc_ips TEXT,
		is_proxy TEXT,
		raw_json TEXT,
		timestamp TEXT,
		FOREIGN KEY(group_id) REFERENCES fingerprint_groups(id)
	);`

	// === 新增：专门记录蜜罐/扫描攻击的表 ===
    honeypotQuery := `
    CREATE TABLE IF NOT EXISTS honeypot_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        trap_path TEXT,    -- 攻击者踩中的路径 (如 /config.json)
        user_agent TEXT,
        timestamp TEXT
    );`

	// === 新增：SSH 蜜罐攻击记录表 ===
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
		log.Fatal("创建 ssh_attacks 表失败:", err)
	}

    if _, err := db.Exec(honeypotQuery); err != nil {
        log.Fatal("创建 honeypot_events 表失败:", err)
    }

	if _, err := db.Exec(detectionQuery); err != nil {
		log.Fatal("创建 bot_detections 表失败:", err)
	}
	// 执行新增 SQL
	if _, err := db.Exec(groupQuery); err != nil {
		log.Fatal("创建 fingerprint_groups 表失败:", err)
	}
	if _, err := db.Exec(fingerprintQuery); err != nil {
		log.Fatal("创建 device_fingerprints 表失败:", err)
	}
	log.Println("数据库初始化完成")
}