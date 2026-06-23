package pkg

import (
	"log"
	"os"
	"path/filepath"
	"server/internal/models"

	_ "modernc.org/sqlite"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	Db            *gorm.DB // 数据库
	dbLogFilePath string
	dbFilePath    string
	dbLogFile     *os.File
)

func InitDB() (*gorm.DB, error) {
	// 确保日志目录存在于项目根目录下
	if err := CreateDirIfNotExist("log"); err != nil {
		return nil, err
	}
	// 打开日志文件
	dbLogFilePath = filepath.Join(ProjectRootDir, "log/db.log")
	file, err := os.OpenFile(dbLogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}
	if dbLogFile != nil {
		_ = dbLogFile.Close()
	}
	dbLogFile = file

	// 设置日志输出文件
	log.SetOutput(file)

	// 确保数据目录存在于项目根目录下
	if err := CreateDirIfNotExist("data"); err != nil {
		return nil, err
	}

	// 连接数据库
	dbFilePath = filepath.Join(ProjectRootDir, "data/token.db")
	Db, err = gorm.Open(sqlite.Dialector{
		DriverName: "sqlite",
		DSN:        dbFilePath,
	}, &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// WAL 模式 + busy_timeout：解决 SQLite 读写互斥导致的 "database is locked" 错误
	Db.Exec("PRAGMA journal_mode=WAL")
	Db.Exec("PRAGMA busy_timeout=5000")
	Db.Exec("PRAGMA foreign_keys=ON")

	// 连接池：SQLite 只支持单写者，限制最大连接数避免锁争用
	sqlDB, _ := Db.DB()
	if sqlDB != nil {
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
	}

	// 数据迁移
	modelsToMigrate := []interface{}{
		&models.TokenInfo{},
		&models.TriggerInfo{},
		&models.SecurityLog{},
		&models.CompanyInfo{},
		&models.BotDetection{},
		&models.DeviceFingerprint{},
		&models.FingerprintGroup{},
		&models.AccountAlert{},
	}
	if err := Db.AutoMigrate(modelsToMigrate...); err != nil {
		log.Fatalf("数据库迁移失败: %v", err)
		return nil, err
	}

	log.Println("数据库连接及迁移成功")
	return Db, nil

}

func CheckErr(err error) {
	if err != nil {
		panic(err)
	}
}
