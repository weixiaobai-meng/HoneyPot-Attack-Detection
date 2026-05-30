package models

import (
	"log"
	"os"
	"time"

	"gorm.io/gorm"
)

// 安全日志记录
type SecurityLog struct {
	gorm.Model
	Id           uint
	Trigger_time time.Time
	Src_ip       string // 原IP
	Event        string // 事件/类型
	Url          string // 其他信息
	Other        string
}

func Insert_securityLog(db *gorm.DB, info *SecurityLog) uint {
	file, err := os.OpenFile("db.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal("无法打开日志文件:", err)
	}
	defer file.Close()
	log.SetOutput(file)

	result := db.Create(&info)
	if result.Error != nil {
		//错误记录日志
		log.Panicf("failed to insert securitylog %s", result.Error.Error())
		return 1
	}

	return 0
}
