package models

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"gorm.io/gorm"
)

type TriggerInfo struct {
	gorm.Model
	Token         string    // token
	Token_url     string    // token对应的url
	Trigger_time  time.Time // 告警时间
	Alert_addr    string    // 告警邮箱
	Alert_msg     string    // 告警信息
	Trigger_ip    string    // 告警IP（攻击者IP）
	Trigger_agent string    // 打开工具的User-Agent
	Company_id    uint      `gorm:"default:0"`
}

func Insert_trigger(db *gorm.DB, info *TriggerInfo) uint {
	file, err := os.OpenFile("db.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal("无法打开日志文件:", err)
	}
	defer file.Close()
	log.SetOutput(file)

	var tokeninfo TokenInfo
	result := db.Where("token = ?", info.Token).First(&tokeninfo)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		// 没有找到匹配的记录
		fmt.Println("No records found")
		log.Printf("token %s not exists,insertion failed", info.Token)
	} else if result.Error != nil {
		// 查询出现了其他错误
		fmt.Println("Error occurred:", result.Error.Error())
		log.Panicf("token %s not exists,insertion failed", info.Token)
	}
	info.Company_id = tokeninfo.Company_id // 设定所属公司id
	result = db.Create(&info)
	if result.Error != nil {
		//错误记录日志
		log.Panicf("failed to insert triggerinfo %s", result.Error.Error())
		return 1
	}

	return 0
}

func FindTriggerLog(db *gorm.DB, count int, start_time time.Time, companyId uint) []TriggerInfo {
	var triggerinfos []TriggerInfo

	query := db.Where("trigger_time > ?", start_time).Order("created_at desc").Limit(count)
	if companyId != 0 { // 根据companyId查询
		query = query.Where("company_id = ?", companyId)
	}
	result := query.Find(&triggerinfos)

	// result := db.Order("created_at desc").Limit(count).Find(&triggerinfos)
	if result.Error != nil {
		//错误记录日志
		log.Panicf("failed to find triggerinfo %s", result.Error.Error())
		return nil
	}
	return triggerinfos
}
