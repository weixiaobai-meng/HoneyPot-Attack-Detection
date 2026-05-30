package models

import (
	"errors"
	"fmt"
	"log"
	"os"

	"gorm.io/gorm"
)

type TokenInfo struct {
	gorm.Model
	Token      string
	Alert_addr string
	Alert_msg  string
	Company_id uint `gorm:"default:1"`
}

func InsertToken(db *gorm.DB, info *TokenInfo) uint {
	//检查msg和addr是否存在
	// row, _ := db.Query("SELECT token FROM tokeninfo WHERE token=?", info.token)
	//设置日志文件
	file, err := os.OpenFile("db.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal("无法打开日志文件:", err)
	}
	defer file.Close()
	log.SetOutput(file)

	var tokeninfos []TokenInfo
	db.Where("token = ?", info.Token).Find(&tokeninfos)
	if len(tokeninfos) > 0 {
		log.Printf("token %s exists,insertion failed", info.Token)
		return 1
	}

	result := db.Create(&info)

	if result.Error != nil {
		log.Panicf("failed to insert tokeninfo %s", result.Error.Error())
		panic(result.Error)
	}

	// res, _ := stmt.Exec(info.token, info.alert_addr, info.alert_msg, time.Now().Format("2006-01-02 15:04:05"))

	fmt.Println(info.ID)
	return 0
}

// 查找token对应的信息
func FindTokenInfo(db *gorm.DB, token string, companyId uint) (*TokenInfo, error) {
	var tokeninfo TokenInfo
	query := db.Model(&TokenInfo{})
	if companyId != 0 {
		query = query.Where("company_id = ?", companyId)
	}
	result := query.Where("token = ?", token).First(&tokeninfo)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, result.Error
	}
	return &tokeninfo, nil
}

func FindAlertMsg(db *gorm.DB, token string) (TokenInfo, error) {
	var tokeninfo TokenInfo
	result := db.Where("token = ?", token).First(&tokeninfo) // 查询数据库
	if result.Error != nil {
		return TokenInfo{}, result.Error
	}

	return tokeninfo, nil
}
