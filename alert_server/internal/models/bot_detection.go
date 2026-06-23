package models

import (
	"time"

	"gorm.io/gorm"
)

// BotDetection Bot检测记录
type BotDetection struct {
	gorm.Model
	SessionToken string    `gorm:"index;size:128"`
	IP           string    `gorm:"index;size:64"`
	URL          string    `gorm:"size:512"`
	UserAgent    string    `gorm:"size:512"`
	Score        int       `gorm:"default:0"`
	IsBot        bool      `gorm:"default:false"`
	MousePoints  int       `gorm:"default:0"`
	ClickCount   int       `gorm:"default:0"`
	Reasons      string    `gorm:"type:text"`       // JSON数组
	DetectMethod string    `gorm:"size:32"`          // advanced / simple
	Timestamp    time.Time `gorm:"index"`
}

func (BotDetection) TableName() string {
	return "bot_detections"
}
