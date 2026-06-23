package models

import (
	"time"

	"gorm.io/gorm"
)

// AccountAlert 账户蜜点告警记录（SSH/VPN登录尝试）
type AccountAlert struct {
	gorm.Model
	TriggerTime   time.Time `gorm:"index;not null"`
	ReportTime    time.Time `gorm:"autoCreateTime"`
	SrcIP         string    `gorm:"size:64;index"`
	SrcPort       string    `gorm:"size:20"`
	DstIP         string    `gorm:"size:64"`
	DstPort       string    `gorm:"size:20"`
	Username      string    `gorm:"size:128"`
	Password      string    `gorm:"size:255"`
	ClientVersion string    `gorm:"size:255"`
	Protocol      string    `gorm:"size:32;default:ssh;index"`
	Message       string    `gorm:"size:255"`
	RawEvent      string    `gorm:"type:text"` // 原始事件JSON
}

func (AccountAlert) TableName() string {
	return "account_alerts"
}
