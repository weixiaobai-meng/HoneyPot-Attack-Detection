package models

import (
	"time"

	"gorm.io/gorm"
)

// DeviceFingerprint 设备指纹记录
type DeviceFingerprint struct {
	gorm.Model
	SessionToken    string    `gorm:"index;size:128"`
	RemoteIP        string    `gorm:"index;size:64"`
	GroupID         uint      `gorm:"default:0;index"`     // 设备分组ID
	WebRTCIPs       string    `gorm:"type:text"`            // JSON数组
	IsProxy         bool      `gorm:"default:false"`        // 是否为代理
	FingerprintData string    `gorm:"type:text"`            // 原始指纹JSON
	FingerprintID   string    `gorm:"index;size:128"`       // 浏览器指纹ID
	TargetURL       string    `gorm:"size:512"`             // 目标URL
	Browser         string    `gorm:"size:64"`
	OS              string    `gorm:"size:64"`
	UserAgent       string    `gorm:"size:512"`
	BotScore        int       `gorm:"default:0"`
	IsBot           bool      `gorm:"default:false"`
	ProxyDetectResult string  `gorm:"size:16;default:''"`
	Timestamp       time.Time `gorm:"index"`
}

func (DeviceFingerprint) TableName() string {
	return "device_fingerprints"
}
