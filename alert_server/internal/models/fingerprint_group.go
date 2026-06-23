package models

import (
	"time"

	"gorm.io/gorm"
)

// FingerprintGroup 硬件特征分组
type FingerprintGroup struct {
	gorm.Model
	VectorJSON string    `gorm:"type:text"` // 规范设备的硬件特征向量JSON
	CreatedAt  time.Time `gorm:"autoCreateTime"`
}

func (FingerprintGroup) TableName() string {
	return "fingerprint_groups"
}
