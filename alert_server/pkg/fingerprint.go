package pkg

import (
	"encoding/json"
	"fmt"
)

// FingerprintData 请求数据结构
type FingerprintData struct {
	Fingerprint string                 `json:"fingerprint"`
	Path        string                 `json:"path"`
	Details     map[string]interface{} `json:"details"`
}

// FingerLogData 写入文件的数据结构
type FingerLogData struct {
	Time        int64  `json:"time"`
	IP          string `json:"ip"`
	Path        string `json:"path"`
	Fingerprint string `json:"fingerprint"`
	Details     string `json:"details"`
}

// getString 安全地将接口类型转换为字符串
func GetString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		return fmt.Sprintf("%v", val)
	case int:
		return fmt.Sprintf("%d", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	case nil:
		return ""
	default:
		// 尝试JSON序列化其他类型
		if b, err := json.Marshal(v); err == nil {
			return string(b)
		}
		return ""
	}
}
