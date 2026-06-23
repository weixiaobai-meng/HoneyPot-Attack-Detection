package parasitic

import (
	"encoding/json"
	"log"
	"math"
	"server/internal/models"
	"strconv"
	"strings"

	"gorm.io/gorm"
)

// 指纹相似度阈值常量
const (
	SimilarityThreshold = 0.85
)

// HardwareVectors 硬件特征向量
type HardwareVectors struct {
	CPUCores          string  `json:"cpuCores"`
	CurrentResolution string  `json:"currentResolution"`
	AvailableRes      string  `json:"availableResolution"`
	GPU               string  `json:"gpu"`
	GpuVendor         string  `json:"gpuVendor"`
	OS                string  `json:"os"`
	OSVersion         string  `json:"osVersion"`
	Language          string  `json:"language"`
	TimeZone          string  `json:"timeZone"`
	ColorDepth        string  `json:"colorDepth"`
	DeviceMemory      string  `json:"deviceMemory"`
	TouchSupport      string  `json:"touchSupport"`
	Platform          string  `json:"platform"`
	SessionStorage    string  `json:"sessionStorage"`
	LocalStorage      string  `json:"localStorage"`
	Cookies           string  `json:"cookies"`
}

// FingerprintGroupManager 指纹分组管理器
type FingerprintGroupManager struct {
	db *gorm.DB
}

// NewFingerprintGroupManager 创建指纹分组管理器
func NewFingerprintGroupManager(db *gorm.DB) *FingerprintGroupManager {
	return &FingerprintGroupManager{db: db}
}

// GetOrCreateGroupID 获取或创建设备分组ID
func (fgm *FingerprintGroupManager) GetOrCreateGroupID(data *BufferData, fingerprintJSON string) uint {
	// 从指纹JSON中提取硬件特征
	vectors := extractHardwareVectors(data, fingerprintJSON)
	if vectors == nil {
		return 0
	}

	// 查询已有分组
	var groups []models.FingerprintGroup
	if err := fgm.db.Find(&groups).Error; err != nil {
		return 0
	}

	// 与已有分组计算相似度
	for _, group := range groups {
		var groupVectors HardwareVectors
		if err := json.Unmarshal([]byte(group.VectorJSON), &groupVectors); err != nil {
			continue
		}

		similarity := calculateSimilarity(vectors, &groupVectors)
		if similarity >= SimilarityThreshold {
			return group.ID
		}
	}

	// 没有匹配的分组，创建新分组
	vectorsJSON, err := json.Marshal(vectors)
	if err != nil {
		return 0
	}

	newGroup := models.FingerprintGroup{
		VectorJSON: string(vectorsJSON),
	}
	if err := fgm.db.Create(&newGroup).Error; err != nil {
		log.Printf("[Fingerprint] 创建指纹分组失败: %v", err)
		return 0
	}

	log.Printf("[Fingerprint] 创建新指纹分组 ID:%d", newGroup.ID)
	return newGroup.ID
}

// extractHardwareVectors 从指纹数据中提取硬件特征向量
func extractHardwareVectors(data *BufferData, fingerprintJSON string) *HardwareVectors {
	if data == nil {
		return nil
	}

	vectors := &HardwareVectors{}

	// 从指纹JSON中解析字段
	if fingerprintJSON != "" {
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(fingerprintJSON), &raw); err == nil {
			if v, ok := raw["cpuCores"]; ok {
				vectors.CPUCores = toString(v)
			}
			if v, ok := raw["screenPrint"]; ok {
				vectors.CurrentResolution = toString(v)
			}
			if v, ok := raw["gpuInfo"]; ok {
				if gpuMap, ok := v.(map[string]interface{}); ok {
					vectors.GPU = toString(gpuMap["renderer"])
					vectors.GpuVendor = toString(gpuMap["vendor"])
				}
			}
			if v, ok := raw["os"]; ok {
				vectors.OS = toString(v)
			}
			if v, ok := raw["osVersion"]; ok {
				vectors.OSVersion = toString(v)
			}
			if v, ok := raw["language"]; ok {
				vectors.Language = toString(v)
			}
			if v, ok := raw["timeZone"]; ok {
				vectors.TimeZone = toString(v)
			}
			if v, ok := raw["isMobile"]; ok {
				vectors.Platform = toString(v)
			}
			if v, ok := raw["isLocalStorage"]; ok {
				vectors.LocalStorage = toString(v)
			}
			if v, ok := raw["sessionStorage"]; ok {
				vectors.SessionStorage = toString(v)
			}
			if v, ok := raw["isCookie"]; ok {
				vectors.Cookies = toString(v)
			}
		}
	}

	return vectors
}

// calculateSimilarity 计算两个硬件特征向量的相似度
func calculateSimilarity(a, b *HardwareVectors) float64 {
	if a == nil || b == nil {
		return 0
	}

	totalWeight := 0.0
	matchWeight := 0.0

	// CPU核心数 (权重20)
	totalWeight += 20
	if a.CPUCores != "" && a.CPUCores == b.CPUCores {
		matchWeight += 20
	}

	// GPU渲染器 (权重20)
	totalWeight += 20
	if a.GPU != "" && b.GPU != "" {
		sim := stringSimilarity(a.GPU, b.GPU)
		matchWeight += 20 * math.Pow(sim, 2)
	}

	// GPU供应商 (权重5)
	totalWeight += 5
	if a.GpuVendor != "" && a.GpuVendor == b.GpuVendor {
		matchWeight += 5
	}

	// 操作系统 (权重10)
	totalWeight += 10
	if a.OS != "" && strings.EqualFold(a.OS, b.OS) {
		matchWeight += 10
	}

	// 操作系统版本 (权重10)
	totalWeight += 10
	if a.OSVersion != "" && b.OSVersion != "" {
		sim := stringSimilarity(a.OSVersion, b.OSVersion)
		matchWeight += 10 * sim
	}

	// 语言 (权重5)
	totalWeight += 5
	if a.Language != "" && strings.EqualFold(a.Language, b.Language) {
		matchWeight += 5
	}

	// 时区 (权重5)
	totalWeight += 5
	if a.TimeZone != "" && a.TimeZone == b.TimeZone {
		matchWeight += 5
	}

	// 基础环境 (OS/屏幕/存储等, 权重25)
	totalWeight += 25
	if a.Platform != "" && a.Platform == b.Platform {
		matchWeight += 5
	}
	if a.LocalStorage != "" && a.LocalStorage == b.LocalStorage {
		matchWeight += 5
	}
	if a.SessionStorage != "" && a.SessionStorage == b.SessionStorage {
		matchWeight += 5
	}
	if a.Cookies != "" && a.Cookies == b.Cookies {
		matchWeight += 5
	}
	if a.CurrentResolution != "" && a.CurrentResolution == b.CurrentResolution {
		matchWeight += 5
	}

	if totalWeight == 0 {
		return 0
	}
	return matchWeight / totalWeight
}

// stringSimilarity 计算两个字符串的相似度 (基于Levenshtein编辑距离)
func stringSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	// 使用Levenshtein距离
	al := strings.ToLower(a)
	bl := strings.ToLower(b)

	// 简化版：使用较长字符串的长度减去编辑距离
	distance := levenshteinDistance(al, bl)
	maxLen := math.Max(float64(len(al)), float64(len(bl)))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - float64(distance)/maxLen
}

// levenshteinDistance 计算编辑距离
func levenshteinDistance(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	// 使用一维DP优化
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)

	for j := 0; j <= len(b); j++ {
		prev[j] = j
	}

	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(
				prev[j]+1,
				curr[j-1]+1,
				prev[j-1]+cost,
			)
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// toString 安全转为字符串
func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case float64:
		if val == math.Trunc(val) {
			return strconv.FormatInt(int64(val), 10)
		}
		return strconv.FormatFloat(val, 'f', 2, 64)
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		if b, err := json.Marshal(v); err == nil {
			return string(b)
		}
		return ""
	}
}
