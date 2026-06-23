package parasitic

import (
	"math"
	"time"
)

// Bot检测阈值常量
const (
	BotScoreThreshold    = 5   // Bot判定分数线
	MaxMousePoints       = 500 // 最大鼠标轨迹点数
	MaxClickIntervals    = 100 // 最大点击间隔数
	MaxKeypressTimes     = 200 // 最大键盘事件数
	MaxScrollTimes       = 50  // 最大滚动事件数
)

// BotCheckRequest Bot检测请求数据
type BotCheckRequest struct {
	SessionToken   string    `json:"sessionToken"`
	MouseTrack     [][]float64 `json:"mouseTrack"`   // [[x,y], ...]
	MouseMeta      *MouseMeta `json:"mouseMeta"`
	ClickIntervals []float64   `json:"clickIntervals"` // 点击间隔(ms)
	UserAgent      string      `json:"userAgent"`
	Timestamp      int64       `json:"timestamp"`
}

// MouseMeta 鼠标元数据
type MouseMeta struct {
	Timestamps []float64 `json:"timestamps"`
	Speeds     []float64 `json:"speeds"`
}

// SessionInfo Session信息
type SessionInfo struct {
	LastUpdate time.Time
	Requests   []time.Time
	UA         string
	IP         string
	MouseTrack [][]float64
}

// DetectionLog 检测日志
type DetectionLog struct {
	Timestamp    string   `json:"timestamp"`
	SessionID    string   `json:"session_id"`
	IP           string   `json:"ip"`
	Score        int      `json:"score"`
	MousePoints  int      `json:"mouse_points"`
	ClickCount   int      `json:"click_count"`
	Reasons      []string `json:"reasons"`
	IsBot        bool     `json:"is_bot"`
	RequestURL   string   `json:"request_url"`
	Method       string   `json:"method"`
	DetectMethod string   `json:"detect_method"`
}

// calcScore 计算Bot得分
// 阈值: >= BotScoreThreshold(5) 判定为Bot
func calcScore(s *SessionInfo, mouseTrack [][]float64, clickIntervals []float64, detector *BotDetector) (int, []string) {
	score := 0
	var reasons []string

	// 1. UA匹配检测
	if detector != nil && detector.IsBot(s.UA) {
		score += 3
		reasons = append(reasons, "UA匹配Bot规则")
	}

	// 2. HeadlessChrome强制判定
	if containsIgnoreCase(s.UA, "headlesschrome") || containsIgnoreCase(s.UA, "headless") {
		reasons = append(reasons, "Headless浏览器UA")
		return 5, reasons
	}

	// 3. 鼠标轨迹检测
	mousePoints := len(mouseTrack)
	if mousePoints < 5 {
		score += 2
		reasons = append(reasons, "鼠标轨迹点数过少")
	} else if isRegularMouseTrack(mouseTrack) {
		score += 3
		reasons = append(reasons, "鼠标轨迹过于规律")
	}

	// 4. 点击间隔检测
	clickCount := len(clickIntervals)
	if clickCount > 1 {
		variance := calculateClickVariance(clickIntervals)
		if variance < 1000 {
			score += 3
			reasons = append(reasons, "点击间隔过于规律")
		}
	} else if clickCount == 0 {
		score += 1
		reasons = append(reasons, "无点击事件")
	}

	// 5. 请求频率检测
	if len(s.Requests) > 2 {
		freqScore := analyzeRequestFrequency(s.Requests)
		if freqScore > 0 {
			score += freqScore
			reasons = append(reasons, "请求频率异常")
		}
	}

	// 确保分数不为负
	if score < 0 {
		score = 0
	}
	if score > 20 {
		score = 20
	}

	return score, reasons
}

// isRegularMouseTrack 检测鼠标轨迹是否过于规律（机器生成）
func isRegularMouseTrack(track [][]float64) bool {
	if len(track) < 10 {
		return false
	}

	// 计算速度和转向角
	speeds := make([]float64, 0, len(track)-1)
	angles := make([]float64, 0, len(track)-2)

	for i := 1; i < len(track); i++ {
		dx := track[i][0] - track[i-1][0]
		dy := track[i][1] - track[i-1][1]
		speed := math.Sqrt(dx*dx + dy*dy)
		speeds = append(speeds, speed)
	}

	for i := 2; i < len(track); i++ {
		dx1 := track[i-1][0] - track[i-2][0]
		dy1 := track[i-1][1] - track[i-2][1]
		dx2 := track[i][0] - track[i-1][0]
		dy2 := track[i][1] - track[i-1][1]

		dot := dx1*dx2 + dy1*dy2
		norm1 := math.Sqrt(dx1*dx1 + dy1*dy1)
		norm2 := math.Sqrt(dx2*dx2 + dy2*dy2)

		if norm1 > 0 && norm2 > 0 {
			cosAngle := dot / (norm1 * norm2)
			if cosAngle > 1 {
				cosAngle = 1
			} else if cosAngle < -1 {
				cosAngle = -1
			}
			angles = append(angles, math.Acos(cosAngle))
		}
	}

	// 分析特征
	botScore := 0

	// 特征1: 停顿比（速度接近0的比例）
	pauseCount := 0
	for _, s := range speeds {
		if s < 2 {
			pauseCount++
		}
	}
	pauseRatio := float64(pauseCount) / float64(len(speeds))
	if pauseRatio < 0.05 {
		botScore++
	}

	// 特征2: 平均转向角
	if len(angles) > 0 {
		var sum float64
		for _, a := range angles {
			sum += a
		}
		meanAngle := sum / float64(len(angles))
		if meanAngle < 0.13 { // ~7.5度
			botScore += 2
		}

		// 特征3: 转向角方差
		var varSum float64
		for _, a := range angles {
			diff := a - meanAngle
			varSum += diff * diff
		}
		turnVar := varSum / float64(len(angles))
		if turnVar < 0.17 { // ~10度^2
			botScore += 2
		}
	}

	// 特征4: 速度方差
	if len(speeds) > 1 {
		var meanSpeed float64
		for _, s := range speeds {
			meanSpeed += s
		}
		meanSpeed /= float64(len(speeds))

		var speedVar float64
		for _, s := range speeds {
			diff := s - meanSpeed
			speedVar += diff * diff
		}
		speedVar /= float64(len(speeds))
		if speedVar < 180 {
			botScore += 2
		}
	}

	// 阈值判定：botScore >= 4 认为是规律轨迹（原代码的43似乎是笔误，实际最大10分）
	return botScore >= 4
}

// calculateClickVariance 计算点击间隔方差
func calculateClickVariance(intervals []float64) float64 {
	if len(intervals) < 2 {
		return 0
	}

	var sum float64
	for _, v := range intervals {
		sum += v
	}
	mean := sum / float64(len(intervals))

	var variance float64
	for _, v := range intervals {
		diff := v - mean
		variance += diff * diff
	}
	return variance / float64(len(intervals))
}

// analyzeRequestFrequency 分析请求频率
func analyzeRequestFrequency(requests []time.Time) int {
	if len(requests) < 3 {
		return 0
	}

	intervals := make([]float64, 0, len(requests)-1)
	for i := 1; i < len(requests); i++ {
		intervals = append(intervals, requests[i].Sub(requests[i-1]).Seconds())
	}

	var mean float64
	for _, v := range intervals {
		mean += v
	}
	mean /= float64(len(intervals))

	if mean < 0.1 {
		return 2
	}
	return 0
}

// containsIgnoreCase 忽略大小写检查子串
func containsIgnoreCase(s, substr string) bool {
	s = stringsToLower(s)
	substr = stringsToLower(substr)
	return stringsContains(s, substr)
}

// CalcScorePublic 公开的分数计算接口
func CalcScorePublic(session *SessionInfo, mouseTrack [][]float64, clickIntervals []float64, detector *BotDetector) (int, []string) {
	return calcScore(session, mouseTrack, clickIntervals, detector)
}

// stringsToLower 将字符串转为小写
func stringsToLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result[i] = c + 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}

// stringsContains 检查是否包含子串
func stringsContains(s, substr string) bool {
	return len(substr) == 0 || stringsIndex(s, substr) >= 0
}

// stringsIndex 查找子串位置
func stringsIndex(s, substr string) int {
	n := len(substr)
	if n == 0 {
		return 0
	}
	if n > len(s) {
		return -1
	}
	for i := 0; i <= len(s)-n; i++ {
		if s[i:i+n] == substr {
			return i
		}
	}
	return -1
}
