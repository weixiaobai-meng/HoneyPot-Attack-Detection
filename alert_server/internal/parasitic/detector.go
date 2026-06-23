package parasitic

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// BotInfo Bot规则信息
type BotInfo struct {
	Regex    string `json:"regex"`
	Name     string `json:"name"`
	Category int    `json:"category"`
	URL      string `json:"url"`
	Producer struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"producer"`
}

// BotDetector Bot检测器
type BotDetector struct {
	compiledRegex *regexp.Regexp
	defaultRegex  *regexp.Regexp
	cache         sync.Map
	cacheTTL      time.Duration
	ruleCount     int
}

// NewBotDetector 创建Bot检测器
func NewBotDetector(botsJSONPath string) *BotDetector {
	d := &BotDetector{
		cacheTTL: 10 * time.Minute,
	}

	// 尝试加载bots.json
	if err := d.loadBotsJSON(botsJSONPath); err != nil {
		logrus.Warnf("[Parasitic] 加载bots.json失败: %v, 使用默认规则", err)
	}

	// 编译默认正则（作为兜底）
	d.defaultRegex = regexp.MustCompile(`(?i)(googlebot|bot|spider|crawl|curl|wget|python|headless|scanner|scrapy|semrush|ahrefs|bingpreview)`)
	if d.compiledRegex == nil {
		d.compiledRegex = d.defaultRegex
	}

	return d
}

// loadBotsJSON 从JSON文件加载Bot规则
func (d *BotDetector) loadBotsJSON(jsonPath string) error {
	absPath := jsonPath
	if !filepath.IsAbs(jsonPath) {
		wd, _ := os.Getwd()
		absPath = filepath.Join(wd, jsonPath)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return err
	}

	var rules []BotInfo
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}

	if len(rules) == 0 {
		return nil
	}

	// 编译复合正则
	patterns := make([]string, 0, len(rules))
	for _, rule := range rules {
		pat := strings.TrimSpace(rule.Regex)
		if pat != "" {
			patterns = append(patterns, pat)
		}
	}

	if len(patterns) > 0 {
		combined := "(?i)" + strings.Join(patterns, "|")
		re, err := regexp.Compile(combined)
		if err != nil {
			return err
		}
		d.compiledRegex = re
		d.ruleCount = len(patterns)
		logrus.Infof("[Parasitic] 加载了 %d 条Bot检测规则", d.ruleCount)
	}

	return nil
}

// IsBot 检测User-Agent是否为Bot
func (d *BotDetector) IsBot(userAgent string) bool {
	if userAgent == "" {
		return false
	}

	// 检查缓存
	key := strings.ToLower(userAgent)
	if val, ok := d.cache.Load(key); ok {
		entry := val.(*cacheEntry)
		if time.Since(entry.created) < d.cacheTTL {
			return entry.isBot
		}
		d.cache.Delete(key)
	}

	// 执行匹配
	isBot := d.compiledRegex.MatchString(userAgent)

	// 写入缓存
	d.cache.Store(key, &cacheEntry{
		isBot:   isBot,
		created: time.Now(),
	})

	return isBot
}

// Parse 解析UA匹配到的Bot信息
func (d *BotDetector) Parse(userAgent string) *BotInfo {
	if userAgent == "" {
		return nil
	}

	match := d.compiledRegex.FindString(userAgent)
	if match == "" {
		return nil
	}

	name := strings.TrimSpace(match)
	if len(name) > 64 {
		name = name[:64]
	}

	return &BotInfo{
		Name: name,
	}
}

type cacheEntry struct {
	isBot   bool
	created time.Time
}
