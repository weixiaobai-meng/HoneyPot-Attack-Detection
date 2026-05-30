package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
	"encoding/json"

	"github.com/dlclark/regexp2"
)

type BotDetector struct {
	rules         []*BotRule
	combinedRegex *regexp2.Regexp
	cache         *sync.Map
	cacheTTL      time.Duration
}

func NewBotDetector(rulesFile string) (*BotDetector, error) {
	file, err := os.ReadFile(rulesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %v", err)
	}

	var rules []*BotRule
	if err := json.Unmarshal(file, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse rules file: %v", err)
	}

	// 预编译正则表达式
	var regexPatterns []string
	for i, rule := range rules {
		compiled, err := regexp2.Compile(rule.Regex, regexp2.RE2)
		if err != nil {
			log.Printf("Warning: invalid regex for rule %s: %v\nRegex: %s", rule.Name, err, rule.Regex)
			continue
		}
		compiled.MatchTimeout = time.Second
		rules[i].compiled = compiled
		regexPatterns = append(regexPatterns, rule.Regex)
	}

	// 创建组合正则表达式
	combinedPattern := "(?i)" + strings.Join(regexPatterns, "|")
	combinedRegex, err := regexp2.Compile(combinedPattern, regexp2.RE2)
	if err != nil {
		return nil, fmt.Errorf("failed to compile combined regex: %v", err)
	}
	combinedRegex.MatchTimeout = time.Second

	log.Printf("Bot检测器初始化完成，加载了 %d 条规则", len(rules))
	return &BotDetector{
		rules:         rules,
		combinedRegex: combinedRegex,
		cache:         &sync.Map{},
		cacheTTL:      CacheTTL,
	}, nil
}

func (bd *BotDetector) IsBot(userAgent string) bool {
	if userAgent == "" {
		return false
	}

	if cached, ok := bd.cache.Load(userAgent); ok {
		if result, ok := cached.(bool); ok {
			return result
		}
	}

	isMatch, err := bd.combinedRegex.MatchString(userAgent)
	if err != nil {
		log.Printf("Regex match error: %v", err)
		return false
	}

	bd.cache.Store(userAgent, isMatch)
	go func(ua string) {
		time.Sleep(bd.cacheTTL)
		bd.cache.Delete(ua)
	}(userAgent)

	return isMatch
}

func (bd *BotDetector) Parse(userAgent string) (*BotInfo, bool) {
	if !bd.IsBot(userAgent) {
		return nil, false
	}

	cacheKey := "parse:" + userAgent
	if cached, ok := bd.cache.Load(cacheKey); ok {
		if result, ok := cached.(*BotInfo); ok && result != nil {
			return result, true
		}
	}

	for _, rule := range bd.rules {
		if rule.compiled != nil {
			isMatch, err := rule.compiled.MatchString(userAgent)
			if err != nil {
				log.Printf("Regex match error for %s: %v", rule.Name, err)
				continue
			}
			if isMatch {
				botInfo := &BotInfo{
					Name:     rule.Name,
					Category: rule.Category,
					URL:      rule.URL,
					Producer: rule.Producer,
				}

				bd.cache.Store(cacheKey, botInfo)
				go func(key string) {
					time.Sleep(bd.cacheTTL)
					bd.cache.Delete(key)
				}(cacheKey)

				return botInfo, true
			}
		}
	}

	return nil, false
}

func createDefaultDetector() *BotDetector {
	defaultRules := []*BotRule{
		{
			Name:     "Googlebot",
			Regex:    `(?i)googlebot`,
			Category: "search_engine",
			Producer: &Producer{Name: "Google Inc."},
		},
		{
			Name:     "Common Bots",
			Regex:    `(?i)bot|spider|crawl|curl|wget|python|headless`,
			Category: "generic_bot",
			Producer: &Producer{Name: "Various"},
		},
	}

	// 预编译正则表达式
	for i, rule := range defaultRules {
		compiled, err := regexp2.Compile(rule.Regex, regexp2.RE2)
		if err == nil {
			compiled.MatchTimeout = time.Second
			defaultRules[i].compiled = compiled
		}
	}

	combinedRegex, _ := regexp2.Compile(`(?i)bot|spider|crawl`, regexp2.RE2)
	combinedRegex.MatchTimeout = time.Second

	log.Println("使用默认Bot检测规则")
	return &BotDetector{
		rules:         defaultRules,
		combinedRegex: combinedRegex,
		cache:         &sync.Map{},
		cacheTTL:      CacheTTL,
	}
}