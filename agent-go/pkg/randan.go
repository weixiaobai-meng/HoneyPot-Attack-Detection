package pkg

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/exp/rand"
)

// 生成符合 Xshell 密码风格的随机密码
func GenerateXshellPassword(length int) string {
	// 验证密码长度
	if length < 8 {
		length = 8 // 最小密码长度
	} else if length > 16 {
		length = 16 // 最大密码长度
	}

	// 定义字符集
	const (
		lowercase   = "abcdefghijklmnopqrstuvwxyz"
		uppercase   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits      = "0123456789"
		specialChar = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~"
	)

	// 将字符集合并
	allChars := lowercase + uppercase + digits + specialChar

	// 初始化随机数生成器
	rand.Seed(uint64(time.Now().UnixNano()))

	// 使用 strings.Builder 提高性能
	var password strings.Builder
	password.Grow(length)

	// 确保密码包含至少一个小写字母、大写字母、数字和特殊字符
	password.WriteByte(lowercase[rand.Intn(len(lowercase))])
	password.WriteByte(uppercase[rand.Intn(len(uppercase))])
	password.WriteByte(digits[rand.Intn(len(digits))])
	password.WriteByte(specialChar[rand.Intn(len(specialChar))])

	// 剩余部分随机生成
	for i := 4; i < length; i++ {
		password.WriteByte(allChars[rand.Intn(len(allChars))])
	}

	// 将密码打乱以保证随机性
	runes := []rune(password.String())
	rand.Shuffle(len(runes), func(i, j int) {
		runes[i], runes[j] = runes[j], runes[i]
	})

	return string(runes)
}

// 生成随机字符串
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	rand.Seed(uint64(time.Now().UnixNano()))
	var sb strings.Builder
	sb.Grow(length)
	for i := 0; i < length; i++ {
		sb.WriteByte(charset[rand.Intn(len(charset))])
	}
	return sb.String()
}

// 生成 Xshell 配置文件名
func GenerateXshellConfigFilename(user string) string {
	// 获取当前时间
	now := time.Now()
	date := now.Format("20060102") // 格式化日期为 YYYYMMDD

	// 生成随机字符串
	randomPart := generateRandomString(6)

	// 组装文件名
	filename := fmt.Sprintf("%s_%s_%s.xsh", user, date, randomPart)
	return filename
}
