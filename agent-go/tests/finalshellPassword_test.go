package tests

import (
	"encoding/base64"
	"systemwire/agent/pkg"
	"testing"
)

func TestEncodePassword(t *testing.T) {
	plainText := "这是一段需要加密的明文字符串"
	encoded, err := pkg.EncodePassword(plainText)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	t.Logf("加密后的字符串: %s", encoded)

	// 验证加密结果是否能被解密（与Java解密逻辑对比时使用）
	decodedData, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("Base64 解码失败: %v", err)
	}

	head := decodedData[:8]
	encryptedData := decodedData[8:]
	key := pkg.GenerateRandomKey(head)

	// 尝试使用DES解密数据，验证逻辑是否正确
	decryptedData, err := pkg.EncryptDES(encryptedData, key) // 此处可以调用解密逻辑
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}

	t.Logf("解密后的字符串: %s", string(decryptedData))
}
