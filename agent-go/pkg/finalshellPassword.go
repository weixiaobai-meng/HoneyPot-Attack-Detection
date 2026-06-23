package pkg

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"fmt"
)

func main() {
	// 示例明文字符串
	plainText := "123456"
	// 执行加密
	encrypted, err := EncodePassword(plainText)
	if err != nil {
		fmt.Println("加密失败:", err)
		return
	}
	fmt.Println("加密后的字符串:", encrypted)
}

// EncryptDES 用于DES加密
func EncryptDES(data, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 数据需要填充至块大小的倍数
	blockSize := block.BlockSize()
	data = pkcs5Padding(data, blockSize)

	cipherText := make([]byte, len(data))
	blockMode := cipher.NewCBCEncrypter(block, key)
	blockMode.CryptBlocks(cipherText, data)

	return cipherText, nil
}

// EncodePassword 实现对字符串的加密
func EncodePassword(data string) (string, error) {
	if data == "" {
		return "", fmt.Errorf("输入数据为空")
	}

	// 生成8字节的随机前缀
	head := []byte("12345678") // 示例密钥前缀，可以替换为动态生成
	key := GenerateRandomKey(head)

	// 加密数据
	encryptedData, err := EncryptDES([]byte(data), key)
	if err != nil {
		return "", err
	}

	// 拼接前缀和加密数据
	finalData := append(head, encryptedData...)

	// 使用Base64编码
	encoded := base64.StdEncoding.EncodeToString(finalData)
	return encoded, nil
}

// GenerateRandomKey 根据head生成8字节的密钥
func GenerateRandomKey(head []byte) []byte {
	key := make([]byte, 8)
	copy(key, head)
	return key
}

// pkcs5Padding 实现PKCS5填充
func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}

// pkcs5Unpadding 实现PKCS5去填充
func pkcs5Unpadding(origData []byte) []byte {
	length := len(origData)
	unPadding := int(origData[length-1])
	return origData[:(length - unPadding)]
}
