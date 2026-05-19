package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Использование: go run ./cmd/config-tool config.json [config.enc.json]")
	}
	inputFile := os.Args[1]
	outputFile := "config.enc.json"
	if len(os.Args) >= 3 {
		outputFile = os.Args[2]
	}

	plainText, err := os.ReadFile(inputFile)
	if err != nil {
		log.Fatalf("❌ Ошибка чтения %s: %v", inputFile, err)
	}

	// Генерация 32-байтного ключа
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("❌ Ошибка генерации ключа: %v", err)
	}

	block, _ := aes.NewCipher(key)
	aesGCM, _ := cipher.NewGCM(block)
	nonce := make([]byte, aesGCM.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	// Шифрование
	cipherText := aesGCM.Seal(nonce, nonce, plainText, nil)
	if err := os.WriteFile(outputFile, cipherText, 0600); err != nil {
		log.Fatalf("❌ Ошибка записи %s: %v", outputFile, err)
	}

	fmt.Println("✅ Файл успешно зашифрован:", outputFile)
	fmt.Println("🔑 Мастер-ключ (скопируйте и сохраните!):")
	fmt.Println(hex.EncodeToString(key))
}