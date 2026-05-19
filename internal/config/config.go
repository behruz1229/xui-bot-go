package config

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type Inbound struct {
	ID       int    `json:"id"`
	Remark   string `json:"remark"`
	Protocol string `json:"protocol"`
}

type Config struct {
	Token            string    `json:"token"`
	PanelURL         string    `json:"panel_url"`
	PanelLogin       string    `json:"panel_login"`
	PanelPassword    string    `json:"panel_password"`
	ServerIP         string    `json:"server_ip"`
	AuthorizedUserID int64     `json:"authorized_user_id"`
	Inbounds         []Inbound `json:"inbounds"`
}

func Load() (*Config, error) {
	keyHex := os.Getenv("XUI_BOT_KEY")
	if keyHex == "" {
		return nil, fmt.Errorf("переменная окружения XUI_BOT_KEY не установлена")
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("неверный формат ключа XUI_BOT_KEY (ожидается 64 hex-символа)")
	}

	encData, err := os.ReadFile("config.enc.json")
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения config.enc.json: %w", err)
	}

	block, _ := aes.NewCipher(key)
	aesGCM, _ := cipher.NewGCM(block)

	nonceSize := aesGCM.NonceSize()
	if len(encData) < nonceSize {
		return nil, fmt.Errorf("неверный формат зашифрованных данных")
	}

	nonce, cipherText := encData[:nonceSize], encData[nonceSize:]
	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки (проверьте XUI_BOT_KEY): %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(plainText, &cfg); err != nil {
		return nil, fmt.Errorf("ошибка разбора JSON: %w", err)
	}

	return &cfg, nil
}