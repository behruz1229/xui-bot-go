package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type APIResponse struct {
	Success bool            `json:"success"`
	Msg     string          `json:"msg"`
	Obj     json.RawMessage `json:"obj"`
}

type InboundRaw struct {
	ID             int    `json:"id"`
	Port           int    `json:"port"`
	Protocol       string `json:"protocol"`
	Settings       string `json:"settings"`
	StreamSettings string `json:"streamSettings"`
}

type ClientData struct {
	ID         string `json:"id"`
	Flow       string `json:"flow"`
	Email      string `json:"email"`
	LimitIP    int    `json:"limitIp"`
	TotalGB    int64  `json:"totalGB"`
	ExpiryTime int64  `json:"expiryTime"`
	Enable     bool   `json:"enable"`
	TgID       any    `json:"tgId"`
	SubID      any    `json:"subId"`
	Comment    string `json:"comment"`
	Reset      int    `json:"reset"`
}

type Client struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
	mu         sync.Mutex // 🔥 Защита от гонки при логине
	loggedIn   bool
}

func NewClient(baseURL, username, password string) *Client {
	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		username: username,
		password: password,
		httpClient: &http.Client{
			Jar:       jar,
			Timeout:   15 * time.Second,
			Transport: transport,
		},
	}
}

func (c *Client) doLogin(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	payload := map[string]string{
		"username": c.username,
		"password": c.password,
	}
	resp, err := c.doRequest(ctx, "POST", "/login", payload, true)
	if err != nil {
		c.loggedIn = false
		return fmt.Errorf("ошибка запроса логина: %w", err)
	}
	if !resp.Success {
		c.loggedIn = false
		return fmt.Errorf("ошибка авторизации: %s", resp.Msg)
	}
	c.loggedIn = true
	return nil
}

// doRequest с безопасным повтором при 401/404
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}, useForm bool) (*APIResponse, error) {
	return c.doRequestWithRetry(ctx, method, path, body, useForm, false)
}

func (c *Client) doRequestWithRetry(ctx context.Context, method, path string, body interface{}, useForm bool, retried bool) (*APIResponse, error) {
	var reqBody io.Reader
	contentType := "application/json"
	var bodyBytes []byte

	if body != nil {
		if useForm {
			if formBody, ok := body.(map[string]string); ok {
				form := url.Values{}
				for k, v := range formBody {
					form.Set(k, v)
				}
				bodyBytes = []byte(form.Encode())
				reqBody = bytes.NewReader(bodyBytes)
				contentType = "application/x-www-form-urlencoded"
			}
		} else {
			var err error
			bodyBytes, err = json.Marshal(body)
			if err != nil {
				return nil, err
			}
			reqBody = bytes.NewReader(bodyBytes)
		}
	}

	fullURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")

	respHTTP, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer respHTTP.Body.Close()

	// 🔥 Обработка истёкшей сессии
	if respHTTP.StatusCode == http.StatusUnauthorized || (respHTTP.StatusCode == http.StatusNotFound && strings.Contains(path, "/panel/api/")) {
		if !retried {
			_, _ = io.Copy(io.Discard, respHTTP.Body)
			if err := c.doLogin(ctx); err != nil {
				return nil, fmt.Errorf("повторный логин не удался: %w", err)
			}
			// Повторяем запрос с теми же данными
			return c.doRequestWithRetry(ctx, method, path, body, useForm, true)
		}
	}

	if respHTTP.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, respHTTP.Body)
		return nil, fmt.Errorf("HTTP ошибка %d", respHTTP.StatusCode)
	}

	var apiResp APIResponse
	if err := json.NewDecoder(respHTTP.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("ошибка разбора JSON: %w", err)
	}

	if !apiResp.Success {
		return nil, fmt.Errorf("ошибка API: %s", apiResp.Msg)
	}

	return &apiResp, nil
}

func (c *Client) Login(ctx context.Context) error {
	if c.loggedIn {
		return nil
	}
	return c.doLogin(ctx)
}

func (c *Client) IsLoggedIn() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loggedIn
}

// === Публичные методы (все вызывают Login() для гарантии сессии) ===

func (c *Client) GetInbounds(ctx context.Context) ([]InboundRaw, error) {
	if err := c.Login(ctx); err != nil {
		return nil, err
	}
	resp, err := c.doRequest(ctx, "GET", "/panel/api/inbounds/list", nil, false)
	if err != nil {
		return nil, err
	}
	var inbounds []InboundRaw
	if err := json.Unmarshal(resp.Obj, &inbounds); err != nil {
		return nil, err
	}
	return inbounds, nil
}

func (c *Client) GetClientsFromInbound(ctx context.Context, inboundID int) ([]ClientData, error) {
	if err := c.Login(ctx); err != nil {
		return nil, err
	}
	inbounds, err := c.GetInbounds(ctx)
	if err != nil {
		return nil, err
	}
	for _, ib := range inbounds {
		if ib.ID == inboundID {
			var rawSettings map[string]json.RawMessage
			if err := json.Unmarshal([]byte(ib.Settings), &rawSettings); err != nil {
				return []ClientData{}, nil
			}
			clientsJSON, ok := rawSettings["clients"]
			if !ok {
				return []ClientData{}, nil
			}
			var clients []ClientData
			if err := json.Unmarshal(clientsJSON, &clients); err != nil {
				return []ClientData{}, nil
			}
			return clients, nil
		}
	}
	return []ClientData{}, nil
}

func (c *Client) GetOnlineUsers(ctx context.Context) ([]string, error) {
	if err := c.Login(ctx); err != nil {
		return nil, err
	}
	resp, err := c.doRequest(ctx, "POST", "/panel/api/inbounds/onlines", map[string]string{}, true)
	if err != nil {
		return nil, err
	}
	var emails []string
	if err := json.Unmarshal(resp.Obj, &emails); err != nil {
		return nil, err
	}
	return emails, nil
}

func (c *Client) AddClient(ctx context.Context, inboundID int, email string, totalGB float64, expiryDays int) error {
	if err := c.Login(ctx); err != nil {
		return err
	}
	var expiryTime int64
	if expiryDays > 0 {
		expiryTime = time.Now().AddDate(0, 0, expiryDays).UnixMilli()
	}

	client := ClientData{
		ID: uuid.New().String(), Flow: "", Email: email, LimitIP: 0,
		TotalGB: int64(totalGB * 1024 * 1024 * 1024), ExpiryTime: expiryTime,
		Enable: true, TgID: nil, SubID: nil, Comment: "", Reset: 0,
	}

	clients := []ClientData{client}
	settingsObj := map[string]interface{}{"clients": clients}
	settingsJSON, err := json.Marshal(settingsObj)
	if err != nil {
		return fmt.Errorf("ошибка кодирования settings: %w", err)
	}

	formData := map[string]string{
		"id":       fmt.Sprintf("%d", inboundID),
		"settings": string(settingsJSON),
	}
	_, err = c.doRequest(ctx, "POST", "/panel/api/inbounds/addClient", formData, true)
	return err
}

func (c *Client) DeleteClient(ctx context.Context, inboundID int, clientID string) error {
	if err := c.Login(ctx); err != nil {
		return err
	}
	_, err := c.doRequest(ctx, "POST", fmt.Sprintf("/panel/api/inbounds/%d/delClient/%s", inboundID, clientID), map[string]string{}, true)
	return err
}

func (c *Client) ResetClientTraffic(ctx context.Context, inboundID int, email string) error {
	if err := c.Login(ctx); err != nil {
		return err
	}
	_, err := c.doRequest(ctx, "POST", fmt.Sprintf("/panel/api/inbounds/%d/resetClientTraffic/%s", inboundID, email), map[string]string{}, true)
	return err
}

func (c *Client) RestartXray(ctx context.Context) error {
	if err := c.Login(ctx); err != nil {
		return err
	}
	_, err := c.doRequest(ctx, "POST", "/panel/api/server/restartXrayService", map[string]string{}, true)
	return err
}

func (c *Client) GetClientTraffic(ctx context.Context, email string) (map[string]interface{}, error) {
	if err := c.Login(ctx); err != nil {
		return nil, err
	}
	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/panel/api/inbounds/getClientTraffics/%s", email), nil, false)
	if err == nil {
		var data map[string]interface{}
		if err := json.Unmarshal(resp.Obj, &data); err == nil {
			return data, nil
		}
	}
	resp2, err := c.doRequest(ctx, "GET", "/panel/api/inbounds/stats", nil, false)
	if err != nil {
		return nil, err
	}
	var stats []map[string]interface{}
	if err := json.Unmarshal(resp2.Obj, &stats); err != nil {
		return nil, err
	}
	for _, s := range stats {
		if s["email"] == email {
			return s, nil
		}
	}
	return nil, nil
}

func (c *Client) UpdateClient(ctx context.Context, inboundID int, clientID string, newTotalGB *float64, newExpiryDays *int) error {
	if err := c.Login(ctx); err != nil {
		return err
	}
	clients, err := c.GetClientsFromInbound(ctx, inboundID)
	if err != nil {
		return err
	}
	var target *ClientData
	for i := range clients {
		if clients[i].ID == clientID {
			target = &clients[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("клиент %s не найден в inbound %d", clientID, inboundID)
	}
	if newTotalGB != nil {
		target.TotalGB = int64(*newTotalGB * 1024 * 1024 * 1024)
	}
	if newExpiryDays != nil {
		if *newExpiryDays > 0 {
			target.ExpiryTime = time.Now().AddDate(0, 0, *newExpiryDays).UnixMilli()
		} else {
			target.ExpiryTime = 0
		}
	}
	clientsList := []ClientData{*target}
	settingsObj := map[string]interface{}{"clients": clientsList}
	settingsJSON, err := json.Marshal(settingsObj)
	if err != nil {
		return fmt.Errorf("ошибка кодирования settings: %w", err)
	}
	formData := map[string]string{
		"id":       fmt.Sprintf("%d", inboundID),
		"settings": string(settingsJSON),
	}
	_, err = c.doRequest(ctx, "POST", fmt.Sprintf("/panel/api/inbounds/updateClient/%s", clientID), formData, true)
	return err
}

func (c *Client) GetInboundSettings(ctx context.Context, inboundID int) (map[string]interface{}, error) {
	if err := c.Login(ctx); err != nil {
		return nil, err
	}
	inbounds, err := c.GetInbounds(ctx)
	if err != nil {
		return nil, err
	}
	for _, ib := range inbounds {
		if ib.ID == inboundID {
			var settings map[string]interface{}
			if err := json.Unmarshal([]byte(ib.StreamSettings), &settings); err != nil {
				return nil, fmt.Errorf("ошибка парсинга streamSettings: %w", err)
			}
			return settings, nil
		}
	}
	return nil, fmt.Errorf("inbound %d не найден", inboundID)
}