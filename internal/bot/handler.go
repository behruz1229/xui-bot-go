package bot

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/bek/xui-bot-go/internal/api"
	"github.com/bek/xui-bot-go/internal/config"
)

type EditState struct {
	Type      string
	InboundID int
	ClientID  string
	Email     string
}

var (
	editStates   = make(map[int64]EditState)
	editStatesMu sync.RWMutex
)

type Handler struct {
	bot *tgbotapi.BotAPI
	xui *api.Client
	cfg *config.Config
}

func NewHandler(bot *tgbotapi.BotAPI, xui *api.Client, cfg *config.Config) *Handler {
	return &Handler{bot: bot, xui: xui, cfg: cfg}
}

func (h *Handler) isAuthorized(update tgbotapi.Update) bool {
	var userID int64
	if update.Message != nil {
		userID = update.Message.From.ID
	} else if update.CallbackQuery != nil {
		userID = update.CallbackQuery.From.ID
	} else {
		return false
	}
	return userID == h.cfg.AuthorizedUserID
}

func (h *Handler) sendUnauthorized(chatID int64) {
	msg := tgbotapi.NewMessage(chatID, "⛔ Доступ запрещён.")
	_, _ = h.bot.Send(msg)
}

func (h *Handler) showMainMenu(chatID int64) {
	keyboard := tgbotapi.NewReplyKeyboard(
		tgbotapi.NewKeyboardButtonRow(tgbotapi.NewKeyboardButton("➕ Создание клиента")),
		tgbotapi.NewKeyboardButtonRow(tgbotapi.NewKeyboardButton("📋 Список пользователей")),
		tgbotapi.NewKeyboardButtonRow(tgbotapi.NewKeyboardButton("ℹ️ Информация о сервере")),
		tgbotapi.NewKeyboardButtonRow(tgbotapi.NewKeyboardButton("❓ Помощь")),
	)
	keyboard.OneTimeKeyboard = false
	keyboard.ResizeKeyboard = true
	msg := tgbotapi.NewMessage(chatID, "Добро пожаловать! Выберите действие:")
	msg.ReplyMarkup = keyboard
	_, _ = h.bot.Send(msg)
}

func generateVLESSLink(clientID, email, serverIP string, port int, inboundSettings map[string]interface{}, protocolType string) string {
	security := "reality"
	encryption := "none"

	realitySettings, _ := inboundSettings["realitySettings"].(map[string]interface{})
	settings, _ := realitySettings["settings"].(map[string]interface{})
	pbk, _ := settings["publicKey"].(string)
	fp, _ := settings["fingerprint"].(string)
	if fp == "" {
		fp = "chrome"
	}
	serverNames, _ := realitySettings["serverNames"].([]interface{})
	sni := serverIP
	if len(serverNames) > 0 {
		if s, ok := serverNames[0].(string); ok && s != "" {
			sni = s
		}
	}
	shortIDs, _ := realitySettings["shortIds"].([]interface{})
	sid := ""
	if len(shortIDs) > 0 {
		if s, ok := shortIDs[0].(string); ok {
			sid = s
		}
	}
	spiderX, _ := settings["spiderX"].(string)
	pqv, _ := settings["mldsa65Verify"].(string)

	params := fmt.Sprintf("encryption=%s&security=%s&pbk=%s&fp=%s&sni=%s",
		encryption, security, url.QueryEscape(pbk), url.QueryEscape(fp), url.QueryEscape(sni))
	if sid != "" {
		params += "&sid=" + sid
	}
	if spiderX != "" {
		params += "&spx=" + url.QueryEscape(spiderX)
	}
	if pqv != "" {
		params += "&pqv=" + url.QueryEscape(pqv)
	}

	if protocolType == "grpc" {
		grpcSettings, _ := inboundSettings["grpcSettings"].(map[string]interface{})
		serviceName, _ := grpcSettings["serviceName"].(string)
		mode, _ := grpcSettings["mode"].(string)
		authority, _ := grpcSettings["authority"].(string)
		params = "type=grpc&" + params
		if serviceName != "" {
			params += "&serviceName=" + url.QueryEscape(serviceName)
		}
		if mode != "" {
			params += "&mode=" + mode
		}
		if authority != "" {
			params += "&authority=" + url.QueryEscape(authority)
		}
		params += "#grpc-" + url.QueryEscape(email)
	} else {
		params = "type=tcp&" + params + "#tcp-" + url.QueryEscape(email)
	}
	return fmt.Sprintf("vless://%s@%s:%d?%s", clientID, serverIP, port, params)
}

func (h *Handler) getInboundPort(inboundID int) *int {
	inbounds, err := h.xui.GetInbounds(context.Background())
	if err != nil {
		return nil
	}
	for _, ib := range inbounds {
		if ib.ID == inboundID {
			return &ib.Port
		}
	}
	return nil
}

func (h *Handler) HandleStart(update tgbotapi.Update) {
	if !h.isAuthorized(update) {
		h.sendUnauthorized(update.Message.Chat.ID)
		return
	}
	h.showMainMenu(update.Message.Chat.ID)
}

func (h *Handler) HandleText(msg tgbotapi.Message) {
	chatID := msg.Chat.ID

	editStatesMu.RLock()
	state, hasState := editStates[chatID]
	editStatesMu.RUnlock()

	if hasState {
		if !h.isAuthorized(tgbotapi.Update{Message: &msg}) {
			h.sendUnauthorized(chatID)
			return
		}

		if state.Type == "create_select" {
			var inboundID int
			for _, ib := range h.cfg.Inbounds {
				if ib.Remark == msg.Text {
					inboundID = ib.ID
					break
				}
			}
			if inboundID == 0 {
				_, _ = h.bot.Send(tgbotapi.NewMessage(chatID, "❌ Неверный inbound. Выберите из кнопок."))
				h.startCreateClient(chatID)
				return
			}
			editStatesMu.Lock()
			editStates[chatID] = EditState{Type: "create_name", InboundID: inboundID}
			editStatesMu.Unlock()
			_, _ = h.bot.Send(tgbotapi.NewMessage(chatID, "✏️ Введите имя клиента (email):"))
			return
		}

		if state.Type == "create_name" {
			email := strings.TrimSpace(msg.Text)
			if email == "" {
				_, _ = h.bot.Send(tgbotapi.NewMessage(chatID, "❌ Имя не может быть пустым."))
				return
			}
			success, message := h.createClientFlow(state.InboundID, email)
			editStatesMu.Lock()
			delete(editStates, chatID)
			editStatesMu.Unlock()
			_, _ = h.bot.Send(tgbotapi.NewMessage(chatID, fmt.Sprintf("%s %s", map[bool]string{true: "✅", false: "❌"}[success], message)))
			h.showMainMenu(chatID)
			return
		}

		value, err := strconv.Atoi(strings.TrimSpace(msg.Text))
		if err != nil || value < 0 {
			_, _ = h.bot.Send(tgbotapi.NewMessage(chatID, "❌ Введите целое число >= 0."))
			return
		}

		var success bool
		var message string
		if state.Type == "limit" {
			gb := float64(value)
			err := h.xui.UpdateClient(context.Background(), state.InboundID, state.ClientID, &gb, nil)
			success = err == nil
			message = "Клиент успешно обновлён"
			if err != nil {
				message = err.Error()
			}
		} else if state.Type == "expiry" {
			days := value
			err := h.xui.UpdateClient(context.Background(), state.InboundID, state.ClientID, nil, &days)
			success = err == nil
			message = "Клиент успешно обновлён"
			if err != nil {
				message = err.Error()
			}
		}

		editStatesMu.Lock()
		delete(editStates, chatID)
		editStatesMu.Unlock()
		_, _ = h.bot.Send(tgbotapi.NewMessage(chatID, fmt.Sprintf("%s %s", map[bool]string{true: "✅", false: "❌"}[success], message)))
		h.showMainMenu(chatID)
		return
	}

	if !h.isAuthorized(tgbotapi.Update{Message: &msg}) {
		h.sendUnauthorized(chatID)
		return
	}

	switch msg.Text {
	case "➕ Создание клиента":
		h.startCreateClient(chatID)
	case "📋 Список пользователей":
		h.showClientsList(chatID)
	case "ℹ️ Информация о сервере":
		h.showServerInfo(chatID)
	case "❓ Помощь":
		_, _ = h.bot.Send(tgbotapi.NewMessage(chatID,
			"Ссылка для (v2box) 🤖 https://goo.su/L0HcC8l\n\n"+
				"Ссылка для (incy) 🤖 https://goo.su/6XjkbR\n\n"+
				"Ссылка для (incy) 🍏 https://goo.su/eQe99mV\n\n"+
				"Ссылка для (XRayClient) 🍏 https://goo.su/butr4n\n\n"+
				"Ссылка для (Alice Ray) 🍏 https://goo.su/jCFdHZ\n\n"+
				"Ссылка для (sing-box VT) 🍏 https://goo.su/QtoKjyG",
		))
	}
}

func (h *Handler) startCreateClient(chatID int64) {
	inbounds := h.cfg.Inbounds
	var keyboard [][]tgbotapi.KeyboardButton
	for _, ib := range inbounds {
		keyboard = append(keyboard, tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton(ib.Remark),
		))
	}
	replyMarkup := tgbotapi.NewReplyKeyboard(keyboard...)
	replyMarkup.ResizeKeyboard = true
	replyMarkup.OneTimeKeyboard = true
	msg := tgbotapi.NewMessage(chatID, "📡 Выберите inbound для нового клиента:")
	msg.ReplyMarkup = replyMarkup
	_, _ = h.bot.Send(msg)
	editStatesMu.Lock()
	editStates[chatID] = EditState{Type: "create_select", InboundID: 0}
	editStatesMu.Unlock()
}

func (h *Handler) createClientFlow(inboundID int, email string) (bool, string) {
	ctx := context.Background()
	totalGB := 0.0
	expiryDays := 0
	err := h.xui.AddClient(ctx, inboundID, email, totalGB, expiryDays)
	if err != nil {
		return false, err.Error()
	}
	return true, fmt.Sprintf("Клиент %s успешно создан.", email)
}

func (h *Handler) showClientsList(chatID int64) {
	ctx := context.Background()
	allClients := []struct {
		api.ClientData
		InboundID     int
		InboundRemark string
	}{}

	for _, ibCfg := range h.cfg.Inbounds {
		log.Printf("🔍 [List] Запрос клиентов для inbound %d (%s)", ibCfg.ID, ibCfg.Remark)
		clients, err := h.xui.GetClientsFromInbound(ctx, ibCfg.ID)
		if err != nil {
			log.Printf("⚠️ Ошибка получения клиентов для inbound %d (%s): %v", ibCfg.ID, ibCfg.Remark, err)
			continue
		}
		log.Printf("✅ inbound %d: получено %d клиентов", ibCfg.ID, len(clients))
		for _, c := range clients {
			allClients = append(allClients, struct {
				api.ClientData
				InboundID     int
				InboundRemark string
			}{ClientData: c, InboundID: ibCfg.ID, InboundRemark: ibCfg.Remark})
		}
	}

	if len(allClients) == 0 {
		_, _ = h.bot.Send(tgbotapi.NewMessage(chatID, "📭 Список клиентов пуст."))
		return
	}

	onlineEmails, _ := h.xui.GetOnlineUsers(ctx)
	onlineMap := make(map[string]bool)
	for _, e := range onlineEmails {
		onlineMap[e] = true
	}

	var inlineKeys [][]tgbotapi.InlineKeyboardButton
	for _, c := range allClients {
		status := "🔴"
		if onlineMap[c.Email] {
			status = "🟢"
		}
		inlineKeys = append(inlineKeys, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(
				fmt.Sprintf("%s %s (%s)", status, c.Email, c.InboundRemark),
				fmt.Sprintf("info_%d_%s", c.InboundID, c.ID),
			),
			tgbotapi.NewInlineKeyboardButtonData(
				"🗑 Удалить",
				fmt.Sprintf("delete_%d_%s", c.InboundID, c.ID),
			),
		))
	}
	inlineKeys = append(inlineKeys, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData("🔙 Главное меню", "back_main"),
	))

	msg := tgbotapi.NewMessage(chatID, "📋 **Список клиентов:**")
	msg.ParseMode = tgbotapi.ModeMarkdown
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(inlineKeys...)
	_, _ = h.bot.Send(msg)
}

func (h *Handler) showServerInfo(chatID int64) {
	info := "ℹ️ **Информация о сервере**\n"
	info += fmt.Sprintf("Панель: %s\n", h.cfg.PanelURL)
	info += "Доступные inbound'ы:\n"
	for _, ib := range h.cfg.Inbounds {
		info += fmt.Sprintf("- %s (id %d)\n", ib.Remark, ib.ID)
	}
	inlineKeys := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔄 Перезапустить Xray", "restart_xray"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔙 Главное меню", "back_main"),
		),
	)
	msg := tgbotapi.NewMessage(chatID, info)
	msg.ParseMode = tgbotapi.ModeMarkdown
	msg.ReplyMarkup = inlineKeys
	_, _ = h.bot.Send(msg)
}

func (h *Handler) showClientCard(chatID int64, inboundID int, clientID string) {
	ctx := context.Background()
	port := h.getInboundPort(inboundID)
	if port == nil {
		_, _ = h.bot.Send(tgbotapi.NewMessage(chatID, "❌ Не удалось определить порт inbound."))
		return
	}
	inboundSettings, err := h.xui.GetInboundSettings(ctx, inboundID)
	if err != nil || inboundSettings == nil {
		_, _ = h.bot.Send(tgbotapi.NewMessage(chatID, "❌ Ошибка получения настроек inbound."))
		return
	}
	clients, err := h.xui.GetClientsFromInbound(ctx, inboundID)
	if err != nil || len(clients) == 0 {
		_, _ = h.bot.Send(tgbotapi.NewMessage(chatID, "❌ Клиент не найден."))
		return
	}
	var client *api.ClientData
	for i := range clients {
		if clients[i].ID == clientID {
			client = &clients[i]
			break
		}
	}
	if client == nil {
		_, _ = h.bot.Send(tgbotapi.NewMessage(chatID, "❌ Клиент не найден."))
		return
	}

	trafficInfo := "📊 **Использовано:** недоступно"
	traffic, err := h.xui.GetClientTraffic(ctx, client.Email)
	if err == nil && traffic != nil {
		up, _ := traffic["up"].(float64)
		down, _ := traffic["down"].(float64)
		total := (up + down) / (1024 * 1024 * 1024)
		trafficInfo = fmt.Sprintf("📊 **Использовано:** %.2f GB (↑%.2f ↓%.2f)\n",
			total, up/(1024*1024*1024), down/(1024*1024*1024))
	}

	totalGB := float64(client.TotalGB) / (1024 * 1024 * 1024)
	expiryDate := "бессрочно"
	if client.ExpiryTime > 0 {
		expiryDate = time.Unix(client.ExpiryTime/1000, 0).Format("2006-01-02")
	}
	enable := "Нет"
	if client.Enable {
		enable = "Да"
	}

	infoText := fmt.Sprintf(
		"📧 **Email:** %s\n"+
			"%s"+
			"📦 **Лимит:** %.2f GB\n"+
			"📅 **Истекает:** %s\n"+
			"✅ **Активен:** %s\n"+
			"🔌 **Inbound:** %d",
		client.Email, trafficInfo, totalGB, expiryDate, enable, inboundID,
	)

	inlineKeys := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("📋 Копировать ссылку", fmt.Sprintf("copy_%d_%s", inboundID, clientID)),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("📦 Изменить лимит (GB)", fmt.Sprintf("edit_limit_%d_%s", inboundID, clientID)),
			tgbotapi.NewInlineKeyboardButtonData("📅 Изменить срок (дни)", fmt.Sprintf("edit_expiry_%d_%s", inboundID, clientID)),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔄 Сбросить трафик", fmt.Sprintf("reset_traffic_%d_%s", inboundID, client.Email)),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔙 Назад к списку", "list_back"),
		),
	)

	msg := tgbotapi.NewMessage(chatID, infoText)
	msg.ParseMode = tgbotapi.ModeMarkdown
	msg.ReplyMarkup = inlineKeys
	_, _ = h.bot.Send(msg)
}

func (h *Handler) HandleCallback(query *tgbotapi.CallbackQuery) {
	if !h.isAuthorized(tgbotapi.Update{CallbackQuery: query}) {
		callback := tgbotapi.NewCallback(query.ID, "⛔ Доступ запрещён")
		_, _ = h.bot.Request(callback)
		return
	}

	data := query.Data
	chatID := query.Message.Chat.ID

	answer := func(text string) {
		_, _ = h.bot.Request(tgbotapi.NewCallback(query.ID, text))
	}

	switch {
	case data == "back_main":
		answer("OK")
		_, _ = h.bot.Request(tgbotapi.NewDeleteMessage(chatID, query.Message.MessageID))
		h.showMainMenu(chatID)
		return

	case data == "restart_xray":
		err := h.xui.RestartXray(context.Background())
		msg := "Сервис Xray успешно перезапущен."
		if err != nil {
			msg = "Ошибка: " + err.Error()
		}
		answer(msg)
		_, _ = h.bot.Request(tgbotapi.NewEditMessageText(chatID, query.Message.MessageID,
			fmt.Sprintf("%s %s", map[bool]string{true: "✅", false: "❌"}[err == nil], msg)))
		return

	case data == "list_back":
		answer("OK")
		h.showClientsList(chatID)
		return

	case strings.HasPrefix(data, "info_"):
		parts := strings.Split(data, "_")
		if len(parts) < 3 {
			answer("❌ Ошибка формата")
			return
		}
		inboundID, _ := strconv.Atoi(parts[1])
		clientID := parts[2]
		answer("OK")
		_, _ = h.bot.Request(tgbotapi.NewDeleteMessage(chatID, query.Message.MessageID))
		h.showClientCard(chatID, inboundID, clientID)
		return

	case strings.HasPrefix(data, "copy_"):
		parts := strings.Split(data, "_")
		if len(parts) < 3 {
			answer("❌ Ошибка формата")
			return
		}
		inboundID, _ := strconv.Atoi(parts[1])
		clientID := parts[2]
		port := h.getInboundPort(inboundID)
		if port == nil {
			answer("❌ Не удалось определить порт")
			return
		}
		inboundSettings, err := h.xui.GetInboundSettings(context.Background(), inboundID)
		if err != nil {
			answer("❌ Ошибка настроек")
			return
		}
		clients, err := h.xui.GetClientsFromInbound(context.Background(), inboundID)
		if err != nil {
			answer("❌ Клиент не найден")
			return
		}
		var client *api.ClientData
		for i := range clients {
			if clients[i].ID == clientID {
				client = &clients[i]
				break
			}
		}
		if client == nil {
			answer("❌ Клиент не найден")
			return
		}
		protocolType := "tcp"
		if _, ok := inboundSettings["grpcSettings"]; ok {
			protocolType = "grpc"
		}
		link := generateVLESSLink(client.ID, client.Email, h.cfg.ServerIP, *port, inboundSettings, protocolType)
		msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("`%s`", link))
		msg.ParseMode = tgbotapi.ModeMarkdown
		_, _ = h.bot.Send(msg)
		answer("✅ Ссылка отправлена")
		return

	case strings.HasPrefix(data, "edit_limit_"):
		parts := strings.Split(data, "_")
		if len(parts) < 3 {
			answer("❌ Ошибка формата")
			return
		}
		inboundID, _ := strconv.Atoi(parts[2])
		clientID := parts[3]
		editStatesMu.Lock()
		editStates[chatID] = EditState{Type: "limit", InboundID: inboundID, ClientID: clientID}
		editStatesMu.Unlock()
		answer("OK")
		_, _ = h.bot.Request(tgbotapi.NewEditMessageText(chatID, query.Message.MessageID,
			"Введите новый лимит трафика в GB (целое число, 0 - безлимит):"))
		return

	case strings.HasPrefix(data, "edit_expiry_"):
		parts := strings.Split(data, "_")
		if len(parts) < 3 {
			answer("❌ Ошибка формата")
			return
		}
		inboundID, _ := strconv.Atoi(parts[2])
		clientID := parts[3]
		editStatesMu.Lock()
		editStates[chatID] = EditState{Type: "expiry", InboundID: inboundID, ClientID: clientID}
		editStatesMu.Unlock()
		answer("OK")
		_, _ = h.bot.Request(tgbotapi.NewEditMessageText(chatID, query.Message.MessageID,
			"Введите новый срок действия в днях (целое число, 0 - бессрочно):"))
		return

	case strings.HasPrefix(data, "reset_traffic_"):
		parts := strings.Split(data, "_")
		if len(parts) < 3 {
			answer("❌ Ошибка формата")
			return
		}
		inboundID, _ := strconv.Atoi(parts[2])
		email := parts[3]
		err := h.xui.ResetClientTraffic(context.Background(), inboundID, email)
		msg := "Трафик успешно сброшен"
		if err != nil {
			msg = "Ошибка: " + err.Error()
		}
		answer(msg)
		_, _ = h.bot.Request(tgbotapi.NewEditMessageText(chatID, query.Message.MessageID,
			fmt.Sprintf("%s %s\n\nНажмите кнопку Назад и откройте карточку снова для обновления статистики.",
				map[bool]string{true: "✅", false: "❌"}[err == nil], msg)))
		return

	case strings.HasPrefix(data, "delete_"):
		parts := strings.Split(data, "_")
		if len(parts) < 3 {
			answer("❌ Ошибка формата")
			return
		}
		inboundID, _ := strconv.Atoi(parts[1])
		clientID := parts[2]
		inlineKeys := tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("✅ Да", fmt.Sprintf("confirm_%d_%s", inboundID, clientID)),
				tgbotapi.NewInlineKeyboardButtonData("❌ Нет", "list_back"),
			),
		)
		answer("OK")
		_, _ = h.bot.Request(tgbotapi.NewEditMessageText(chatID, query.Message.MessageID, "⚠️ Удалить клиента?"))
		_, _ = h.bot.Request(tgbotapi.NewEditMessageReplyMarkup(chatID, query.Message.MessageID, inlineKeys))
		return

	case strings.HasPrefix(data, "confirm_"):
		parts := strings.Split(data, "_")
		if len(parts) < 3 {
			answer("❌ Ошибка формата")
			return
		}
		inboundID, _ := strconv.Atoi(parts[1])
		clientID := parts[2]
		err := h.xui.DeleteClient(context.Background(), inboundID, clientID)
		msg := "Клиент удалён"
		if err != nil {
			msg = "Ошибка: " + err.Error()
		}
		answer(msg)
		backBtn := tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("🔙 К списку", "list_back"),
			),
		)
		_, _ = h.bot.Request(tgbotapi.NewEditMessageText(chatID, query.Message.MessageID,
			fmt.Sprintf("%s %s", map[bool]string{true: "✅", false: "❌"}[err == nil], msg)))
		_, _ = h.bot.Request(tgbotapi.NewEditMessageReplyMarkup(chatID, query.Message.MessageID, backBtn))
		return

	case h.isInboundRemark(data):
		var inboundID int
		for _, ib := range h.cfg.Inbounds {
			if ib.Remark == data {
				inboundID = ib.ID
				break
			}
		}
		if inboundID == 0 {
			answer("❌ Inbound не найден")
			return
		}
		editStatesMu.Lock()
		editStates[chatID] = EditState{Type: "create_name", InboundID: inboundID}
		editStatesMu.Unlock()
		answer("OK")
		_, _ = h.bot.Send(tgbotapi.NewMessage(chatID, "✏️ Введите имя клиента (email):"))
		return
	}
	answer("🚧 Функция в разработке")
}

func (h *Handler) isInboundRemark(text string) bool {
	for _, ib := range h.cfg.Inbounds {
		if ib.Remark == text {
			return true
		}
	}
	return false
}