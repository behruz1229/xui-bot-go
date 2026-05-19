package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/bek/xui-bot-go/internal/api"
	"github.com/bek/xui-bot-go/internal/bot"
	"github.com/bek/xui-bot-go/internal/config"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("🚀 Запуск xui-bot-go...")

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("❌ Ошибка загрузки конфига: %v", err)
	}
	log.Printf("✅ Конфиг расшифрован. Авторизованный ID: %d", cfg.AuthorizedUserID)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("📥 Получен сигнал остановки. Завершаем работу...")
		cancel()
	}()

	xui := api.NewClient(cfg.PanelURL, cfg.PanelLogin, cfg.PanelPassword)
	if err := xui.Login(ctx); err != nil {
		log.Fatalf("❌ Ошибка авторизации в панели: %v", err)
	}
	log.Println("✅ Авторизация в 3x-ui успешна")

	// 🔁 Фоновое обновление сессии каждые 3 часа
	go func() {
		ticker := time.NewTicker(3 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				log.Println("🔄 Фоновое обновление сессии 3x-ui...")
				if err := xui.Login(ctx); err != nil {
					log.Printf("⚠️ Ошибка обновления сессии: %v (повторится через 3ч)", err)
				} else {
					log.Println("✅ Сессия успешно обновлена")
				}
			}
		}
	}()

	botAPI, err := tgbotapi.NewBotAPI(cfg.Token)
	if err != nil {
		log.Fatalf("❌ Ошибка инициализации Telegram бота: %v", err)
	}
	botAPI.Debug = false
	log.Printf("✅ Telegram бот авторизован как @%s", botAPI.Self.UserName)

	handler := bot.NewHandler(botAPI, xui, cfg)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 30
	updates := botAPI.GetUpdatesChan(u)

	log.Println("✅ Бот запущен. Ожидание команд...")

	for {
		select {
		case <-ctx.Done():
			log.Println("🛑 Остановка поллинга...")
			botAPI.StopReceivingUpdates()
			return
		case update, ok := <-updates:
			if !ok {
				log.Println("⚠️ Канал обновлений закрыт")
				return
			}
			if update.Message != nil {
				if update.Message.IsCommand() && update.Message.Command() == "start" {
					handler.HandleStart(update)
				} else {
					handler.HandleText(*update.Message)
				}
			} else if update.CallbackQuery != nil {
				handler.HandleCallback(update.CallbackQuery)
			}
		}
	}
}