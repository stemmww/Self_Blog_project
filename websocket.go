package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// 📌 Обработчик WebSocket подключений
func wsHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("📡 WebSocket: New connection attempt")

	query := r.URL.Query()
	token := query.Get("token")
	chatIDParam := query.Get("chat_id")

	if token == "" || chatIDParam == "" {
		http.Error(w, "Missing token or chat_id", http.StatusBadRequest)
		log.Println("❌ Missing token or chat_id")
		return
	}

	chatID := parseChatID(chatIDParam)
	if chatID == 0 {
		http.Error(w, "Invalid chat_id", http.StatusBadRequest)
		log.Println("❌ Invalid chat_id format")
		return
	}

	// Обновляем соединение до WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("❌ WebSocket upgrade error:", err)
		return
	}
	defer conn.Close()

	log.Printf("✅ WebSocket connected to ChatID: %d", chatID)

	// Регистрируем клиента
	mu.Lock()
	clients[chatID] = conn
	mu.Unlock()

	// Отправляем историю сообщений
	sendChatHistory(chatID, conn)

	// Читаем входящие сообщения
	for {
		var msg ChatMessage
		if err := conn.ReadJSON(&msg); err != nil {
			log.Println("❌ WebSocket read error:", err)
			break
		}

		msg.ChatID = chatID
		msg.Time = time.Now().Format("15:04:05")

		log.Printf("📨 Message received: %+v", msg)

		// Сохраняем сообщение в базе данных
		saveMessageToDB(msg)

		// Отправляем сообщение в канал для трансляции
		broadcast <- msg
	}

	// Удаляем клиента из списка при отключении
	mu.Lock()
	delete(clients, chatID)
	mu.Unlock()

	log.Printf("❌ WebSocket disconnected from ChatID: %d", chatID)
}

// 📡 Трансляция сообщений всем подключённым клиентам
func handleMessages() {
	for {
		msg := <-broadcast
		mu.Lock()
		if conn, ok := clients[msg.ChatID]; ok {
			if err := conn.WriteJSON(msg); err != nil {
				log.Println("❌ Error sending message:", err)
				conn.Close()
				delete(clients, msg.ChatID)
			}
		}
		mu.Unlock()
	}
}

// 🗃️ Сохранение сообщений в базе данных
func saveMessageToDB(msg ChatMessage) {
	newMsg := Message{
		ChatID:    msg.ChatID,
		UserID:    0, // Заменить на получение userID из токена при реализации аутентификации
		Sender:    msg.Sender,
		Content:   msg.Content,
		Timestamp: time.Now(),
	}

	if err := db.Create(&newMsg).Error; err != nil {
		log.Printf("❌ Error saving message to database: %v", err)
	} else {
		log.Printf("💾 Message saved to DB for ChatID %d", msg.ChatID)
	}
}

// 📜 Отправка истории сообщений при подключении
func sendChatHistory(chatID uint, conn *websocket.Conn) {
	var messages []Message
	if err := db.Where("chat_id = ?", chatID).Order("timestamp asc").Find(&messages).Error; err != nil {
		log.Println("❌ Error retrieving chat history:", err)
		return
	}

	for _, message := range messages {
		msg := ChatMessage{
			ChatID:  message.ChatID,
			Sender:  message.Sender,
			Content: message.Content,
			Time:    message.Timestamp.Format("15:04:05"),
		}
		if err := conn.WriteJSON(msg); err != nil {
			log.Println("❌ Error sending chat history:", err)
			return
		}
	}
	log.Printf("📜 Chat history sent to ChatID: %d", chatID)
}

// 🛑 Закрытие чата
func closeChatHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	chatID := parseChatID(query.Get("chat_id"))

	if chatID == 0 {
		http.Error(w, "Invalid chat ID", http.StatusBadRequest)
		return
	}

	db.Model(&Chat{}).Where("id = ?", chatID).Update("status", "inactive")

	// Закрываем WebSocket соединение
	mu.Lock()
	if conn, ok := clients[chatID]; ok {
		conn.Close()
		delete(clients, chatID)
	}
	mu.Unlock()

	log.Printf("🚫 Chat %d closed by admin", chatID)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Chat %d closed", chatID)))
}

// 📊 Получение списка активных чатов для администратора
func getActiveChatsHandler(w http.ResponseWriter, r *http.Request) {
	var activeChats []Chat
	db.Where("status = ?", "active").Find(&activeChats)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(activeChats)
}

// 🆕 Создание нового чата для пользователя
func createChatHandler(w http.ResponseWriter, r *http.Request) {
	userID := 1 // Подставьте реальный userID после аутентификации

	var existingChat Chat
	if err := db.Where("user_id = ? AND status = ?", userID, "active").First(&existingChat).Error; err == nil {
		log.Printf("⚠️ Active chat already exists for user %d", userID)
		json.NewEncoder(w).Encode(existingChat)
		return
	}

	newChat := Chat{
		UserID:    uint(userID), // Приводим int к uint
		Status:    "active",
		CreatedAt: time.Now(),
	}

	if err := db.Create(&newChat).Error; err != nil {
		http.Error(w, "Failed to create chat", http.StatusInternalServerError)
		return
	}

	log.Printf("✅ New chat created with ID: %d for User: %d", newChat.ID, userID)
	json.NewEncoder(w).Encode(newChat)
}

// 📌 Вспомогательная функция для парсинга chat_id
func parseChatID(param string) uint {
	var chatID uint
	_, err := fmt.Sscanf(param, "%d", &chatID)
	if err != nil {
		log.Printf("❌ Error parsing chat_id: %v", err)
		return 0
	}
	return chatID
}
