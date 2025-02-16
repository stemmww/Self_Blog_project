package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/websocket"
)

// 📌 Обработчик WebSocket подключений
// 📡 Обработчик WebSocket
func wsHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	chatID := parseChatID(query.Get("chat_id"))
	role := query.Get("role") // user или admin

	if chatID == 0 || (role != "user" && role != "admin") {
		http.Error(w, "Invalid parameters", http.StatusBadRequest)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("❌ WebSocket upgrade error:", err)
		return
	}
	defer conn.Close()

	log.Printf("✅ WebSocket connected: ChatID=%d, Role=%s", chatID, role)

	// Регистрируем соединение в зависимости от роли
	mu.Lock()
	if role == "user" {
		clients[chatID] = conn
	} else if role == "admin" {
		adminConn[chatID] = conn
	}
	mu.Unlock()

	// Отправляем историю сообщений
	sendChatHistory(chatID, conn)

	for {
		var msg ChatMessage
		if err := conn.ReadJSON(&msg); err != nil {
			log.Println("❌ WebSocket read error:", err)
			break
		}

		// Extract user_id from the JWT token
		tokenString := r.URL.Query().Get("token")
		if tokenString != "" {
			claims := &Claims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				return jwtSecret, nil
			})
			if err == nil && token.Valid {
				msg.UserID = claims.UserID
			}
		}

		msg.ChatID = chatID
		msg.Time = time.Now().Format("15:04:05")

		log.Printf("📨 Received message: %+v", msg)

		// Сохраняем сообщение в базе данных
		saveMessageToDB(msg)

		// Пересылаем сообщение другому участнику чата
		mu.Lock()
		if role == "user" {
			if admin, ok := adminConn[chatID]; ok {
				admin.WriteJSON(msg)
			}
		} else if role == "admin" {
			if user, ok := clients[chatID]; ok {
				user.WriteJSON(msg)
			}
		}
		mu.Unlock()
	}

	// Удаляем соединение при отключении
	mu.Lock()
	if role == "user" {
		delete(clients, chatID)
	} else if role == "admin" {
		delete(adminConn, chatID)
	}
	mu.Unlock()

	log.Printf("❌ WebSocket disconnected: ChatID=%d, Role=%s", chatID, role)
}

// 📡 Трансляция сообщений всем участникам чата
func handleMessages() {
	for {
		msg := <-broadcast
		mu.Lock()
		for chatID, conn := range clients {
			if chatID == msg.ChatID { // Рассылаем только участникам этого чата
				if err := conn.WriteJSON(msg); err != nil {
					log.Println("❌ Error sending message:", err)
					conn.Close()
					delete(clients, chatID)
				}
			}
		}
		mu.Unlock()
	}
}

// 🗃️ Сохранение сообщений в базе данных
func saveMessageToDB(msg ChatMessage) {
	newMsg := Message{
		ChatID:    msg.ChatID,
		UserID:    msg.UserID, // Use the UserID from the message
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

func createChatHandler(w http.ResponseWriter, r *http.Request) {
	// Extract user_id from the JWT token
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	tokenString = strings.TrimSpace(tokenString)

	if tokenString == "" {
		http.Error(w, "Unauthorized: No token provided", http.StatusUnauthorized)
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	userID := claims.UserID // Get the user_id from the token

	// Check if the user already has an active chat
	var existingChat Chat
	if err := db.Where("user_id = ? AND status = ?", userID, "active").First(&existingChat).Error; err == nil {
		log.Printf("⚠️ Active chat already exists for user %d", userID)
		json.NewEncoder(w).Encode(existingChat)
		return
	}

	// Create a new chat for the user
	newChat := Chat{
		UserID:    userID, // Use the user_id from the token
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
