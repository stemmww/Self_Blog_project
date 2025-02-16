package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"gorm.io/gorm"
)

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Error upgrading to WebSocket:", err)
		return
	}
	defer conn.Close()

	userID := r.Context().Value("user_id").(uint)
	clients[conn] = userID

	for {
		var msg ChatMessage
		if err := conn.ReadJSON(&msg); err != nil {
			log.Println("Error reading message:", err)
			delete(clients, conn)
			break
		}

		msg.Time = time.Now().Format("15:04:05")
		broadcast <- msg
	}
}

func handleMessages(db *gorm.DB) {
	for {
		msg := <-broadcast

		// Save message to database
		newMsg := Message{
			ChatID:    msg.ChatID,
			UserID:    msg.UserID,
			Sender:    msg.Sender,
			Content:   msg.Content,
			Timestamp: time.Now(),
		}
		db.Create(&newMsg)

		// Send message to all clients
		for client := range clients {
			if err := client.WriteJSON(msg); err != nil {
				log.Println("Error writing message:", err)
				client.Close()
				delete(clients, client)
			}
		}
	}
}

func createChatHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(uint)

	var activeChat Chat
	db.Where("user_id = ? AND status = ?", userID, "active").First(&activeChat)

	if activeChat.ID != 0 {
		http.Error(w, "You already have an active chat", http.StatusConflict)
		return
	}

	newChat := Chat{
		UserID:    userID,
		Status:    "active",
		CreatedAt: time.Now(),
	}
	db.Create(&newChat)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newChat)
}

func getActiveChatsHandler(w http.ResponseWriter, r *http.Request) {
	var activeChats []Chat
	db.Where("status = ?", "active").Find(&activeChats)
	json.NewEncoder(w).Encode(activeChats)
}

func closeChatHandler(w http.ResponseWriter, r *http.Request) {
	chatID := r.URL.Query().Get("chat_id")
	db.Model(&Chat{}).Where("id = ?", chatID).Update("status", "inactive")
	w.Write([]byte("Chat closed successfully"))
}
