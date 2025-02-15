package main

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var (
	clients   = make(map[*websocket.Conn]bool) // Connected clients
	broadcast = make(chan ChatMessage)         // Broadcast channel
	mu        sync.Mutex                       // Mutex to lock clients map
	upgrader  = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins
		},
	}
)

// WebSocket handler for chat
func chatHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	mu.Lock()
	clients[conn] = true
	mu.Unlock()

	// Load previous messages from DB
	var previousMessages []ChatMessage
	db.Order("timestamp asc").Find(&previousMessages)
	for _, msg := range previousMessages {
		conn.WriteJSON(msg)
	}

	for {
		var msg ChatMessage
		err := conn.ReadJSON(&msg)
		if err != nil {
			log.Printf("WebSocket read error: %v", err)
			mu.Lock()
			delete(clients, conn)
			mu.Unlock()
			break
		}

		// Set timestamp and save to database
		msg.Timestamp = time.Now()
		db.Create(&msg)

		// Broadcast the message to all connected clients
		broadcast <- msg
	}
}

// Listen for broadcast messages and send them to all clients
func handleMessages() {
	for {
		msg := <-broadcast
		mu.Lock()
		for client := range clients {
			err := client.WriteJSON(msg)
			if err != nil {
				log.Printf("WebSocket write error: %v", err)
				client.Close()
				delete(clients, client)
			}
		}
		mu.Unlock()
	}
}
