package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

// PaymentRequest represents incoming payment data
type PaymentRequest struct {
	TransactionID  uint   `json:"transaction_id"`
	CardNumber     string `json:"card_number"`
	ExpirationDate string `json:"expiration_date"`
	CVV            string `json:"cvv"`
}

// PaymentResponse represents the response sent back to the main server
type PaymentResponse struct {
	TransactionID uint   `json:"transaction_id"`
	Status        string `json:"status"`
	Message       string `json:"message"`
}

func processPayment(w http.ResponseWriter, r *http.Request) {
	var request PaymentRequest

	// Decode JSON request
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, `{"message": "Invalid request format"}`, http.StatusBadRequest)
		return
	}

	log.Printf("Processing payment for Transaction ID: %d", request.TransactionID)

	// Simulate payment success/failure based on the card number
	var status, message string
	if request.CardNumber == "4242424242424242" {
		status = "paid"
		message = "Payment successful"
	} else {
		status = "declined"
		message = "Payment failed"
	}

	// Send the payment result back to the main server
	callbackURL := "http://localhost:8080/payment-callback"
	response := PaymentResponse{
		TransactionID: request.TransactionID,
		Status:        status,
		Message:       message,
	}

	jsonData, _ := json.Marshal(response)

	// ✅ Use `bytes.NewBuffer(jsonData)` instead of `json.NewDecoder(jsonData)`
	_, err := http.Post(callbackURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Println("Error sending callback request:", err)
	}

	// Send response to the client
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// CORS Middleware to allow frontend requests
func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8080") // Allow frontend requests
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// ✅ Properly Handle OPTIONS (Preflight Request)
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()
	r.Use(enableCORS) // ✅ Apply CORS Middleware globally

	// ✅ Explicitly Handle OPTIONS Requests for `/process-payment`
	r.HandleFunc("/process-payment", processPayment).Methods("POST")
	r.HandleFunc("/process-payment", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods("OPTIONS") // ✅ Fixes CORS Prefligh

	log.Println("✅ Payment Microservice running on port 8081")
	http.ListenAndServe(":8081", r)
}
