package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jung-kurt/gofpdf"
	"golang.org/x/crypto/bcrypt"
)

func getUserProfile(w http.ResponseWriter, r *http.Request) {
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

	userID := claims.UserID
	var user User
	if err := db.Where("id = ?", userID).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	response := map[string]interface{}{
		"id":              user.ID,
		"name":            user.Name,
		"email":           user.Email,
		"profile_picture": user.ProfilePicture, // Include the profile picture URL or path here
	}

	json.NewEncoder(w).Encode(response)
}

func updateUserProfile(w http.ResponseWriter, r *http.Request) {
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

	userID := claims.UserID
	var user User
	if err := db.Where("id = ?", userID).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Parse form data
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	email := r.FormValue("email")
	password := r.FormValue("password")
	profilePicture, _, err := r.FormFile("profile_picture")

	// Validate the incoming data
	if name != "" {
		user.Name = name
	}
	if email != "" {
		user.Email = email
	}

	// If password is provided, hash it and update
	if password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}
		user.PasswordHash = string(hashedPassword)
	}

	// If profile picture is provided, save it
	if profilePicture != nil {
		// Store the profile picture (You may need to save the image in the file system or cloud)
		filePath := fmt.Sprintf("uploads/%d_%d.jpg", user.ID, time.Now().Unix())
		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Error saving profile picture", http.StatusInternalServerError)
			return
		}
		defer file.Close()
		_, err = io.Copy(file, profilePicture)
		if err != nil {
			http.Error(w, "Error copying profile picture", http.StatusInternalServerError)
			return
		}
		user.ProfilePicture = filePath // Store the file path or URL in the DB
	}

	// Save updated user
	if err := db.Save(&user).Error; err != nil {
		http.Error(w, "Error updating user", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Profile updated successfully"})
}

func paymentCallbackHandler(w http.ResponseWriter, r *http.Request) {
	var callback PaymentCallback

	// Decode JSON request
	if err := json.NewDecoder(r.Body).Decode(&callback); err != nil {
		http.Error(w, `{"message": "Invalid request format"}`, http.StatusBadRequest)
		fmt.Println("❌ Invalid callback request:", err)
		return
	}

	fmt.Println("🟢 Received payment update for Transaction ID:", callback.TransactionID, "New Status:", callback.Status)

	// Fetch the transaction from the database
	var transaction Transaction
	if err := db.First(&transaction, callback.TransactionID).Error; err != nil {
		http.Error(w, `{"message": "Transaction not found"}`, http.StatusNotFound)
		fmt.Println("❌ Transaction not found in database:", err)
		return
	}

	// Update transaction status to "Completed" after successful payment
	if callback.Status == "paid" {
		transaction.Status = "Completed"
	} else {
		transaction.Status = "Declined"
	}

	transaction.UpdatedAt = time.Now()

	// Save the transaction status in the database
	if err := db.Save(&transaction).Error; err != nil {
		http.Error(w, `{"message": "Failed to update transaction status"}`, http.StatusInternalServerError)
		fmt.Println("❌ Failed to update transaction:", err)
		return
	}

	fmt.Println("✅ Transaction updated to:", transaction.Status)

	// If payment is successful, generate and send receipt
	if callback.Status == "paid" {
		receiptPath := fmt.Sprintf("receipts/receipt_%d.pdf", transaction.ID)
		err := generateReceipt(transaction, receiptPath)
		if err != nil {
			fmt.Println("❌ Error generating receipt:", err)
		} else {
			fmt.Println("📄 Receipt generated:", receiptPath)

			// Send Receipt Email
			go func() {
				err = sendReceiptEmail(transaction.CustomerID, receiptPath)
				if err != nil {
					fmt.Println("❌ Error sending receipt email:", err)
				} else {
					fmt.Println("📧 Receipt email sent successfully")
				}
			}()
		}
	}

	// Send response to the frontend
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Transaction updated successfully",
		"status":  transaction.Status,
	})
}

func createTransactionHandler(w http.ResponseWriter, r *http.Request) {
	// Verify user authentication
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tokenString == "" {
		http.Error(w, `{"message": "Unauthorized: No token provided"}`, http.StatusUnauthorized)
		return
	}

	// Parse the JWT to get the user ID
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, `{"message": "Unauthorized: Invalid token"}`, http.StatusUnauthorized)
		return
	}

	// Decode request JSON
	var request struct {
		Amount float64 `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, `{"message": "Invalid request format"}`, http.StatusBadRequest)
		return
	}

	// Validate amount
	if request.Amount <= 0 {
		http.Error(w, `{"message": "Invalid donation amount"}`, http.StatusBadRequest)
		return
	}

	// Create a new transaction
	transaction := Transaction{
		CustomerID: claims.UserID,
		Amount:     request.Amount,
		Status:     "pending",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Save to the database
	if err := db.Create(&transaction).Error; err != nil {
		http.Error(w, `{"message": "Failed to create transaction"}`, http.StatusInternalServerError)
		return
	}

	// Respond with the transaction ID
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":        "Transaction created",
		"transaction_id": transaction.ID,
	})
}

func generateReceipt(transaction Transaction, filePath string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)

	pdf.Cell(40, 10, "Official Payment Receipt")
	pdf.Ln(10)

	// ✅ Company Name (Header)
	pdf.Cell(40, 10, "Self Blog.kz - Official Payment Receipt")
	pdf.Ln(10)

	pdf.SetFont("Arial", "", 12)
	pdf.Cell(40, 10, fmt.Sprintf("Transaction ID: %d", transaction.ID))
	pdf.Ln(8)
	pdf.Cell(40, 10, fmt.Sprintf("Customer ID: %d", transaction.CustomerID))
	pdf.Ln(8)
	pdf.Cell(40, 10, fmt.Sprintf("Amount: $%.2f", transaction.Amount))
	pdf.Ln(8)
	pdf.Cell(40, 10, fmt.Sprintf("Status: %s", transaction.Status))
	pdf.Ln(8)
	pdf.Cell(40, 10, fmt.Sprintf("Date: %s", time.Now().Format("2006-01-02 15:04:05")))

	// Save the PDF
	return pdf.OutputFileAndClose(filePath)
}

func getTransactionsHandler(w http.ResponseWriter, r *http.Request) {
	// Get user ID from token
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tokenString == "" {
		http.Error(w, `{"message": "Unauthorized: No token provided"}`, http.StatusUnauthorized)
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, `{"message": "Unauthorized: Invalid token"}`, http.StatusUnauthorized)
		return
	}

	// Fetch transactions for the logged-in user
	var transactions []Transaction
	if err := db.Where("customer_id = ?", claims.UserID).Find(&transactions).Error; err != nil {
		http.Error(w, `{"message": "Error fetching transactions"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(transactions)
}
