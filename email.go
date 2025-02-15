package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"gopkg.in/gomail.v2"
)

func GenerateVerificationCode() string {
	b := make([]byte, 6)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:6]
}

func sendVerificationEmail(email, code string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", EmailSender)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Email Verification Code")
	m.SetBody("text/plain", fmt.Sprintf("Your verification code is: %s", code))
	d := gomail.NewDialer(SMTPServer, SMTPPort, EmailSender, EmailPassword)
	return d.DialAndSend(m)
}

func verifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if request.Email == "" || request.Code == "" {
		http.Error(w, "Email and verification code are required", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.Where("email = ? AND verification_code = ?", request.Email, request.Code).First(&user).Error; err != nil {
		http.Error(w, "Invalid email or verification code", http.StatusBadRequest)
		return
	}

	user.EmailVerified = true
	user.VerificationCode = ""

	if err := db.Save(&user).Error; err != nil {
		http.Error(w, "Error updating email verification status", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Email verified successfully"})
}

func sendEmail(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form to handle file uploads
	if err := r.ParseMultipartForm(10 << 20); err != nil { // Limit to 10 MB
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to parse form"})
		return
	}

	// Get email fields from form
	recipient := r.FormValue("recipient")
	subject := r.FormValue("subject")
	body := r.FormValue("body")

	if recipient == "" || subject == "" || body == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Recipient, subject, and body are required"})
		return
	}

	// Handle file uploads
	files := r.MultipartForm.File["attachments"]
	m := gomail.NewMessage()
	m.SetHeader("From", EmailSender)
	m.SetHeader("To", recipient)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", body)

	// Attach files to the email
	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to open attachment: " + err.Error()})
			return
		}
		defer file.Close()

		m.Attach(fileHeader.Filename, gomail.SetCopyFunc(func(w io.Writer) error {
			_, err := io.Copy(w, file)
			return err
		}))
	}

	// Send the email
	d := gomail.NewDialer(SMTPServer, SMTPPort, EmailSender, EmailPassword)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true} // Add this if TLS certificate issues occur

	if err := d.DialAndSend(m); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to send email: " + err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Email sent successfully with attachments"})
}

func sendEmailWithAttachment(to string, subject string, body string, attachmentPath string) error {
	log.Println("📧 Preparing to send email...")
	log.Println("📤 Recipient:", to)
	log.Println("📄 Attaching file:", attachmentPath)

	m := gomail.NewMessage()
	m.SetHeader("From", EmailSender)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", body)

	// Attach the receipt PDF
	if attachmentPath != "" {
		m.Attach(attachmentPath)
	}

	// Configure SMTP server
	d := gomail.NewDialer(SMTPServer, SMTPPort, EmailSender, EmailPassword)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true} // Bypass TLS verification if needed

	// Send the email
	err := d.DialAndSend(m)
	if err != nil {
		log.Println("❌ Email failed to send:", err)
		return fmt.Errorf("Failed to send email: %v", err)
	}

	log.Println("✅ Email sent successfully to:", to)
	return nil
}

func sendReceiptEmail(customerID uint, receiptPath string) error {
	// Fetch the user's email from the database
	var user User
	if err := db.First(&user, customerID).Error; err != nil {
		log.Println("❌ Error: User not found in database:", err)
		return fmt.Errorf("User not found")
	}

	log.Println("📧 Sending receipt email to:", user.Email)

	// Email Content
	subject := "Your Payment Receipt"
	body := fmt.Sprintf("Dear %s,\n\nThank you for your payment. Attached is your receipt.\n\nBest regards,\nSelf Blog.kz", user.Name)

	// Call email sending function
	err := sendEmailWithAttachment(user.Email, subject, body, receiptPath)
	if err != nil {
		log.Println("❌ Error sending email:", err)
	} else {
		log.Println("✅ Email sent successfully to:", user.Email)
	}

	return err
}
