package main

// +profile, +manage data, +selenium login
import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jung-kurt/gofpdf"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB
var logger = logrus.New()

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

// Define the User struct
type User struct {
	ID               uint   `json:"id" gorm:"primaryKey"`
	Name             string `json:"name"`
	Email            string `json:"email"`
	Password         string `json:"-" gorm:"-"` // Добавляем это поле, но оно не будет сохраняться в БД
	PasswordHash     string `json:"-"`
	Role             string `json:"role"`
	EmailVerified    bool   `json:"email_verified"`
	VerificationCode string `json:"-"`
	ProfilePicture   string `json:"profile_picture"` // Add this line for storing the profile picture path or URL
}

// Define the Transaction struct
type Transaction struct {
	ID         uint      `json:"id" gorm:"primaryKey"`
	CustomerID uint      `json:"customer_id"`
	Amount     float64   `json:"amount"`
	Status     string    `json:"status" gorm:"default:pending"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// PaymentCallback represents the response from the payment microservice
type PaymentCallback struct {
	TransactionID uint   `json:"transaction_id"`
	Status        string `json:"status"`
	Message       string `json:"message"`
}

type Claims struct {
	UserID uint   `json:"user_id"`
	Role   string `json:"role"`
	jwt.StandardClaims
}

type Article struct {
	ID      uint   `json:"id" gorm:"primaryKey"`
	Title   string `json:"title"`
	Content string `json:"content"`
	Name    string `json:"name" gorm:"column:name"` // New column name
	UserID  uint   `json:"user_id"`
	User    User   `json:"user" gorm:"foreignKey:UserID"`
}

// Define visitor struct first
type visitor struct {
	lastSeen   time.Time
	requests   int
	limiter    *rateLimiter
	resetTimer *time.Timer
}

// Define rateLimiter struct
type rateLimiter struct {
	visitors map[string]*visitor
	mu       sync.Mutex
	limit    int
	interval time.Duration
}

const (
	SMTPServer    = "smtp.mail.ru" // Replace with your SMTP server
	SMTPPort      = 587            // Usually 587 for TLS
	EmailSender   = "gsosayanbek@mail.ru"
	EmailPassword = "DWnJjJG7Pnp9YPS3MMea"
	// EmailPassword = "NLJF3P2TZU0mh8uKzQf3"
	// Use an app password if needed
)

type EmailRequest struct {
	Recipient string `json:"recipient"`
	Subject   string `json:"subject"`
	Body      string `json:"body"`
}

//// reg

func init() {
	var err error
	dsn := "user=postgres password=admin dbname=bloguser port=5433 sslmode=disable"
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to database")
	}
	// Auto-migrate tables
	db.AutoMigrate(&User{}, &Article{}, &Transaction{})
}

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

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if request.Email == "" || request.Password == "" || request.Name == "" {
		http.Error(w, "Name, email, and password are required", http.StatusBadRequest)
		return
	}

	// Проверяем, существует ли пользователь с таким email
	var existingUser User
	if err := db.Where("email = ?", request.Email).First(&existingUser).Error; err == nil {
		http.Error(w, "User with this email already exists", http.StatusBadRequest)
		return
	}

	// Хешируем пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	// Создаем нового пользователя
	user := User{
		Name:             request.Name,
		Email:            request.Email,
		PasswordHash:     string(hashedPassword),
		Role:             "user",
		EmailVerified:    false,
		VerificationCode: GenerateVerificationCode(),
	}

	// Сохраняем пользователя в базу
	if err := db.Create(&user).Error; err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	// Отправляем письмо с кодом верификации
	if err := sendVerificationEmail(user.Email, user.VerificationCode); err != nil {
		http.Error(w, "Failed to send verification email", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered. Check your email for verification code."})
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

func authMiddleware(next http.HandlerFunc, requiredRole string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		tokenString = strings.TrimSpace(tokenString) // Remove any extra spaces

		fmt.Println("Raw Authorization header:", tokenString)

		if tokenString == "" {
			http.Error(w, "Unauthorized: No token provided", http.StatusUnauthorized)
			return
		}

		// Убираем "Bearer " из токена
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		fmt.Println("Extracted Token:", tokenString)

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})
		if err != nil {
			fmt.Println("JWT parsing error:", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		claims, ok := token.Claims.(*Claims)
		if !ok || !token.Valid {
			fmt.Println("Invalid token structure")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if err != nil || !token.Valid {
			fmt.Println("JWT validation failed:", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		fmt.Println("Token valid! UserID:", claims.UserID, "Role:", claims.Role)

		// Пропускаем запрос дальше
		next(w, r)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Логируем полученные данные
	fmt.Println("🔹 Логин: получен запрос на аутентификацию:", request.Email)

	var user User
	if err := db.Where("email = ?", request.Email).First(&user).Error; err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Проверяем пароль
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.Password)); err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Логируем jwtSecret перед генерацией токена
	fmt.Println("🔹 jwtSecret при генерации токена:", string(jwtSecret))

	// Генерируем новый токен
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID: user.ID,
		Role:   user.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// Логируем сгенерированный токен
	fmt.Println("✅ Сгенерированный токен:", tokenString)

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func logHandler(next http.HandlerFunc, route string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.WithFields(logrus.Fields{
			"method": r.Method,
			"url":    r.URL.Path,
			"route":  route,
			"ip":     r.RemoteAddr,
		}).Info("HTTP request received")
		next(w, r)
	}
}

func createUserHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Name     string `json:"name"`
			Email    string `json:"email"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Ensure required fields are provided
		if request.Name == "" || request.Email == "" || request.Password == "" || request.Role == "" {
			http.Error(w, "All fields (name, email, password, role) are required", http.StatusBadRequest)
			return
		}

		// Hash the password before saving
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}

		// Create user with provided role
		user := User{
			Name:          request.Name,
			Email:         request.Email,
			Role:          request.Role,
			PasswordHash:  string(hashedPassword),
			EmailVerified: false, // User needs to verify email
		}

		if err := db.Create(&user).Error; err != nil {
			http.Error(w, "Error creating user", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "User created successfully",
			"email":   user.Email,
		})
	}
}

func main() {

	r := mux.NewRouter()
	// Initialize the rate limiter
	//Initialize the rate limiter
	rl := newRateLimiter(1000, time.Minute) // Allow 1000 requests per minute per IP

	// Configure Logrus
	logger.SetFormatter(&logrus.JSONFormatter{}) // Logs in JSON format
	logger.SetLevel(logrus.InfoLevel)            // Set logging level
	logger.Info("Server is starting...")

	// Database Connection ///////////////////////////////////////////////////////////////////////
	dsn := "user=postgres password=admin dbname=bloguser port=5433 sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		logger.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Fatal("Failed to connect to the database")
	}
	// Auto-migrate: Create tables if they don't exist
	if err := db.AutoMigrate(&User{}, &Article{}); err != nil {
		logger.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Fatal("Failed to auto-migrate tables")
	}

	logger.Info("Database connection established and migrations applied")

	// ROUTES ////////////////////////////////////////////////////////////////////////////////
	r.HandleFunc("/register", registerHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/verify-email", verifyEmailHandler).Methods("POST")
	r.HandleFunc("/create-transaction", authMiddleware(createTransactionHandler, "user")).Methods("POST")
	r.HandleFunc("/payment-callback", paymentCallbackHandler).Methods("POST")
	r.HandleFunc("/get-transactions", authMiddleware(getTransactionsHandler, "user")).Methods("GET")
	r.Handle("/create", rl.limitMiddleware(http.HandlerFunc(createUserHandler(db)))).Methods("POST")
	r.Handle("/users", rl.limitMiddleware(http.HandlerFunc(getUsers))).Methods("GET")
	r.HandleFunc("/profile", authMiddleware(getUserProfile, "user")).Methods("GET")
	r.HandleFunc("/profile", authMiddleware(updateUserProfile, "user")).Methods("PUT")
	r.Handle("/update", rl.limitMiddleware(http.HandlerFunc(updateUser))).Methods("PUT")
	r.Handle("/delete", rl.limitMiddleware(http.HandlerFunc(deleteUser))).Methods("DELETE")
	r.Handle("/search", rl.limitMiddleware(http.HandlerFunc(searchUser))).Methods("GET")
	r.Handle("/articles", rl.limitMiddleware(http.HandlerFunc(handleArticles))).Methods("GET", "POST")
	r.Handle("/send-email", rl.limitMiddleware(http.HandlerFunc(sendEmail))).Methods("POST")

	http.Handle("/uploads/", http.StripPrefix("/uploads", http.FileServer(http.Dir("./uploads"))))

	r.HandleFunc("/articles", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			var articles []Article
			// Preload User data to fetch the author name
			if err := db.Preload("User").Find(&articles).Error; err != nil {
				http.Error(w, "Error fetching articles", http.StatusInternalServerError)
				return
			}

			// Manually assign the correct author's name to each article
			for i := range articles {
				articles[i].Name = articles[i].User.Name // Ensure name is set from User table
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(articles)
		} else if r.Method == "POST" {
			var article Article
			if err := json.NewDecoder(r.Body).Decode(&article); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}

			// Extract token from request
			tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			tokenString = strings.TrimSpace(tokenString)

			if tokenString == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			fmt.Println("JWT Secret during validation:", string(jwtSecret))

			claims := &Claims{}
			token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return jwtSecret, nil
			})
			if err != nil {
				fmt.Println("JWT parsing error:", err)
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}
			claims, ok := token.Claims.(*Claims)
			if !ok || !token.Valid {
				fmt.Println("Invalid token structure")
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Ensure we retrieve the user from the database
			var user User
			if err := db.First(&user, claims.UserID).Error; err != nil {
				http.Error(w, "User not found", http.StatusBadRequest)
				return
			}

			// Assign the user's ID and name to the article
			article.UserID = user.ID
			article.Name = user.Name // ✅ This ensures 'name' is stored in the database

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"message": "Article created successfully"})
		}
	}).Methods("GET", "POST") // Add support for both GET and POST requests
	r.HandleFunc("/protected", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Protected content"))
	}, "")).Methods("GET")

	// Serve static files from the "static" folder ////////////////////////////////////////////
	r.PathPrefix("/").Handler(http.StripPrefix("/", http.FileServer(http.Dir("./static"))))

	// Fix root redirect (only redirect "/" to /articles.html, but NOT /index.html)///////////////////
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/articles.html", http.StatusFound) // Always go to articles.html
	})

	// Оберните ваш роутер в CORS middleware
	handler := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:8080"}, // Разрешите запросы с этого адреса
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}).Handler(r)

	r.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, err := route.GetPathTemplate()
		if err == nil {
			fmt.Println("Registered route:", path)
		}
		return nil
	})

	// Start the server
	port := 8080
	logger.WithFields(logrus.Fields{
		"port": port,
	}).Info("Starting server")
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), handler))
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

// Function to send an email with an attachment (for receipts)
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

// ////////////////////
func handleArticles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		getArticles(w)
		return
	case http.MethodPost:
		tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		tokenString = strings.TrimSpace(tokenString)

		if tokenString == "" {
			http.Error(w, `{"error": "Missing token"}`, http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, `{"error": "Invalid token"}`, http.StatusUnauthorized)
			return
		}

		if claims.ExpiresAt < time.Now().Unix() {
			http.Error(w, `{"error": "Token expired"}`, http.StatusUnauthorized)
			return
		}

		var article Article
		if err := json.NewDecoder(r.Body).Decode(&article); err != nil {
			http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
			return
		}

		var user User
		if err := db.First(&user, claims.UserID).Error; err != nil {
			http.Error(w, `{"error": "User not found"}`, http.StatusBadRequest)
			return
		}

		article.UserID = user.ID
		article.Name = user.Name

		if err := db.Create(&article).Error; err != nil {
			http.Error(w, `{"error": "Database error"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":    "Article created successfully",
			"article_id": article.ID,
		})
	}
}

func getArticles(w http.ResponseWriter) {
	logger.Info("Fetching all articles")

	var articles []Article
	if err := db.Preload("User").Order("id DESC").Find(&articles).Error; err != nil { // Order by newest first
		logger.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to fetch articles")
		http.Error(w, "Error fetching articles", http.StatusInternalServerError)
		return
	}

	logger.WithFields(logrus.Fields{
		"article_count": len(articles),
	}).Info("Fetched articles successfully")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(articles)
}

func createArticle(w http.ResponseWriter, r *http.Request) {
	// Проверяем, что метод запроса - POST
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Получаем заголовок Authorization
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	tokenString = strings.TrimSpace(tokenString) // Remove any extra spaces

	if tokenString == "" {
		http.Error(w, "Missing authorization token", http.StatusUnauthorized)
		return
	}

	// Убираем "Bearer "
	splitToken := strings.Split(tokenString, " ")
	if len(splitToken) != 2 || splitToken[0] != "Bearer" {
		http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
		return
	}
	tokenString = splitToken[1]
	fmt.Println("Token after trimming 'Bearer':", tokenString)

	// Разбираем токен
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})
	if err != nil {
		fmt.Println("JWT parsing error:", err)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		fmt.Println("Invalid token structure")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	if err != nil {
		fmt.Println("❌ Ошибка парсинга токена:", err)
	} else if !token.Valid {
		fmt.Println("❌ Токен не валидный!")
	}
	http.Error(w, "Invalid token", http.StatusUnauthorized)
	return

	// Декодируем JSON статьи
	var article Article
	if err := json.NewDecoder(r.Body).Decode(&article); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Retrieve user details from database to get the author's name
	var user User
	if err := db.First(&user, claims.UserID).Error; err != nil {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Assign the correct UserID and Author name
	article.UserID = user.ID
	article.Name = user.Name

	// Устанавливаем имя автора
	article.Name = user.Name

	// Сохраняем статью в БД
	if err := db.Create(&article).Error; err != nil {
		http.Error(w, "Error creating article", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Article created successfully"})
}

/////////////////////

// Create a new user
func createUser(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	if r.Method != http.MethodPost {
		logger.WithFields(logrus.Fields{
			"method": r.Method,
			"url":    r.URL.Path,
		}).Warn("Invalid HTTP method for createUser")
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		logger.WithFields(logrus.Fields{
			"error": err.Error(),
			"url":   r.URL.Path,
		}).Error("Failed to decode request body for createUser")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := db.Create(&user).Error; err != nil {
		logger.WithFields(logrus.Fields{
			"error": err.Error(),
			"user":  user,
		}).Error("Failed to create user")
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	logger.WithFields(logrus.Fields{
		"user_id": user.ID,
		"name":    user.Name,
		"email":   user.Email,
	}).Info("User created successfully")

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		logger.WithFields(logrus.Fields{
			"method": r.Method,
			"url":    r.URL.Path,
		}).Warn("Invalid HTTP method for getUsers")

		http.Error(w, `{"error": "Invalid method"}`, http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	email := r.URL.Query().Get("email")
	sortBy := r.URL.Query().Get("sort_by")
	order := r.URL.Query().Get("order")
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")
	var page, limit int
	var err error

	if pageStr == "" {
		page = 1
	} else {
		page, err = strconv.Atoi(pageStr)
		if err != nil || page < 1 {
			logger.WithFields(logrus.Fields{
				"page_str": pageStr,
				"error":    err.Error(),
			}).Warn("Invalid page number provided, defaulting to 1")
			page = 1
		}
	}

	if limitStr == "" {
		limit = 10
	} else {
		limit, err = strconv.Atoi(limitStr)
		if err != nil || limit < 1 {
			logger.WithFields(logrus.Fields{
				"limit_str": limitStr,
				"error":     err.Error(),
			}).Warn("Invalid limit provided, defaulting to 10")
			limit = 10
		}
	}

	offset := (page - 1) * limit

	var users []User
	query := db.Select("id, name, email, role, password_hash")

	if name != "" {
		query = query.Where("name ILIKE ?", "%"+name+"%")
	}
	if email != "" {
		query = query.Where("email ILIKE ?", "%"+email+"%")
	}

	if sortBy != "" {
		if order == "desc" {
			query = query.Order(sortBy + " DESC")
		} else {
			query = query.Order(sortBy + " ASC")
		}
	}

	if err := query.Offset(offset).Limit(limit).Find(&users).Error; err != nil {
		logger.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to fetch users from database")

		http.Error(w, `{"error": "Failed to fetch users"}`, http.StatusInternalServerError)
		return
	}

	for i := range users {
		users[i].PasswordHash = "********"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		logger.WithFields(logrus.Fields{
			"method": r.Method,
			"url":    r.URL.Path,
		}).Warn("Invalid HTTP method for updateUser")
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	var user User
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&user); err != nil {
		logger.WithFields(logrus.Fields{
			"error": err.Error(),
			"url":   r.URL.Path,
		}).Error("Failed to decode request body for updateUser")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Ensure the ID is valid and non-zero
	if user.ID == 0 {
		logger.Warn("Invalid or missing user ID in request body")
		http.Error(w, "User ID is required and must be valid", http.StatusBadRequest)
		return
	}

	// Update the user with the new name, email, and role
	if err := db.Model(&User{}).Where("id = ?", user.ID).Updates(User{Name: user.Name, Email: user.Email, Role: user.Role}).Error; err != nil {
		logger.WithFields(logrus.Fields{
			"user_id": user.ID,
			"error":   err.Error(),
		}).Error("Failed to update user")
		http.Error(w, "Error updating user", http.StatusInternalServerError)
		return
	}

	logger.WithFields(logrus.Fields{
		"user_id": user.ID,
		"name":    user.Name,
		"email":   user.Email,
		"role":    user.Role,
	}).Info("User updated successfully")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "User updated successfully"})
}

// Delete a user by ID
func deleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		logger.WithFields(logrus.Fields{
			"method": r.Method,
			"url":    r.URL.Path,
		}).Warn("Invalid HTTP method for deleteUser")
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	// Extract the user ID from the query parameter
	id := r.URL.Query().Get("id")
	if id == "" {
		logger.Warn("Missing user ID in query parameters for deleteUser")
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	logger.WithFields(logrus.Fields{
		"user_id": id,
	}).Info("Attempting to delete user")

	// Delete the user
	var user User
	if err := db.Where("id = ?", id).Delete(&user).Error; err != nil {
		logger.WithFields(logrus.Fields{
			"user_id": id,
			"error":   err.Error(),
		}).Error("Failed to delete user")
		http.Error(w, "Error deleting user", http.StatusInternalServerError)
		return
	}

	logger.WithFields(logrus.Fields{
		"user_id": id,
	}).Info("User deleted successfully")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "User deleted successfully"})
}

// Search a user by ID
func searchUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		logger.WithFields(logrus.Fields{
			"method": r.Method,
			"url":    r.URL.Path,
		}).Warn("Invalid HTTP method for searchUser")
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		logger.Warn("Missing user ID in query parameters for searchUser")
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	logger.WithFields(logrus.Fields{
		"user_id": id,
	}).Info("Searching for user")

	var user User
	if err := db.Where("id = ?", id).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.WithFields(logrus.Fields{
				"user_id": id,
			}).Warn("User not found")
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			logger.WithFields(logrus.Fields{
				"error":   err.Error(),
				"user_id": id,
			}).Error("Failed to fetch user")
			http.Error(w, "Error fetching user", http.StatusInternalServerError)
		}
		return
	}

	logger.WithFields(logrus.Fields{
		"user_id": user.ID,
		"name":    user.Name,
		"email":   user.Email,
	}).Info("User found successfully")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

// lkjlkjlkjlkjlkjjlkjlkjlkjlkjlkjlkjlkjlkjlkjlkjlkjlkj
// Create a new rate limiter
func newRateLimiter(limit int, interval time.Duration) *rateLimiter {
	return &rateLimiter{
		visitors: make(map[string]*visitor),
		mu:       sync.Mutex{}, // ✅ Ensure Mutex is properly initialized
		limit:    limit,
		interval: interval,
	}
}

// Middleware function to apply rate limiting
func (rl *rateLimiter) limitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		rl.mu.Lock()
		v, exists := rl.visitors[ip]
		if !exists {
			v = &visitor{
				lastSeen: time.Now(),
				requests: 0,
				limiter:  rl,
			}
			rl.visitors[ip] = v

			// Set a timer to remove the visitor after the interval
			v.resetTimer = time.AfterFunc(rl.interval, func() {
				rl.mu.Lock()
				delete(rl.visitors, ip)
				rl.mu.Unlock()
			})
		}
		v.requests++
		rl.mu.Unlock() // ✅ Unlock mutex after modifying shared resource

		// Check if request limit is exceeded
		if v.requests > rl.limit {
			http.Error(w, "Too many requests, please try again later", http.StatusTooManyRequests)
			return
		}

		// Proceed with request
		next.ServeHTTP(w, r)
	})
}

/////////////////////////////////////////

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
