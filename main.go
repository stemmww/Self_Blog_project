package main

// +profile, +manage data, +selenium login
import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
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

// // reg
type ChatMessage struct {
	ID        uint      `gorm:"primaryKey"`
	Username  string    `json:"username"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

func initDatabase() {
	var err error
	dsn := "user=postgres password=assbreaker2023 dbname=bloguser port=5432 sslmode=disable"
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Auto-migrate ChatMessage table
	if err := db.AutoMigrate(&ChatMessage{}); err != nil {
		log.Fatal("Failed to migrate database:", err)
	}
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

func main() {

	initDatabase()

	r := mux.NewRouter()
	// Initialize the rate limiter
	//Initialize the rate limiter
	rl := newRateLimiter(1000, time.Minute) // Allow 1000 requests per minute per IP

	// Configure Logrus
	logger.SetFormatter(&logrus.JSONFormatter{}) // Logs in JSON format
	logger.SetLevel(logrus.InfoLevel)            // Set logging level
	logger.Info("Server is starting...")

	// Database Connection ///////////////////////////////////////////////////////////////////////
	dsn := "user=postgres password=assbreaker2023 dbname=bloguser port=5432 sslmode=disable"
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

	go handleMessages()

	// Serve static HTML for the chat
	http.Handle("/", http.FileServer(http.Dir(".")))
	http.HandleFunc("/ws", chatHandler)

	// Start the server
	port := 8090
	logger.WithFields(logrus.Fields{
		"port": port,
	}).Info("Starting server")
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), handler))
}
