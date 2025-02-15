package main

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

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
