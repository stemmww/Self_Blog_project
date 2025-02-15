package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

// TestGenerateVerificationCode ensures the verification code is of the correct length
func TestGenerateVerificationCode(t *testing.T) {
	code := GenerateVerificationCode()
	assert.Equal(t, 6, len(code), "Code length should be 6")
	assert.Regexp(t, "^[A-Za-z0-9_-]{6}$", code, "Code should be a 6-character alphanumeric string")
}

// TestPasswordHashing ensures password hashing works correctly
func TestHashPassword(t *testing.T) {
	password := "securepassword"
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	assert.Nil(t, err, "Hashing should not produce an error")
	assert.NotEmpty(t, hashed, "Hashed password should not be empty")
}

// TestComparePassword ensures password verification works correctly
func TestComparePassword(t *testing.T) {
	password := "securepassword"
	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Correct password check
	err := bcrypt.CompareHashAndPassword(hashed, []byte(password))
	assert.Nil(t, err, "Correct password should match hash")

	// Incorrect password check
	err = bcrypt.CompareHashAndPassword(hashed, []byte("wrongpassword"))
	assert.NotNil(t, err, "Incorrect password should not match hash")
}

// Hello bro
