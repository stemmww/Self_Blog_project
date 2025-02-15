package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/tebeka/selenium"
)

const (
	chromeDriverPath = "./chromedriver.exe"                  // Adjust path if necessary
	seleniumPort     = 4444                                  // ChromeDriver WebDriver port
	websiteURL       = "http://localhost:8080/register.html" // Login page URL
	expectedRedirect = "http://localhost:8080/articles.html" // Expected page after login
	testEmail        = "sayanzhma@gmail.com"                 // Test credentials
	testPassword     = "sayanbek"
)

// TestLogin - Automates login test
func TestLogin(t *testing.T) {
	// Start Selenium WebDriver
	service, err := selenium.NewChromeDriverService(chromeDriverPath, seleniumPort)
	if err != nil {
		t.Fatalf("❌ Failed to start ChromeDriver: %v", err)
	}
	defer service.Stop()

	// Connect to WebDriver
	caps := selenium.Capabilities{"browserName": "chrome"}
	driver, err := selenium.NewRemote(caps, fmt.Sprintf("http://localhost:%d/wd/hub", seleniumPort))
	if err != nil {
		t.Fatalf("❌ Failed to connect to Selenium WebDriver: %v", err)
	}
	defer driver.Quit()

	// Open the login page
	err = driver.Get(websiteURL)
	if err != nil {
		t.Fatalf("❌ Failed to open login page: %v", err)
	}

	// Wait for elements to be available
	time.Sleep(2 * time.Second)

	// Locate and fill email field
	emailField, err := driver.FindElement(selenium.ByID, "loginEmail")
	if err != nil {
		t.Fatalf("❌ Email field not found: %v", err)
	}
	emailField.SendKeys(testEmail)

	// Locate and fill password field
	passwordField, err := driver.FindElement(selenium.ByID, "loginPassword")
	if err != nil {
		t.Fatalf("❌ Password field not found: %v", err)
	}
	passwordField.SendKeys(testPassword)

	// Locate and click the login button
	loginButton, err := driver.FindElement(selenium.ByID, "loginButton")
	if err != nil {
		t.Fatalf("❌ Login button not found: %v", err)
	}
	loginButton.Click()

	// Wait for redirection
	time.Sleep(3 * time.Second)

	// Verify if redirected to articles page
	currentURL, err := driver.CurrentURL()
	if err != nil {
		t.Fatalf("❌ Failed to get current URL: %v", err)
	}

	if currentURL == expectedRedirect {
		fmt.Println("✅ Login Test Passed: Successfully redirected to articles page!")
	} else {
		t.Fatalf("❌ Login Test Failed: Redirected to incorrect page: %s", currentURL)
	}
}
