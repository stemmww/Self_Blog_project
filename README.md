# Personal Blog Project

This is a multifunctional personal blog project built on Go (Golang) programming language and PostgreSQL object-relational database management system. This project provides RESTful API for managing users and articles and includes HTML , CSS, JS frontend for user interaction. The project includes roles (admin, user) for distribution of features. Admins have full access to the user database and can also manage, modify the database. User role includes viewing articles of other users, as well as the ability to create your own article. With all the functionality you can read below.

## Features

### Backend Features

  **User Management**:

- Create, Read, Update, and Delete (CRUD) operations with filtering, sorting, and pagination.
- Role-based access control (Admin/User).
- User profile with image upload.

**Authentication and Authorization**:
- Secure user login with JWT tokens.
- Email-based verification using verification codes.

**Article Management**:
- Full CRUD operations for articles.
- Author attribution.

**WebSocket Support Chat**:
- Real-time chat for users and administrators.
- Separate chat windows for users and admins.
- Persistent chat history stored in PostgreSQL.

**Payment Processing**:
- Integrated payment microservice.
- Secure payment with simulated card processing.
- Payment receipts emailed to users.

**Email Services**:
- Email verification upon registration.
- Send emails (plain text and with file attachments) to users.
- Uses SMTP server for secure email delivery.

**Rate Limiting**:
- Limits requests to prevent abuse.

**Logging**:
- Structured logging using Logrus.

### Frontend Features
- **Dynamic User Management**:
  - Create, update, and delete users via a simple HTML/JavaScript interface.
  - Filter and sort users by name, email, or ID.
- **Article Management**:
  - User-friendly interface for creating and viewing articles.
  - Dropdown for selecting authors during article creation.
- **Email Sending Interface**:
  - Form to send emails with attachments to specific recipients.

  **User Management**:
- Register/Login with email verification.
- Profile management with image upload.

  **Admin Panel**:
- Manage users and articles.
- View active support chats and respond.

**Article Management**:
- Create and view articles with author details.

**Support Cha**t:
- Real-time WebSocket chat for users and admins.

**Payment Page**:
- Secure donation form integrated with the payment microservice.

## Prerequisites

- **Go (Golang)** installed (v1.19 or later recommended).
- **PostgreSQL** (configured for bloguser database on port 5433).
- **ChromeDriver** (for Selenium tests).
- **Environment Variables**: 
- SMTP server credentials and JWT secret.

## Setup Instructions

1. **Clone the Repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY_NAME.git
   cd YOUR_REPOSITORY_NAME
   ```

2. **Create .env file**
   ```bash
   JWT_SECRET=your_jwt_secret
  SMTP_SERVER=smtp.mail.ru
  SMTP_PORT=587
  EMAIL_SENDER=your-email@mail.ru
  EMAIL_PASSWORD=your-email-password
   ```

3. **Run Database Migrations**
   Ensure PostgreSQL is running and execute:
   ```bash
   go run .
   ```
   This will automatically migrate the database schema for users and articles.

4. **Start Servers**
   Main Server:
  ```
   - go run .
  ```
  Server available at: http://localhost:8080

  Payment Microservice:
  ```
  go run payment_microservice.go
  ```
  Service available at: http://localhost:8081


## Tesing
  1. **Unit Tests (unit_test.go)**:
  ```
  go test ./...
  ```
  2. **E2E Tests (e2e_test.go)**:
  ```
  go test -v e2e_test.go
  ```

## Code structure
1. backend
- main.go: Core server logic and routes.
- crud.go: CRUD operations.
- additional.go: User profile and Payment functions.
- websocket.go: WebSocket handlers for support chats.
- email.go: Email functionality.
- unit_test.go: Unit tests for core functions.
- e2e_test.go: Selenium-based login tests.
- admin.html, supportChat.html: Admin and support chat interfaces.
2. frontend
- index.html: Admin panel with all functionality.
- createArticle.html: Article creation page.
- articles.html: All list of articles created by users.
- admin.html, supportChat.html: Admin and support chat interfaces.
- payment.html: Payment page with inputs to enter card data.
- profile.html: Profile page of users with information and ability to modify user data.
- verify.html: Email verification in registration process.
- style.css: main styling of website.
- nav.js: navigation menu dynamic buttons.
3. folders
- static: all frontend files.
- receipts: receipts that are sent when user donate.
- uploads: profile pictures.
- payment-microservice: payment microservice essentials.


###  Contribution Guide

1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature
   ```
3. Commit changes:
   ```bash
   git commit -m "Add feature"
   ```
4. Push the branch and open a pull request:
   ```bash
   git push origin feature/your-feature
   ```
5. Open a pull request

## Contact
For any questions or issues, please contact the repository owner at `sayanzhma@gmail.com`.

---

**Happy Blogging!**

