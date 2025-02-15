# Personal Blog Project

This is a feature-rich personal blog project built with Go (Golang) and PostgreSQL. It provides a RESTful API for managing users and articles and includes a frontend for user interactions.

## Features

### Backend Features
- **User Management**:
  - Create, Read, Update, and Delete (CRUD) operations for users.
  - User search with filtering and sorting.
  - Pagination support for large user datasets.
- **Article Management**:
  - Create, Read, and Fetch articles linked to specific users.
  - Author selection from registered users during article creation.
- **Rate Limiting**:
  - Middleware to limit the number of requests per user to prevent abuse.
- **Email Functionality**:
  - Send emails (plain text and with file attachments) to users.
  - Uses SMTP server for secure email delivery.

### Frontend Features
- **Dynamic User Management**:
  - Create, update, and delete users via a simple HTML/JavaScript interface.
  - Filter and sort users by name, email, or ID.
- **Article Management**:
  - User-friendly interface for creating and viewing articles.
  - Dropdown for selecting authors during article creation.
- **Email Sending Interface**:
  - Form to send emails with attachments to specific recipients.

## Prerequisites

- **Go (Golang)** installed (v1.19 or later recommended).
- **PostgreSQL** installed and running.
- A modern web browser for frontend usage.
- **SMTP Configuration**:
  - Valid credentials for an SMTP server (e.g., mail.ru, Gmail).
  - App password or proper SMTP authentication setup.

## Setup Instructions

1. **Clone the Repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY_NAME.git
   cd YOUR_REPOSITORY_NAME
   ```

2. **Run Database Migrations**
   Ensure PostgreSQL is running and execute:
   ```bash
   go run main.go
   ```
   This will automatically migrate the database schema for users and articles.

3. **Start the Server**
   Run the following command to start the Go server:
   ```bash
   go run main.go
   ```
   The server will be available at `http://localhost:8080`.

4. **Access the Frontend**
   Open a web browser and navigate to:
   - Home: `http://localhost:8080`
   - Articles: `http://localhost:8080/articles.html`
   - Create Article: `http://localhost:8080/createArticle.html`

## How to Use

### Sending Emails
1. Navigate to the "Send Email" section on the home page.
2. Fill in the recipient's email, subject, message, and attach files if needed.
3. Click "Send Email" to deliver the message.

### Managing Users
- **Create User**: Use the form on the homepage to add a new user.
- **Search User**: Enter a user ID to search for a specific user.
- **Update/Delete User**: Use the "Edit" or "Delete" buttons in the user table.

### Managing Articles
- **Create Article**: Navigate to `createArticle.html` to write and submit a new article.
- **View Articles**: Access all articles on `articles.html`.

## Development and Contribution

### Code Structure
- **Backend**:
  - RESTful API implemented in Go.
  - PostgreSQL integration for user and article storage.
  - SMTP email functionality using `gomail`.
- **Frontend**:
  - Simple HTML and JavaScript for user interaction.
  - Fetch API for communicating with the backend.

### Adding New Features
1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature/new-feature
   ```
3. Implement your changes and commit them:
   ```bash
   git commit -m "Add new feature"
   ```
4. Push the branch and open a pull request:
   ```bash
   git push origin feature/new-feature
   ```

## Contact
For any questions or issues, please contact the repository owner at `your-email@mail.ru`.

---

**Happy Blogging!**

