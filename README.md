# Secure Login & User Authentication System

A secure Flask application demonstrating best practices for user authentication, session management, and vulnerability defense. This project was built for a university assignment to showcase defenses against common web attacks.

## 🚀 Features

- **Secure Authentication**: User registration and login with strong password hashing (PBKDF2/Scrypt).
- **Multi-Factor Authentication (MFA)**: Time-based One-Time Password (TOTP) integration using Google Authenticator/Authy.
- **Session Security**: Secure cookie configuration (`HttpOnly`, `SameSite=Lax`).
- **Vulnerability Protection**:
  - **SQL Injection (SQLi)**: Prevented via SQLAlchemy ORM.
  - **Cross-Site Scripting (XSS)**: Prevented via Jinja2 auto-escaping.
  - **Cross-Site Request Forgery (CSRF)**: Prevented via Flask-WTF tokens.
  - **Rainbow Table Attacks**: Prevented via salted password hashing.
  - **Insecure Direct Object References (IDOR)**: Prevented by session-based user context.

## 🛠️ Setup & Installation

1.  **Prerequisites**: Python 3.8+
2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
3.  **Initialize Database**:
    The app automatically creates the database (`users.db`) on the first run.
4.  **Run the Application**:
    ```bash
    python app.py
    ```
5.  **Access the App**:
    Open your browser and navigate to `http://127.0.0.1:5000`.

## 🧪 Vulnerability Testing Guide

Use this guide to verify the security measures implemented in the application.

### 1. SQL Injection (SQLi)
**Goal**: Attempt to bypass authentication or extract data using SQL payloads.
- **Test**: Go to the Login page.
- **Payload**: Enter `' OR '1'='1` into the Username or Password field.
- **Expected Result**: Login fails. The application uses SQLAlchemy's ORM (`User.query.filter_by()`), which automatically parameterizes queries, treating the payload as a literal string rather than executable SQL.

### 2. Cross-Site Scripting (XSS)
**Goal**: Inject malicious JavaScript to execute in the victim's browser.
- **Test**: Go to the Registration page.
- **Payload**: Enter `<script>alert('XSS')</script>` as the Username.
- **Expected Result**: After registration (if length allows) or upon display, the script **does not execute**. The username is displayed as plain text (e.g., `&lt;script&gt;...`). This is due to Jinja2's automatic HTML escaping.

### 3. Cross-Site Request Forgery (CSRF)
**Goal**: Force a user to perform an action (like changing a password) without their consent.
- **Test**: Inspect the HTML source of the "Change Password" or "Login" form.
- **Observation**: You will see a hidden input field named `csrf_token`.
    ```html
    <input id="csrf_token" name="csrf_token" type="hidden" value="...">
    ```
- **Verification**: Try to submit a POST request to `/change-password` using a tool like Postman or `curl` *without* including this token.
- **Expected Result**: The server returns a `400 Bad Request` or `403 Forbidden` error (handled by Flask-WTF), blocking the request.

### 4. Weak Password & Rainbow Table Attacks
**Goal**: Register with a weak password or compromise the database to reverse passwords.
- **Test 1 (Complexity)**: Try to register with "password" or "123456".
- **Expected Result**: Registration fails. The app enforces a minimum of 8 characters and at least one special character.
- **Test 2 (Hashing)**: Inspect the `users.db` database (using a tool like *DB Browser for SQLite*).
- **Observation**: The `password_hash` column contains a long, random-looking string (e.g., `scrypt:32768:8:1$...`).
- **Explanation**: Passwords are hashed using `werkzeug.security.generate_password_hash`. Even if the database is stolen, attackers cannot easily reverse these hashes to retrieve original passwords, unlike plain MD5 or SHA1.

### 5. Session Hijacking (Cookie Security)
**Goal**: Steal a session cookie via JavaScript.
- **Test**: Open the browser's Developer Tools (F12) -> Application -> Cookies.
- **Observation**: Look for the `session` cookie.
    - **HttpOnly**: Checked (✅). This means JavaScript (`document.cookie`) cannot access the cookie, preventing XSS-based session theft.
    - **SameSite**: Set to `Lax` (✅). This prevents the cookie from being sent in cross-site POST requests, adding a layer of CSRF protection.

### 6. MFA Bypass
**Goal**: Login without the second factor.
- **Test**: Enter valid credentials on the login page.
- **Action**: When redirected to the MFA page, try to navigate directly to the dashboard (`/`) or force-browse to other protected routes.
- **Expected Result**: You are redirected back to the Login or MFA page. The `current_user` is not fully authenticated until the MFA step is completed.

### 7. Insecure Direct Object References (IDOR)
**Goal**: Access or modify another user's data by changing an ID parameter.
- **Test**: Attempt to find a URL like `/user/1/edit` or `/change-password?user_id=2`.
- **Observation**: The application does not expose user IDs in URLs for sensitive actions.
- **Explanation**: Routes like `/change-password` rely entirely on `current_user` from the secure session. There is no parameter to manipulate, making it impossible to change another user's password.
