# 🔐 Authentication & Authorization API

A **production-ready authentication and authorization REST API** built using **Node.js, Express, and MongoDB**.  
This project follows clean architecture principles and implements secure, scalable, and modern authentication flows used in real-world applications.

---

## 🚀 Features

- User Registration with Email Verification  
- Secure Login with JWT (Access & Refresh Tokens)  
- Token Refresh Mechanism  
- Protected Routes with JWT Middleware  
- Forgot & Reset Password Flow  
- Change Current Password (Authenticated Users)  
- Get Current Logged-in User  
- Secure Logout  
- Request Validation using `express-validator`  
- Centralized Error Handling  
- HTTP-only Secure Cookies  
- Clean MVC Folder Structure  

---

## 🛠️ Tech Stack

- **Backend:** Node.js, Express.js  
- **Database:** MongoDB, Mongoose  
- **Authentication:** JWT (Access & Refresh Tokens)  
- **Security:** bcrypt, crypto  
- **Validation:** express-validator  
- **Email Service: Mailgen  
- **Environment Management:** dotenv  

---

## 📁 Project Structure

src/
├── controllers/
│ └── auth_controller.js
├── middlewares/
│ ├── auth_middlewares.js
│ └── validator_middlewares.js
├── models/
│ └── user_model.js
├── routes/
│ └── auth_routes.js
├── utils/
│ ├── api-error.js
│ ├── api-response.js
│ ├── async-handler.js
│ └── mail.js
├── validators/
│ └── index.js
├── app.js
└── server.js


---

## 🔐 Authentication Flow

Register → Email Verification → Login
→ Access Token + Refresh Token
→ Protected Routes
→ Refresh Token → New Access Token



---

## 📌 API Endpoints

### Authentication

| Method | Endpoint | Description | Protected |
|------|---------|-------------|-----------|
| POST | `/api/auth/register` | Register new user | ❌ |
| POST | `/api/auth/login` | Login user | ❌ |
| GET | `/api/auth/email-verify/:token` | Verify email | ❌ |
| POST | `/api/auth/refreshAccessToken` | Refresh access token | ❌ |
| GET | `/api/auth/logout` | Logout user | ✅ |
| GET | `/api/auth/current-user` | Get current user | ✅ |

---

### Password Management

| Method | Endpoint | Description | Protected |
|------|---------|-------------|-----------|
| POST | `/api/auth/forgotPassword` | Send password reset email | ❌ |
| POST | `/api/auth/resetForgotPassword/:token` | Reset password | ❌ |
| POST | `/api/auth/changeCurrentPassword` | Change current password | ✅ |

---

## 🛡️ Security Highlights

- Passwords are hashed using **bcrypt**
- JWT tokens are stored in **HTTP-only cookies**
- Refresh tokens are securely stored in the database
- Token expiration and validation handled centrally
- Request validation on all endpoints

---

## ⚙️ Environment Variables

Create a `.env` file in the root directory:

```env
PORT=3000
MONGO_URI=mongodb://localhost:27017/your-database-name

ACCESS_TOKEN_SECRET=your_access_token_secret
REFRESH_TOKEN_SECRET=your_refresh_token_secret

ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d

EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_email_password

CLIENT_URL=http://localhost:5173


👨‍💻 Author

Chetan Badgujar
Backend Developer

