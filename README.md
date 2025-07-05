# Standard Cuts API - Backend System

Welcome to the backend authentication system. This project demonstrates a production-ready Node.js backend using Express, designed with resilience, security, and scalability in mind.

---

## 🚀 Table of Contents

- [Overview](#overview)
- [Tech Stack](##tech-stack)
- [Project Structure](#project-structure)
- [Setup & Installation](#setup--installation)
- [Core Features](#core-features)
- [6-Stage Engineering Markers](#6-stage-engineering-markers)
- [Environment Variables](#environment-variables)
- [API Routes](#api-routes)
- [Testing](#testing)
- [Deployment Notes](#deployment-notes)

---

## 📘 Overview

The system provides authentication, user management, and secure data access . Built using modular, layered architecture (controller-service-utils-model), it can be extended to microservices or upgraded to use real databases like MongoDB or PostgreSQL.

---

## 🛠️ Tech Stack

- **Node.js** + **Express.js**
- **JWT Authentication**
- **Rate Limiting** (`express-rate-limit`)
- **Emailing** via `nodemailer`
- **Custom JSON Mock DB** (file-based with future DB-readiness in mind)
- **Postman** for manual testing
- **Nodemon** for dev mode

---

## 📁 Project Structure

```
root/
├── Routes/                  # Express route handlers
├── Controllers/             # Logic to extract data from req/res
├── Services/                # Core business logic and feature ops
├── Utils/                   # Reusable helpers (mailer, jwt, etc)
├── Middlewares/            # Global and route-specific middlewares
├── Database/               # JSON-based mock data
├── server.js               # App entry point
├── app.js                  # Express app config
├── nodemon.json            # Config for ignoring JSON db
└── .env                    # Environment variables
```

---

## 🔧 Setup & Installation

```bash
git clone https://github.com/mpho-shabalala/standalone-jwt-authentication.git
cd standalone-jwt-authentication
npm install
```

Set up your `.env` file with:
```env
PORT=5000
ACCESS_TOKEN_SECRET=your_access_secret
REFRESH_TOKEN_SECRET=your_refresh_secret
EMAIL_USERNAME=your_email@gmail.com
EMAIL_PASSWORD=your_email_password
PAGE_RECOVER_URL=http://127.0.0.1:5500/FrontEnd/html
```

Run the server:
```bash
npm run dev
```

---

## 🌟 Core Features

- ✅ Secure login, signup, and logout
- ✅ Role-based access (admin, user, guest)
- ✅ Email verification + password reset
- ✅ Token expiration & refresh logic
- ✅ Blacklist & revoke JWTs
- ✅ Rate limiter with IP+user+role keys
- ✅ Middleware abstraction
- ✅ Centralized global error handler

---

## 🔐 6-Stage Engineering Markers

### 1. **Structured API Responses**
- Unified format for all endpoints: `{ httpCode, status, message, statusCode, data }`

### 2. **Resilience**
- Graceful error handling which catches input errors from the client and database errors
- Global error middleware
- Catching unknown routes

### 3. **Secure Access Architecture**
- Access & Refresh token system
- JWT verification middleware
- Token blacklisting/revocation
- Logout flow clears access

### 4. **Rate Limiting**
- Role-based limits: guest, user, admin
- IP + userID + role combination as key
- Graceful 429 responses

### 5. **Environment-based Configuration**
- All secrets, keys, paths stored in `.env`
- No sensitive logic hardcoded

### 6. **Separation of Concerns**
- Controllers: Extract from req/res
- Services: Process logic, return data and throw error into global error handler
- Utils: Encapsulate low-level helpers
- Reusable Middlewares

**(Bonus)**: Interfaces for easy DB migration from file to real DB (Mongo, SQL)

---

## 🌍 Environment Variables

Make sure to provide all required `.env` keys. Missing ones will cause app startup to fail or silently break logic.

---

## 🔌 API Routes

| Endpoint | Method | Auth | Description |
|---------|--------|------|-------------|
| `/api/v1/authentication/login` | POST | ❌ | Log in with email & password |
| `/api/v1/authentication/users` | POST | ❌ | Register a new user |
| `/api/v1/authentication/verify_user` | POST | ❌ | Email verification via token |
| `/api/v1/authentication/recover_account` | POST | ❌ | Request password reset email |
| `/api/v1/authentication/renew_password` | POST | ✅ | Reset password with token |
| `/api/v1/authentication/refresh-token` | GET | ✅ | Get new access token via refresh |
| `/api/v1/authentication/logout` | POST | ✅ | Logout and blacklist token |

All secured endpoints are protected by:
- `authenticateToken` middleware
- `checkBlacklist` middleware

---

## 🧪 Testing (Coming Soon)

Planned testing stack:
- `jest` for unit tests
- `supertest` for API route testing
- Mocks for service and utils

Testing will follow the 6-stage markers with clear coverage:
- Token creation
- Expiry
- Failure states
- Email flows
- Rate limiting

---

## 🚀 Deployment Notes

- Filesystem should be replaced with a real DB for scaling
- Use Redis for rate limiting and token blacklists
- Use a background job queue for email delivery (e.g., Bull + Redis)
- Apply HTTPS, helmet headers, and input sanitization

---

## 👷 Author

**Mpho Shabalala** — Building foundational tools for secure and intuitive web service systems.

GitHub: [@mpho-shabalala](https://github.com/mpho-shabalala)

---

## 📌 License

MIT License. Built for learning, adaptation, and real-world application.

---
