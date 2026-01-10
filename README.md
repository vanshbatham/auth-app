# 🔐 Authentication Service

Designed a **production-grade authentication and authorization service** built using **Spring Boot** and **Spring
Security**, designed to provide secure, scalable, and reusable identity management for backend applications.

The project focuses on **security fundamentals**, **token-based authentication**, and **clean authorization design**,
similar to real-world backend systems.

---

## 🚀 Features

### 🔑 Authentication

* Email & password based signup and login
* Secure password hashing
* JWT-based authentication
* Short-lived access tokens
* Long-lived refresh tokens with rotation
* Logout and token invalidation

### 🔗 OAuth2 Login

* Google OAuth2 login
* GitHub OAuth2 login
* Automatic user provisioning for OAuth users
* Provider-based user identification

### 🛡️ Authorization

* Role-Based Access Control (**RBAC**)
* Fine-grained authorization at API level
* Secured endpoints using Spring Security filters

---

## 🧠 Security Highlights

* HTTP-only cookies for refresh tokens
* Secure token lifecycle management
* Centralized exception handling for auth failures
* Protection against unauthorized access
* Clear separation of authentication and authorization logic

---

## 🛠️ Tech Stack

* **Language:** Java
* **Framework:** Spring Boot
* **Security:** Spring Security
* **Authentication:** JWT, OAuth2
* **Persistence:** JPA / Hibernate
* **Database:** MySQL
* **Build Tool:** Maven
* **Documentation:** Swagger / OpenAPI

---

## 🏗️ Architecture Overview

* Layered architecture:

    * Controller layer (Auth APIs)
    * Service layer (authentication & token logic)
    * Repository layer (user & token persistence)
* Stateless authentication using JWT
* Persistent refresh token management
* Clean separation of concerns

---

## 🗄️ Database Design (High-Level)

* Users
* Roles
* User–Role mappings
* Refresh tokens
* OAuth provider details

Designed to support **secure session management** and **future extensibility**.

---

## 📖 API Documentation

* Interactive API documentation using **Swagger UI**
* Clearly defined request/response models
* Standardized error responses for authentication failures

---

## 🧪 Testing & Validation

* Manual API testing using Postman & Swagger
* Validation of token lifecycle scenarios:

    * Login
    * Token refresh
    * Logout
    * OAuth2 authentication

---

## 📌 Key Learnings

* Deep understanding of Spring Security internals
* Implementing secure JWT and refresh token workflows
* Designing OAuth2 login flows
* Handling authorization using RBAC
* Building reusable authentication services

---

## 🔮 Future Enhancements

* Multi-tenant authentication support
* API key based authentication
* Rate limiting for auth endpoints
* Login audit logs and analytics

---

## 👤 Author

**Vansh Batham**
Backend Java Developer
🔗 GitHub: [https://github.com/vanshbatham](https://github.com/vanshbatham)
🔗 LinkedIn: [https://www.linkedin.com/in/vanshbatham](https://www.linkedin.com/in/vanshbatham)

