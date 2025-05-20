# 🔐 breizhcamp-2025-demo-jwt-spring

A minimal Spring Boot demo project to illustrate how JWT tokens can (and should) be used to secure an API — and what goes wrong when they're not properly validated.

---

## 🎯 Goal

This demo shows:

- How to generate a JWT token (`/token`)
- How to protect an API endpoint (`/saloon`) using that token
- How **DPoP** (Demonstration of Proof-of-Possession) can secure against token replay
- What happens when:
    - The token has **no expiration**
    - The token is **stolen and reused**
    - The **signature isn't checked**
    - The **DPoP proof is missing or invalid**

---

## ▶️ Features

| Endpoint               | Description                             |
|------------------------|-----------------------------------------|
| `/token`               | Generates a JWT (customizable behavior) |
| `/saloon`              | Protected endpoint secured by JWT       |
| `/proof-of-possession` | Generates a valid DPoP proof JWT        |

---

## ⚠️ Security Issues Demonstrated

1. **Unsigned token accepted** → anyone can forge it.
2. **No expiration (`exp`)** → token is valid forever if leaked.
3. **Signature not verified** → token reuse is undetected.
4. **DPoP disabled** → bearer token is replayable.
5. **DPoP enabled** → missing or invalid proof leads to 401.

This is a great live demo to show how *not* to implement JWT validation 😅

---

## 🔐 DPoP (Proof-of-Possession)

- Implemented as a custom Spring filter
- Can be toggled globally via a property or bean
- Verifies the DPoP JWT:
  - Signature (public key from JWK)
  - HTTP method and URI match
  - Token not reused (optional replay protection)
  - JWT expiration and `jti` uniqueness

---

## 🚀 Getting Started

### Run the app

```bash
./mvnw spring-boot:run
```

---

## 🛠 What you'll learn
- Why expiration (exp) is critical
- Why verifying the JWT signature matters
- How DPoP prevents token replay and adds an extra layer of protection
- How easily a bad JWT implementation can be abused 😬

---
