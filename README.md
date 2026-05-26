# Securous — JWT Authentication System

A production-grade stateless authentication system built with Spring Boot.

## Tech Stack
- Java 17
- Spring Boot 3
- Spring Security
- MySQL
- Redis
- JWT (JJWT)
- Docker

## Features
- JWT access + refresh token authentication
- Token rotation on every refresh
- HttpOnly cookie for refresh token security
- Refresh token persistence in DB
- Role-based access control (RBAC)
- Redis-based token blacklisting (in progress)
- Session management per device (in progress)
- Production-grade exception handling

## API Endpoints

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/v1/auth/register | Register new user |
| POST | /api/v1/auth/login | Login |
| POST | /api/v1/auth/refresh | Rotate refresh token |
| POST | /api/v1/auth/logout | Logout |

### User
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/users/me | Get current user profile |

## How to Run

### Prerequisites
- Java 17
- MySQL
- Docker (for Redis)

### Steps
1. Clone the repository
2. Configure application.yml with your DB credentials
3. Run Redis via Docker
4. Run the application

### Run Redis
docker run --name redis-securous -p 6379:6379 -d redis:7-alpine

### Environment Variables
- DB_URL
- DB_USERNAME  
- DB_PASSWORD
- JWT_SECRET
- MAX_SESSIONS
- REDIS_HOST
- REDIS_PORT
- REDIS_PASSWORD

## Security Design
- Access token — short lived (1 hour), stateless
- Refresh token — long lived (24 hours), stored in DB
- Refresh token sent via HttpOnly cookie — JS cannot read it
- Token rotation — every refresh issues new token pair
- Immediate revocation via Redis blacklist
