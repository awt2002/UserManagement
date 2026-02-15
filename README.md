# UserManagement API

A RESTful User Management API built with **ASP.NET Core 9** and **ASP.NET Core Identity**. It provides JWT-based authentication with refresh tokens, role-based authorization, email confirmation, password reset, and a full admin panel API.

--- 
 
## Features

- **JWT Authentication** – Access token + refresh token flow with configurable expiry
- **Role-Based Authorization** – `Admin` and `User` roles with policy-based access control
- **Email Confirmation** – SMTP-based email verification on registration
- **Password Reset** – Forgot-password flow with email link and a server-rendered HTML reset form
- **Admin Panel** – List/search users, assign/remove roles, lock/unlock accounts, trigger password resets, delete users
- **Swagger / OpenAPI** – Interactive API documentation with Bearer token support
- **Auto-Seeding** – Roles (`Admin`, `User`) and a default admin account are created on first run

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | ASP.NET Core 9 (.NET 9) |
| Authentication | ASP.NET Core Identity + JWT Bearer |
| Database | SQL Server + Entity Framework Core 9 |
| Email | SMTP (System.Net.Mail) |
| API Docs | Swagger / OpenAPI (Swashbuckle) |

---

## Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- [SQL Server](https://www.microsoft.com/en-us/sql-server/) (LocalDB, Express, or full instance)

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/awt2002/UserManagement.git
cd UserManagement
```

### 2. Configure `appsettings.json`

Open `UserManagement/appsettings.json` and update the sections below.

#### Connection String

Point to your SQL Server instance:

```json
"ConnectionStrings": {
  "DefaultConnection": "Server=YOUR_SERVER;Database=UserManagementDB;Trusted_Connection=True;TrustServerCertificate=True"
}
```

#### Email (SMTP)

```json
"Email": {
  "SmtpHost": "smtp.gmail.com",
  "SmtpPort": 587,
  "SmtpUser": "youremail@gmail.com",
  "SmtpPass": "your-app-password", // https://myaccount.google.com/apppasswords
  "FromEmail": "youremail@gmail.com",
  "FromName": "UserManagement"
}
```



#### Default Admin Account

Seeded automatically on first run:

```json
"AdminSettings": {
  "Email": "admin@admin.com",
  "Password": "Admin@1234",
  "Name": "Administrator"
}
```

### 3. Apply database migrations

```bash
cd UserManagement
dotnet ef database update
```



### 4. Run the application

```bash
dotnet run
```

The API will start at **https://localhost:7122** by default.

### 5. Explore with Swagger

Open [https://localhost:7122/swagger](https://localhost:7122/swagger/index.html) to view and test all endpoints.

Use the **Authorize** button in Swagger to enter your JWT token as `Bearer <token>`.

---

## API Endpoints

### Authentication — `POST /api/UserManagement/...`

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/register` | Register a new user account |
| `POST` | `/login` | Login and receive JWT + refresh token |
| `POST` | `/logout` | Revoke refresh token and sign out |
| `POST` | `/refresh-token` | Exchange refresh token for a new JWT |
| `GET` | `/confirm-email` | Confirm email via link (returns HTML) |
| `POST` | `/resend-confirmation` | Resend the email confirmation link |
| `POST` | `/forgot-password` | Send a password reset email |
| `GET` | `/reset-password` | Password reset form (returns HTML) |
| `POST` | `/reset-password` | Submit new password with reset token |


### Admin — `/api/Admin/...` (requires `Admin` role)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/users?search=term` | List/search all users |
| `DELETE` | `/users/{id}` | Delete a user |
| `POST` | `/assign-role` | Assign a role to a user |
| `POST` | `/remove-role` | Remove a role from a user |
| `GET` | `/roles` | List all available roles |
| `POST` | `/users/{id}/lock` | Lock a user account |
| `POST` | `/users/{id}/unlock` | Unlock a user account |
| `POST` | `/send-reset-password/{id}` | Send password reset email to a user |

---

## API Response Format

All endpoints return a consistent JSON envelope:

```json
{
  "success": true,
  "message": "Descriptive message",
  "data": { ... },
  "errors": ["error1", "error2"]
}
```

---

## Request Body Examples

### Register

```json
POST /api/UserManagement/register

{
  "name": "Your Name",
  "email": "youremail@example.com",
  "password": "Strong@123",
  "confirmPassword": "Strong@123"
}
```

### Login

```json
POST /api/UserManagement/login

{
  "email": "youremail@example.com",
  "password": "Strong@123"
}
```

**Response:**

```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "refreshToken": "base64string...",
    "expiration": "2025-01-01T12:30:00Z",
    "roles": ["User"]
  }
}
```

### Change Password

```json
POST /api/UserManagement/change-password
Authorization: Bearer <token>

{
  "currentPassword": "Strong@123",
  "newPassword": "NewStrong@456",
  "confirmNewPassword": "NewStrong@456"
}
```

### Assign Role (Admin)

```json
POST /api/Admin/assign-role
Authorization: Bearer <admin-token>

{
  "userId": "user-guid-here",
  "role": "Admin"
}
```

---

## Password Requirements

| Rule | Value |
|---|---|
| Minimum length | 8 characters |
| Uppercase letter | Required |
| Lowercase letter | Required |
| Digit | Required |
| Special character | Required |


---

## Project Structure

```
UserManagement/
├── Controllers/
│   ├── AdminController.cs            # Admin-only user management endpoints
│   └── UserManagementController.cs   # Auth, profile & password endpoints
├── Data/
│   ├── ApplicationDbContext.cs        # EF Core DbContext (Identity)
│   ├── ApplicationUser.cs            # Custom Identity user (Name, RefreshToken)
│   └── DbSeeder.cs                   # Seeds roles & default admin on startup
├── DTOs/
│   ├── Admin/
│   │   ├── AssignRoleRequest.cs
│   │   ├── RemoveRoleRequest.cs
│   │   └── UserListItemDto.cs
│   ├── Auth/
│   │   ├── ChangePasswordRequest.cs
│   │   ├── ForgotPasswordRequest.cs
│   │   ├── LoginRequestDto.cs
│   │   ├── RefreshTokenRequest.cs
│   │   ├── RegisterRequestDto.cs
│   │   ├── ResendConfirmationRequest.cs
│   │   └── ResetPasswordRequest.cs
│   ├── Common/
│   │   └── ApiResponse.cs            # Generic API response wrapper
│   └── Profile/
│       └── UpdateProfileRequest.cs
├── OpenApi/
│   └── BearerSecuritySchemeTransformer.cs
├── Services/
│   ├── IEmailService.cs              # Email service interface
│   └── SmtpEmailService.cs           # SMTP implementation
├── Properties/
│   └── launchSettings.json
├── Program.cs                         # App startup, DI & middleware config
├── appsettings.json                   # Configuration
└── UserManagement.csproj              # Project file (.NET 9)
```

---

## License

This project is open source.
