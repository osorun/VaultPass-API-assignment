VaultPass API

Secure API with authentication and role-based access control.

Setup

1. Run npm install
2. Run node server.js

Routes

• GET /api/public/message - Public route
• POST /api/auth/register - Register user
• POST /api/auth/login - Login user
• GET /api/user/profile - User profile (needs token)
• GET /api/moderator/reports - Moderator only
• DELETE /api/admin/user/:id - Admin only
• POST /api/admin/promote/:id - Promote user
• GET /api/admin/logs - View logs

Features

• JWT authentication
• Password hashing with bcrypt
• Role-based access control
• Account locking after 5 failed logins
• Activity logging