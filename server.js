const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Fake database
let users = [];
let logs = [];
let nextId = 1;

// JWT secret
const JWT_SECRET = 'vaultpass_secret_key';

// Middleware to verify token
const verifyToken = (req, res, next) => {
const token = req.headers.authorization?.split(' ')[1];
if (!token) return res.status(401).json({ message: 'No token' });

try {
req.user = jwt.verify(token, JWT_SECRET);
next();
} catch {
res.status(401).json({ message: 'Invalid token' });
}
};

// Check role middleware
const checkRole = (roles) => (req, res, next) => {
if (!roles.includes(req.user.role)) {
return res.status(403).json({ message: 'Forbidden' });
}
next();
};

// PUBLIC route
app.get('/api/public/message', (req, res) => {
res.json({ message: 'This route is public' });
});

// REGISTER
app.post('/api/auth/register', async (req, res) => {
const { fullName, email, password, role } = req.body;

if (!['user', 'moderator', 'admin'].includes(role)) {
return res.status(400).json({ message: 'Invalid role' });
}

const existing = users.find(u => u.email === email);
if (existing) return res.status(409).json({ message: 'Email already exists' });

const hashedPassword = await bcrypt.hash(password, 10);
const user = {
_id: nextId++,
fullName,
email,
password: hashedPassword,
role,
loginAttempts: 0,
lockUntil: null
};

users.push(user);
res.status(201).json({ message: 'User registered', user: { ...user, password: undefined } });
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
const { email, password } = req.body;
const user = users.find(u => u.email === email);

if (!user) return res.status(401).json({ message: 'Invalid credentials' });

if (user.lockUntil && user.lockUntil > Date.now()) {
logs.push({ action: 'failed_login_locked', user: email, timestamp: new Date() });
return res.status(423).json({ message: 'Account locked. Try again later.' });
}

const isMatch = await bcrypt.compare(password, user.password);

if (!isMatch) {
user.loginAttempts++;

if (user.loginAttempts >= 5) {
user.lockUntil = Date.now() + 15 * 60 * 1000;
user.loginAttempts = 0;
logs.push({ action: 'account_locked', user: email, timestamp: new Date() });
return res.status(423).json({ message: 'Account locked for 15 minutes' });
}

logs.push({ action: 'failed_login', user: email, timestamp: new Date() });
return res.status(401).json({ message: 'Invalid credentials' });
}

user.loginAttempts = 0;
user.lockUntil = null;

const token = jwt.sign(
{ userId: user._id, role: user.role },
JWT_SECRET,
{ expiresIn: '1h' }
);

res.json({
message: 'Login successful',
token,
user: { ...user, password: undefined }
});
});

// USER profile (protected)
app.get('/api/user/profile', verifyToken, (req, res) => {
const user = users.find(u => u._id === req.user.userId);
res.json({ user: { ...user, password: undefined } });
});

// MODERATOR reports
app.get('/api/moderator/reports', verifyToken, checkRole(['moderator', 'admin']), (req, res) => {
res.json({ message: 'Moderator reports', reports: [] });
});

// ADMIN delete user
app.delete('/api/admin/user/:id', verifyToken, checkRole(['admin']), (req, res) => {
const adminUser = users.find(u => u._id === req.user.userId);
if (req.params.id == adminUser._id) {
return res.status(403).json({ message: 'Admins cannot delete themselves' });
}

const index = users.findIndex(u => u._id == req.params.id);
if (index === -1) return res.status(404).json({ message: 'User not found' });

const deleted = users.splice(index, 1)[0];
logs.push({ action: 'user_deleted', user: deleted.email, timestamp: new Date() });

res.json({ message: 'User deleted', user: { ...deleted, password: undefined } });
});

// ADMIN promote user
app.post('/api/admin/promote/:id', verifyToken, checkRole(['admin']), (req, res) => {
const target = users.find(u => u._id == req.params.id);
if (!target) return res.status(404).json({ message: 'User not found' });
if (target.role === 'admin') return res.status(403).json({ message: 'Cannot promote admin' });

target.role = 'moderator';
res.json({ message: 'User promoted to moderator', user: { ...target, password: undefined } });
});

// GET logs (admin only)
app.get('/api/admin/logs', verifyToken, checkRole(['admin']), (req, res) => {
res.json({ logs });
});

// Error handler
app.use((err, req, res, next) => {
console.error('ERROR:', err.stack);
res.status(500).json({ message: err.message, stack: err.stack });
});

const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));