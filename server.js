// Load environment variables
require('dotenv').config();

const express = require('express');
const argon2 = require('argon2');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');

// Configuration - Require JWT_SECRET to be set
if (!process.env.JWT_SECRET) {
    console.error('FATAL ERROR: JWT_SECRET is not defined in environment variables.');
    console.error('Please create a .env file from .env.example and set a secure JWT_SECRET.');
    process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_PATH = process.env.DATABASE_PATH || './users.db';

// Argon2 configuration - more secure than bcrypt
const ARGON2_CONFIG = {
    type: argon2.argon2id,  // Most secure variant
    memoryCost: 65536,      // 64 MB memory
    timeCost: 3,            // 3 iterations
    parallelism: 4,         // 4 parallel threads
    saltLength: 16          // 16 byte salt
};

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '/')));

// Rate limiting for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: 'Too many authentication attempts, please try again later.'
});

// Initialize SQLite database with better-sqlite3
const db = new Database(DATABASE_PATH);
console.log(`Connected to SQLite database at ${DATABASE_PATH}`);

// Enable foreign keys
db.exec('PRAGMA foreign_keys = ON');

// Create users table if it doesn't exist
try {
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            failed_attempts INTEGER DEFAULT 0,
            locked_until DATETIME,
            is_active BOOLEAN DEFAULT 1,
            is_approved BOOLEAN DEFAULT 0,
            approved_at DATETIME,
            approved_by TEXT,
            approval_notes TEXT
        )
    `);
    console.log('Users table ready');
    
    // Add is_approved column if it doesn't exist (for existing databases)
    const columns = db.prepare("PRAGMA table_info(users)").all();
    if (!columns.some(col => col.name === 'is_approved')) {
        console.log('Adding approval columns to existing users table...');
        db.exec('ALTER TABLE users ADD COLUMN is_approved BOOLEAN DEFAULT 0');
        db.exec('ALTER TABLE users ADD COLUMN approved_at DATETIME');
        db.exec('ALTER TABLE users ADD COLUMN approved_by TEXT');
        db.exec('ALTER TABLE users ADD COLUMN approval_notes TEXT');
        console.log('Approval columns added');
    }
} catch (err) {
    console.error('Error creating users table:', err);
    process.exit(1);
}

// Create sessions table for tracking active sessions
try {
    db.exec(`
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);
    console.log('Sessions table ready');
} catch (err) {
    console.error('Error creating sessions table:', err);
    process.exit(1);
}

// Prepare statements for better performance and security
const statements = {
    insertUser: db.prepare(
        'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'
    ),
    findUserByUsername: db.prepare(
        'SELECT * FROM users WHERE username = ? AND is_active = 1'
    ),
    updateFailedAttempts: db.prepare(
        'UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?'
    ),
    resetFailedAttempts: db.prepare(
        'UPDATE users SET failed_attempts = 0, last_login = CURRENT_TIMESTAMP WHERE id = ?'
    ),
    insertSession: db.prepare(
        'INSERT INTO sessions (user_id, token_hash, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)'
    ),
    getUserProfile: db.prepare(
        'SELECT id, username, email, created_at, last_login FROM users WHERE id = ?'
    ),
    unlockAccount: db.prepare(
        'UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = ?'
    )
};

// Password validation function
function validatePassword(password, hideNonEnglishError = true) {
    if (password.length < 20 || password.length > 84) {
        return { valid: false, message: 'Password must be between 20 and 84 characters' };
    }
    
    // Silent check for English characters only - security measure
    const englishOnly = /^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?\s]+$/.test(password);
    if (!englishOnly) {
        // Log potential attack but give generic error
        console.warn(`[SECURITY] Non-English characters detected in password attempt at ${new Date().toISOString()}`);
        if (hideNonEnglishError) {
            // Generic error to confuse attackers
            return { valid: false, message: 'Invalid password format', isSecurityBlock: true };
        }
        return { 
            valid: false, 
            message: 'Password validation failed' 
        };
    }
    
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
    
    if (!hasUpper || !hasLower || !hasNumber || !hasSpecial) {
        return { 
            valid: false, 
            message: 'Password must contain uppercase, lowercase, number, and special character' 
        };
    }
    
    return { valid: true };
}

// Register endpoint
app.post('/api/register', authLimiter, async (req, res) => {
    const { username, email, password } = req.body;
    
    // Validate input
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Validate username format
    if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
        return res.status(400).json({ error: 'Username must be 3-30 characters, alphanumeric and underscore only' });
    }
    
    // Silent security check for non-ASCII characters
    if (!/^[\x00-\x7F]*$/.test(username)) {
        console.warn(`[SECURITY] Non-ASCII username attempt: ${username.length} chars at ${new Date().toISOString()}`);
        // Generic error - don't reveal the real reason
        return res.status(400).json({ error: 'Registration failed. Please try again.' });
    }
    
    // Validate email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }
    
    // Validate password
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
        return res.status(400).json({ error: passwordValidation.message });
    }
    
    try {
        // Hash password with argon2 (more secure than bcrypt)
        const passwordHash = await argon2.hash(password, ARGON2_CONFIG);
        
        // Insert user into database
        try {
            const result = statements.insertUser.run(username, email, passwordHash);
            const userId = result.lastInsertRowid;
            
            // Generate JWT token
            const token = jwt.sign(
                { userId: Number(userId), username },
                JWT_SECRET,
                { expiresIn: '24h' }
            );
            
            // Store session (use simple hash for token storage)
            const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
            const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
            
            try {
                statements.insertSession.run(
                    userId,
                    tokenHash,
                    req.ip,
                    req.get('user-agent'),
                    expiresAt.toISOString()
                );
            } catch (sessionErr) {
                console.error('Session creation error:', sessionErr);
            }
            
            res.status(201).json({ 
                message: 'Registration successful',
                token,
                userId: Number(userId),
                username
            });
        } catch (dbErr) {
            if (dbErr.message.includes('UNIQUE constraint failed')) {
                return res.status(409).json({ error: 'Username or email already exists' });
            }
            console.error('Database error:', dbErr);
            return res.status(500).json({ error: 'Registration failed' });
        }
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login endpoint
app.post('/api/login', authLimiter, async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    
    // Silent security check for non-English characters
    const usernameAscii = /^[\x00-\x7F]*$/.test(username);
    const passwordEnglish = /^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?\s]+$/.test(password);
    
    if (!usernameAscii || !passwordEnglish) {
        // Log as potential attack
        console.warn(`[SECURITY] Non-English login attempt from IP: ${req.ip} at ${new Date().toISOString()}`);
        // Return generic error identical to wrong password
        // This prevents attackers from knowing they've been detected
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    try {
        const user = statements.findUserByUsername.get(username);
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Check if account is approved
        if (!user.is_approved) {
            console.log(`[APPROVAL] Unapproved login attempt for user: ${username}`);
            // Return special status code 403 (Forbidden) for awaiting approval
            return res.status(403).json({ 
                error: 'Awaiting approval',
                awaiting_approval: true 
            });
        }
        
        // Check if account is locked
        if (user.locked_until) {
            const lockTime = new Date(user.locked_until);
            if (lockTime > new Date()) {
                return res.status(423).json({ 
                    error: 'Account temporarily locked. Please try again later.' 
                });
            } else {
                // Unlock account
                statements.unlockAccount.run(user.id);
            }
        }
        
        // Verify password with argon2
        const validPassword = await argon2.verify(user.password_hash, password);
        
        if (!validPassword) {
            // Increment failed attempts
            const failedAttempts = user.failed_attempts + 1;
            let lockedUntil = null;
            
            if (failedAttempts >= 5) {
                // Lock account for 30 minutes
                lockedUntil = new Date(Date.now() + 30 * 60 * 1000).toISOString();
            }
            
            statements.updateFailedAttempts.run(failedAttempts, lockedUntil, user.id);
            
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Reset failed attempts and update last login
        statements.resetFailedAttempts.run(user.id);
        
        // Generate JWT token
        const token = jwt.sign(
            { userId: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        // Store session (use simple hash for token storage)
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        
        statements.insertSession.run(
            user.id,
            tokenHash,
            req.ip,
            req.get('user-agent'),
            expiresAt.toISOString()
        );
        
        res.json({ 
            message: 'Login successful',
            token,
            userId: user.id,
            username: user.username
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Verify token middleware
function verifyToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        req.userId = decoded.userId;
        req.username = decoded.username;
        next();
    });
}

// Protected route example
app.get('/api/profile', verifyToken, (req, res) => {
    try {
        const user = statements.getUserProfile.get(req.userId);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json(user);
    } catch (err) {
        console.error('Profile fetch error:', err);
        return res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// Logout endpoint
app.post('/api/logout', verifyToken, (req, res) => {
    // In a production environment, you would invalidate the token here
    res.json({ message: 'Logout successful' });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, '127.0.0.1', () => {
    console.log(`Server running on http://127.0.0.1:${PORT}`);
    console.log(`API endpoints available at http://127.0.0.1:${PORT}/api/`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down server...');
    try {
        db.close();
        console.log('Database connection closed.');
    } catch (err) {
        console.error('Error closing database:', err);
    }
    process.exit(0);
});
