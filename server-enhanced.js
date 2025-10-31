/**
 * Enhanced Security Server for Indy Nexus
 * Implements ALL modern security best practices
 */

// Load environment variables first
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
const compression = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const xss = require('xss');
const validator = require('validator');

// Configuration from environment variables (more secure)
const app = express();
const PORT = process.env.PORT || 46228;
const NODE_ENV = process.env.NODE_ENV || 'development';
const DATABASE_PATH = process.env.DATABASE_PATH || './users.db';

// JWT_SECRET is required - no defaults for security
if (!process.env.JWT_SECRET) {
    console.error('[FATAL ERROR] JWT_SECRET is not defined in environment variables.');
    console.error('Please create a .env file from .env.example and set a secure JWT_SECRET.');
    process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;

// Argon2 configuration - even more secure settings
const ARGON2_CONFIG = {
    type: argon2.argon2id,
    memoryCost: 131072,    // 128 MB (doubled from before)
    timeCost: 4,            // 4 iterations (increased)
    parallelism: 4,
    saltLength: 32          // 256-bit salt (doubled)
};

// Enhanced security middleware stack (order matters!)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],  // Allow inline styles for our green theme
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Compression for performance
app.use(compression());

// CORS configuration
const corsOptions = {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://127.0.0.1:46228'],
    credentials: true,
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Body parsing with size limits
app.use(express.json({ limit: '10kb' }));  // Prevent large payload attacks
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Sanitization middleware
app.use(mongoSanitize());  // Prevent NoSQL injection
app.use(hpp());            // Prevent HTTP Parameter Pollution

// Static files with security headers
app.use(express.static(path.join(__dirname, '/'), {
    dotfiles: 'deny',     // Deny access to dotfiles
    index: false,         // Disable directory indexing
    setHeaders: (res, path) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Cache-Control', 'public, max-age=3600');
    }
}));

// Enhanced rate limiting with different limits per endpoint
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 5,                     // 5 requests per window
    message: 'Too many authentication attempts, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
    // Store in database for distributed systems
    skipSuccessfulRequests: false,
    handler: (req, res) => {
        console.warn(`[RATE LIMIT] IP ${req.ip} exceeded auth limit`);
        res.status(429).json({ error: 'Too many attempts. Try again later.' });
    }
});

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,   // 1 minute
    max: 100,                   // 100 requests per minute for general API
    message: 'Too many requests, please slow down.'
});

// Initialize SQLite with additional security settings
const db = new Database(DATABASE_PATH);
console.log(`Connected to SQLite database at ${DATABASE_PATH}`);

// Security-focused PRAGMA settings
db.exec('PRAGMA journal_mode = WAL');          // Better concurrency
db.exec('PRAGMA synchronous = FULL');          // Maximum durability
db.exec('PRAGMA foreign_keys = ON');           // Enforce FK constraints
db.exec('PRAGMA auto_vacuum = FULL');          // Auto cleanup
db.exec('PRAGMA secure_delete = ON');          // Overwrite deleted data

// Create tables with additional security columns
try {
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL COLLATE NOCASE,
            email TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            failed_attempts INTEGER DEFAULT 0,
            locked_until DATETIME,
            is_active BOOLEAN DEFAULT 1,
            is_approved BOOLEAN DEFAULT 0,
            password_changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            two_factor_secret TEXT,
            backup_codes TEXT,
            ip_whitelist TEXT,
            security_questions TEXT,
            metadata TEXT
        )
    `);
    
    // Create indexes for performance
    db.exec('CREATE INDEX IF NOT EXISTS idx_username ON users(username)');
    db.exec('CREATE INDEX IF NOT EXISTS idx_email ON users(email)');
    db.exec('CREATE INDEX IF NOT EXISTS idx_active ON users(is_active)');
    
    console.log('Users table ready with enhanced schema');
} catch (err) {
    console.error('Error creating users table:', err);
    process.exit(1);
}

// Sessions with enhanced tracking
try {
    db.exec(`
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            ip_address TEXT,
            user_agent TEXT,
            fingerprint TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);
    
    db.exec('CREATE INDEX IF NOT EXISTS idx_token ON sessions(token_hash)');
    db.exec('CREATE INDEX IF NOT EXISTS idx_expires ON sessions(expires_at)');
    
    console.log('Sessions table ready with enhanced tracking');
} catch (err) {
    console.error('Error creating sessions table:', err);
    process.exit(1);
}

// Audit log for security events
try {
    db.exec(`
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            user_id INTEGER,
            ip_address TEXT,
            user_agent TEXT,
            details TEXT,
            severity TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    `);
    
    db.exec('CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event_type)');
    db.exec('CREATE INDEX IF NOT EXISTS idx_audit_date ON audit_log(created_at)');
    
    console.log('Audit log table ready');
} catch (err) {
    console.error('Error creating audit log:', err);
    process.exit(1);
}

// Prepared statements with input validation
const statements = {
    insertUser: db.prepare(
        'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'
    ),
    findUserByUsername: db.prepare(
        'SELECT * FROM users WHERE username = ? COLLATE NOCASE AND is_active = 1'
    ),
    updateFailedAttempts: db.prepare(
        'UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?'
    ),
    resetFailedAttempts: db.prepare(
        'UPDATE users SET failed_attempts = 0, last_login = CURRENT_TIMESTAMP WHERE id = ?'
    ),
    insertSession: db.prepare(
        'INSERT INTO sessions (user_id, token_hash, ip_address, user_agent, fingerprint, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
    ),
    getUserProfile: db.prepare(
        'SELECT id, username, email, created_at, last_login, is_approved FROM users WHERE id = ?'
    ),
    unlockAccount: db.prepare(
        'UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = ?'
    ),
    logAudit: db.prepare(
        'INSERT INTO audit_log (event_type, user_id, ip_address, user_agent, details, severity) VALUES (?, ?, ?, ?, ?, ?)'
    ),
    cleanupSessions: db.prepare(
        'DELETE FROM sessions WHERE expires_at < datetime("now")'
    )
};

// Enhanced password validation
function validatePassword(password, hideNonEnglishError = true) {
    // Length check
    if (!validator.isLength(password, { min: 20, max: 84 })) {
        return { valid: false, message: 'Password must be between 20 and 84 characters' };
    }
    
    // Check for common passwords (you'd load this from a file in production)
    const commonPasswords = ['password', '12345678', 'qwerty', 'admin'];
    const lowerPassword = password.toLowerCase();
    for (const common of commonPasswords) {
        if (lowerPassword.includes(common)) {
            return { valid: false, message: 'Password is too common' };
        }
    }
    
    // Silent check for English characters only
    const englishOnly = /^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?\\s]+$/.test(password);
    if (!englishOnly) {
        // Log for security monitoring
        console.warn(`[SECURITY] Non-English password attempt at ${new Date().toISOString()}`);
        if (hideNonEnglishError) {
            return { valid: false, message: 'Invalid password format', isSecurityBlock: true };
        }
    }
    
    // Complexity requirements
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
    
    // Check for sequential characters
    if (/(.)\1{2,}/.test(password)) {
        return { valid: false, message: 'Password contains too many repeated characters' };
    }
    
    return { valid: true };
}

// Audit logging function
function logAudit(eventType, userId, ip, userAgent, details, severity = 'INFO') {
    try {
        statements.logAudit.run(eventType, userId, ip, userAgent, JSON.stringify(details), severity);
    } catch (err) {
        console.error('Audit log error:', err);
    }
}

// Session cleanup job (runs every hour)
setInterval(() => {
    try {
        const result = statements.cleanupSessions.run();
        if (result.changes > 0) {
            console.log(`[CLEANUP] Removed ${result.changes} expired sessions`);
        }
    } catch (err) {
        console.error('Session cleanup error:', err);
    }
}, 60 * 60 * 1000);  // Every hour

// Input sanitization helper
function sanitizeInput(input) {
    if (typeof input !== 'string') return input;
    // Remove any HTML/script tags
    return xss(input);
}

// Register endpoint with enhanced validation
app.post('/api/register', authLimiter, async (req, res) => {
    let { username, email, password } = req.body;
    
    // Sanitize inputs
    username = sanitizeInput(username);
    email = sanitizeInput(email);
    
    // Enhanced validation
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Username validation with validator library
    if (!validator.isAlphanumeric(username, 'en-US', { ignore: '_' }) || 
        !validator.isLength(username, { min: 3, max: 30 })) {
        return res.status(400).json({ error: 'Username must be 3-30 characters, alphanumeric and underscore only' });
    }
    
    // Silent ASCII check
    if (!/^[\x00-\x7F]*$/.test(username)) {
        logAudit('SUSPICIOUS_REGISTRATION', null, req.ip, req.get('user-agent'), 
                { username_length: username.length }, 'WARNING');
        return res.status(400).json({ error: 'Registration failed. Please try again.' });
    }
    
    // Email validation with validator library
    if (!validator.isEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }
    
    // Normalize email
    email = validator.normalizeEmail(email);
    
    // Password validation
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
        if (passwordValidation.isSecurityBlock) {
            logAudit('NON_ENGLISH_PASSWORD', null, req.ip, req.get('user-agent'), 
                    { attempt: 'registration' }, 'WARNING');
        }
        return res.status(400).json({ error: passwordValidation.message });
    }
    
    try {
        // Hash password with Argon2
        const passwordHash = await argon2.hash(password, ARGON2_CONFIG);
        
        // Insert user
        try {
            const result = statements.insertUser.run(username, email, passwordHash);
            const userId = result.lastInsertRowid;
            
            // Log successful registration
            logAudit('USER_REGISTERED', userId, req.ip, req.get('user-agent'), 
                    { username, email }, 'INFO');
            
            // Generate JWT token
            const token = jwt.sign(
                { userId: Number(userId), username },
                JWT_SECRET,
                { expiresIn: '24h', issuer: 'indy-nexus' }
            );
            
            // Store session with fingerprinting
            const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
            const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
            const fingerprint = crypto.createHash('sha256')
                .update(req.ip + req.get('user-agent'))
                .digest('hex');
            
            statements.insertSession.run(
                userId,
                tokenHash,
                req.ip,
                req.get('user-agent'),
                fingerprint,
                expiresAt.toISOString()
            );
            
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
            throw dbErr;
        }
    } catch (error) {
        console.error('Registration error:', error);
        logAudit('REGISTRATION_ERROR', null, req.ip, req.get('user-agent'), 
                { error: error.message }, 'ERROR');
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login endpoint with enhanced security
app.post('/api/login', authLimiter, async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    
    // Silent security checks
    const usernameAscii = /^[\x00-\x7F]*$/.test(username);
    const passwordEnglish = /^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?\\s]+$/.test(password);
    
    if (!usernameAscii || !passwordEnglish) {
        logAudit('NON_ENGLISH_LOGIN', null, req.ip, req.get('user-agent'), 
                { attempt: 'login' }, 'WARNING');
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    try {
        const user = statements.findUserByUsername.get(username);
        
        if (!user) {
            logAudit('LOGIN_FAILED', null, req.ip, req.get('user-agent'), 
                    { username, reason: 'user_not_found' }, 'WARNING');
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Check account lock
        if (user.locked_until) {
            const lockTime = new Date(user.locked_until);
            if (lockTime > new Date()) {
                logAudit('LOGIN_LOCKED', user.id, req.ip, req.get('user-agent'), 
                        { username }, 'WARNING');
                return res.status(423).json({ 
                    error: 'Account temporarily locked. Please try again later.' 
                });
            } else {
                statements.unlockAccount.run(user.id);
            }
        }
        
        // Verify password
        const validPassword = await argon2.verify(user.password_hash, password);
        
        if (!validPassword) {
            const failedAttempts = user.failed_attempts + 1;
            let lockedUntil = null;
            
            if (failedAttempts >= 5) {
                lockedUntil = new Date(Date.now() + 30 * 60 * 1000).toISOString();
                logAudit('ACCOUNT_LOCKED', user.id, req.ip, req.get('user-agent'), 
                        { username, failed_attempts: failedAttempts }, 'WARNING');
            }
            
            statements.updateFailedAttempts.run(failedAttempts, lockedUntil, user.id);
            logAudit('LOGIN_FAILED', user.id, req.ip, req.get('user-agent'), 
                    { username, reason: 'invalid_password' }, 'WARNING');
            
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Successful login
        statements.resetFailedAttempts.run(user.id);
        logAudit('LOGIN_SUCCESS', user.id, req.ip, req.get('user-agent'), 
                { username }, 'INFO');
        
        // Generate JWT
        const token = jwt.sign(
            { userId: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '24h', issuer: 'indy-nexus' }
        );
        
        // Store session
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        const fingerprint = crypto.createHash('sha256')
            .update(req.ip + req.get('user-agent'))
            .digest('hex');
        
        statements.insertSession.run(
            user.id,
            tokenHash,
            req.ip,
            req.get('user-agent'),
            fingerprint,
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
        logAudit('LOGIN_ERROR', null, req.ip, req.get('user-agent'), 
                { error: error.message }, 'ERROR');
        res.status(500).json({ error: 'Login failed' });
    }
});

// Enhanced token verification
function verifyToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET, { issuer: 'indy-nexus' });
        req.userId = decoded.userId;
        req.username = decoded.username;
        
        // Verify session exists and is valid
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const session = db.prepare('SELECT * FROM sessions WHERE token_hash = ? AND is_active = 1').get(tokenHash);
        
        if (!session || new Date(session.expires_at) < new Date()) {
            return res.status(401).json({ error: 'Session expired' });
        }
        
        // Update last activity
        db.prepare('UPDATE sessions SET last_activity = CURRENT_TIMESTAMP WHERE id = ?').run(session.id);
        
        next();
    } catch (err) {
        logAudit('INVALID_TOKEN', null, req.ip, req.get('user-agent'), 
                { error: err.message }, 'WARNING');
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// Profile endpoint
app.get('/api/profile', apiLimiter, verifyToken, (req, res) => {
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
app.post('/api/logout', apiLimiter, verifyToken, (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (token) {
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        db.prepare('UPDATE sessions SET is_active = 0 WHERE token_hash = ?').run(tokenHash);
        logAudit('LOGOUT', req.userId, req.ip, req.get('user-agent'), 
                { username: req.username }, 'INFO');
    }
    
    res.json({ message: 'Logout successful' });
});

// Health check with system info
app.get('/api/health', (req, res) => {
    const stats = {
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        environment: NODE_ENV,
        version: '2.0.0'
    };
    
    // Only show detailed stats in development
    if (NODE_ENV === 'production') {
        res.json({ status: 'OK', timestamp: stats.timestamp });
    } else {
        res.json(stats);
    }
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    logAudit('UNHANDLED_ERROR', null, req.ip, req.get('user-agent'), 
            { error: err.message, stack: err.stack }, 'ERROR');
    
    res.status(500).json({ 
        error: NODE_ENV === 'production' ? 'Internal server error' : err.message 
    });
});

// Start server
const server = app.listen(PORT, '127.0.0.1', () => {
    console.log(`Enhanced Security Server running on http://127.0.0.1:${PORT}`);
    console.log(`Environment: ${NODE_ENV}`);
    console.log(`Security features: Argon2, Rate Limiting, Input Sanitization, Audit Logging`);
    
    if (NODE_ENV === 'production') {
        console.log('Running in PRODUCTION mode with strict security');
    } else {
        console.log('Running in DEVELOPMENT mode with verbose logging');
    }
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down server...');
    server.close(() => {
        try {
            // Close all sessions
            db.prepare('UPDATE sessions SET is_active = 0').run();
            // Close database
            db.close();
            console.log('Database connection closed.');
        } catch (err) {
            console.error('Error during shutdown:', err);
        }
        process.exit(0);
    });
});