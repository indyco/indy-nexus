/**
 * Unified Indy Nexus Server
 * Environment-aware server with configurable security features
 */

// Load configuration
// Use explicit path to server config to avoid loading frontend config.js
const config = require('./config/index');

const express = require('express');
const argon2 = require('argon2');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');

// Conditional middleware imports
const helmet = config.enableHelmet ? require('helmet') : null;
const cors = config.enableCors ? require('cors') : null;
const rateLimit = config.enableRateLimit ? require('express-rate-limit') : null;
const compression = config.enableCompression ? require('compression') : null;

// Additional security for enhanced mode
const mongoSanitize = config.securityPreset === 'enhanced' ? require('express-mongo-sanitize') : null;
const hpp = config.securityPreset === 'enhanced' ? require('hpp') : null;
const xss = config.securityPreset === 'enhanced' ? require('xss') : null;
const validator = config.securityPreset === 'enhanced' ? require('validator') : null;

// Initialize Express app
const app = express();

// Trust proxy if configured
if (config.trustProxy) {
    app.set('trust proxy', 1);
    console.log('Trust proxy enabled');
}

// Force HTTPS redirect in production
if (config.forceHttps) {
    app.use((req, res, next) => {
        if (req.header('x-forwarded-proto') !== 'https') {
            return res.redirect(`https://${req.header('host')}${req.url}`);
        }
        next();
    });
}

// Apply security middleware based on configuration
if (config.enableHelmet) {
    const helmetConfig = {
        contentSecurityPolicy: config.enableCSP ? {
            directives: {
                defaultSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                scriptSrc: ["'self'"],
                imgSrc: ["'self'", "data:", "https:"],
                connectSrc: ["'self'"],
                fontSrc: ["'self'"],
                objectSrc: ["'none'"],
                mediaSrc: ["'self'"],
                frameSrc: ["'none'"],
            }
        } : false,
        hsts: config.enableHSTS ? {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true
        } : false
    };
    app.use(helmet(helmetConfig));
}

// CORS configuration
if (config.enableCors) {
    const corsOptions = {
        origin: config.corsOrigin === '*' ? '*' : config.corsOrigin.split(','),
        credentials: true,
        optionsSuccessStatus: 200
    };
    app.use(cors(corsOptions));
}

// Compression
if (config.enableCompression) {
    app.use(compression());
}

// Body parsing with size limits
app.use(express.json({ limit: config.securityPreset === 'enhanced' ? '10kb' : '1mb' }));
app.use(express.urlencoded({ extended: true, limit: config.securityPreset === 'enhanced' ? '10kb' : '1mb' }));

// Enhanced sanitization for production
if (mongoSanitize) {
    app.use(mongoSanitize());
}
if (hpp) {
    app.use(hpp());
}

// Serve static files
app.use(express.static(path.join(__dirname, '/'), {
    dotfiles: 'deny',
    index: false,
    maxAge: config.staticMaxAge * 1000,
    immutable: config.staticImmutable,
    setHeaders: (res, path) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        if (config.staticMaxAge > 0) {
            res.setHeader('Cache-Control', `public, max-age=${config.staticMaxAge}`);
        }
    }
}));

// Rate limiting
let authLimiter, apiLimiter;
if (config.enableRateLimit) {
    authLimiter = rateLimit({
        windowMs: config.rateLimitWindowMs,
        max: config.rateLimitMax,
        message: 'Too many authentication attempts, please try again later.',
        standardHeaders: true,
        legacyHeaders: false
    });
    
    apiLimiter = rateLimit({
        windowMs: 60 * 1000,  // 1 minute
        max: 100,
        message: 'Too many requests, please slow down.'
    });
}

// Initialize database
const db = new Database(config.databasePath);
console.log(`Connected to SQLite database at ${config.databasePath}`);

// Database pragmas
db.exec('PRAGMA foreign_keys = ON');
if (config.securityPreset === 'enhanced') {
    db.exec('PRAGMA journal_mode = WAL');
    db.exec('PRAGMA synchronous = FULL');
    db.exec('PRAGMA auto_vacuum = FULL');
    db.exec('PRAGMA secure_delete = ON');
}

// Create tables
try {
    // Users table
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
            is_approved BOOLEAN DEFAULT ${config.requireUserApproval ? 0 : 1},
            approved_at DATETIME,
            approved_by TEXT,
            approval_notes TEXT,
            password_changed_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    // Create indexes
    db.exec('CREATE INDEX IF NOT EXISTS idx_username ON users(username)');
    db.exec('CREATE INDEX IF NOT EXISTS idx_email ON users(email)');
    
    // Sessions table
    db.exec(`
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            ip_address TEXT,
            user_agent TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);
    
    db.exec('CREATE INDEX IF NOT EXISTS idx_token ON sessions(token_hash)');
    
    // Audit log table (only in enhanced mode)
    if (config.enableAuditLog) {
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
    }
    
    console.log('Database tables ready');
} catch (err) {
    console.error('Error creating database tables:', err);
    process.exit(1);
}

// Prepared statements
const statements = {
    insertUser: db.prepare(
        'INSERT INTO users (username, email, password_hash, is_approved) VALUES (?, ?, ?, ?)'
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
        'INSERT INTO sessions (user_id, token_hash, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)'
    ),
    getUserProfile: db.prepare(
        'SELECT id, username, email, created_at, last_login, is_approved FROM users WHERE id = ?'
    ),
    unlockAccount: db.prepare(
        'UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = ?'
    ),
    cleanupSessions: db.prepare(
        'DELETE FROM sessions WHERE expires_at < datetime(\'now\')'
    )
};

// Audit log statement (only if enabled)
if (config.enableAuditLog) {
    statements.logAudit = db.prepare(
        'INSERT INTO audit_log (event_type, user_id, ip_address, user_agent, details, severity) VALUES (?, ?, ?, ?, ?, ?)'
    );
}

// Helper functions
function logAudit(eventType, userId, ip, userAgent, details, severity = 'INFO') {
    if (config.enableAuditLog && statements.logAudit) {
        try {
            statements.logAudit.run(eventType, userId, ip, userAgent, JSON.stringify(details), severity);
        } catch (err) {
            console.error('Audit log error:', err);
        }
    }
}

function sanitizeInput(input) {
    if (!xss || typeof input !== 'string') return input;
    return xss(input);
}

function validatePassword(password) {
    if (password.length < 20 || password.length > 84) {
        return { valid: false, message: 'Password must be between 20 and 84 characters' };
    }
    
    // Check for English characters only
    const englishOnly = /^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?\s]+$/.test(password);
    if (!englishOnly) {
        console.warn(`[SECURITY] Non-English characters detected at ${new Date().toISOString()}`);
        return { valid: false, message: 'Invalid password format' };
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
    
    // Check for repeated characters (enhanced mode only)
    if (config.securityPreset === 'enhanced' && /(.)\\1{2,}/.test(password)) {
        return { valid: false, message: 'Password contains too many repeated characters' };
    }
    
    return { valid: true };
}

// Session cleanup (enhanced mode only)
if (config.enableSessionCleanup) {
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
}

// API Routes

// Health check endpoint
app.get('/api/health', (req, res) => {
    const health = {
        status: 'OK',
        timestamp: new Date().toISOString(),
        environment: config.nodeEnv,
        preset: config.securityPreset
    };
    
    if (config.nodeEnv === 'development') {
        health.uptime = process.uptime();
        health.memory = process.memoryUsage();
    }
    
    res.json(health);
});

// Register endpoint
app.post('/api/register', authLimiter || ((req, res, next) => next()), async (req, res) => {
    let { username, email, password } = req.body;
    
    // Sanitize inputs in enhanced mode
    if (config.securityPreset === 'enhanced') {
        username = sanitizeInput(username);
        email = sanitizeInput(email);
    }
    
    // Validation
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Username validation
    if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
        return res.status(400).json({ error: 'Username must be 3-30 characters, alphanumeric and underscore only' });
    }
    
    // Email validation
    if (config.securityPreset === 'enhanced' && validator) {
        if (!validator.isEmail(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        email = validator.normalizeEmail(email);
    } else {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
    }
    
    // Password validation
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
        return res.status(400).json({ error: passwordValidation.message });
    }
    
    try {
        // Hash password with Argon2
        const passwordHash = await argon2.hash(password, config.argon2Config);
        
        // Insert user
        const isApproved = config.requireUserApproval ? 0 : 1;
        const result = statements.insertUser.run(username, email, passwordHash, isApproved);
        const userId = result.lastInsertRowid;
        
        logAudit('USER_REGISTERED', userId, req.ip, req.get('user-agent'), 
                { username, email }, 'INFO');
        
        // Generate JWT token
        const token = jwt.sign(
            { userId: Number(userId), username },
            config.jwtSecret,
            { expiresIn: config.sessionDuration }
        );
        
        // Store session
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        
        statements.insertSession.run(
            userId,
            tokenHash,
            req.ip,
            req.get('user-agent'),
            expiresAt.toISOString()
        );
        
        res.status(201).json({ 
            message: 'Registration successful',
            token,
            userId: Number(userId),
            username,
            requiresApproval: config.requireUserApproval
        });
    } catch (error) {
        if (error.message.includes('UNIQUE constraint failed')) {
            return res.status(409).json({ error: 'Username or email already exists' });
        }
        console.error('Registration error:', error);
        logAudit('REGISTRATION_ERROR', null, req.ip, req.get('user-agent'), 
                { error: error.message }, 'ERROR');
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login endpoint
app.post('/api/login', authLimiter || ((req, res, next) => next()), async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    
    try {
        const user = statements.findUserByUsername.get(username);
        
        if (!user) {
            logAudit('LOGIN_FAILED', null, req.ip, req.get('user-agent'), 
                    { username, reason: 'user_not_found' }, 'WARNING');
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Check if approved (if approval required)
        if (config.requireUserApproval && !user.is_approved) {
            return res.status(403).json({ 
                error: 'Awaiting approval',
                awaiting_approval: true 
            });
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
            
            if (failedAttempts >= config.maxLoginAttempts) {
                lockedUntil = new Date(Date.now() + config.lockoutDurationMinutes * 60 * 1000).toISOString();
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
            config.jwtSecret,
            { expiresIn: config.sessionDuration }
        );
        
        // Store session
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
        logAudit('LOGIN_ERROR', null, req.ip, req.get('user-agent'), 
                { error: error.message }, 'ERROR');
        res.status(500).json({ error: 'Login failed' });
    }
});

// Token verification middleware
function verifyToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    jwt.verify(token, config.jwtSecret, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        req.userId = decoded.userId;
        req.username = decoded.username;
        next();
    });
}

// Profile endpoint
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
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (token) {
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        db.prepare('UPDATE sessions SET is_active = 0 WHERE token_hash = ?').run(tokenHash);
        logAudit('LOGOUT', req.userId, req.ip, req.get('user-agent'), 
                { username: req.username }, 'INFO');
    }
    
    res.json({ message: 'Logout successful' });
});

// Start server
const server = app.listen(config.port, config.host, () => {
    console.log(`\n===============================================`);
    console.log(`Indy Nexus Server Started`);
    console.log(`===============================================`);
    console.log(`Environment: ${config.nodeEnv}`);
    console.log(`Security Preset: ${config.securityPreset}`);
    console.log(`Server: http://${config.host}:${config.port}`);
    console.log(`API: http://${config.host}:${config.port}/api/`);
    console.log(`\nSecurity Features:`);
    console.log(`  Helmet: ${config.enableHelmet}`);
    console.log(`  CSP: ${config.enableCSP}`);
    console.log(`  HSTS: ${config.enableHSTS}`);
    console.log(`  Rate Limiting: ${config.enableRateLimit}`);
    console.log(`  CORS: ${config.enableCors}`);
    console.log(`  Compression: ${config.enableCompression}`);
    console.log(`  Audit Logging: ${config.enableAuditLog}`);
    console.log(`===============================================\n`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down server...');
    server.close(() => {
        try {
            if (config.enableSessionCleanup) {
                db.prepare('UPDATE sessions SET is_active = 0').run();
            }
            db.close();
            console.log('Database connection closed.');
        } catch (err) {
            console.error('Error during shutdown:', err);
        }
        process.exit(0);
    });
});