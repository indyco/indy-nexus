/**
 * Configuration module for Indy Nexus
 * Handles environment variables and security presets
 */

// Load dotenv only in development
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

// Security preset definitions
const PRESETS = {
    basic: {
        // Development-friendly settings
        enableHelmet: true,
        enableCSP: false,
        enableHSTS: false,
        enableRateLimit: false,
        enableCors: true,
        corsOrigin: '*',
        enableCompression: true,
        enableBasicAuth: false,
        forceHttps: false,
        trustProxy: false,
        staticMaxAge: 0,
        staticImmutable: false,
        logFormat: 'dev',
        enableAuditLog: false,
        enableSessionCleanup: false,
        argon2MemoryCost: 65536,  // 64 MB
        rateLimitWindowMs: 900000,
        rateLimitMax: 100
    },
    enhanced: {
        // Production-hardened settings
        enableHelmet: true,
        enableCSP: true,
        enableHSTS: true,
        enableRateLimit: true,
        enableCors: true,
        corsOrigin: process.env.ALLOWED_ORIGINS || 'http://localhost:3000',
        enableCompression: true,
        enableBasicAuth: false,
        forceHttps: true,
        trustProxy: true,
        staticMaxAge: 31536000,
        staticImmutable: true,
        logFormat: 'combined',
        enableAuditLog: true,
        enableSessionCleanup: true,
        argon2MemoryCost: 131072,  // 128 MB
        rateLimitWindowMs: 900000,
        rateLimitMax: 5
    }
};

// Helper to parse boolean env vars
function parseBool(value, defaultValue = false) {
    if (value === undefined || value === null) return defaultValue;
    return value === 'true' || value === '1' || value === 'yes';
}

// Helper to parse number env vars
function parseNumber(value, defaultValue) {
    const num = parseInt(value, 10);
    return isNaN(num) ? defaultValue : num;
}

// Get the base preset
const nodeEnv = process.env.NODE_ENV || 'development';
const securityPreset = process.env.SECURITY_PRESET || (nodeEnv === 'production' ? 'enhanced' : 'basic');
const baseConfig = PRESETS[securityPreset] || PRESETS.basic;

// Build configuration with environment overrides
const config = {
    // Server settings
    nodeEnv,
    securityPreset,
    port: parseNumber(process.env.PORT, 3000),
    host: process.env.HOST || '127.0.0.1',
    
    // Database
    databasePath: process.env.DATABASE_PATH || './users.db',
    
    // JWT
    jwtSecret: process.env.JWT_SECRET,
    sessionDuration: process.env.SESSION_DURATION_HOURS || '24h',
    
    // Security features (with env overrides)
    enableHelmet: parseBool(process.env.ENABLE_HELMET, baseConfig.enableHelmet),
    enableCSP: parseBool(process.env.ENABLE_CSP, baseConfig.enableCSP),
    enableHSTS: parseBool(process.env.ENABLE_HSTS, baseConfig.enableHSTS),
    enableRateLimit: parseBool(process.env.ENABLE_RATE_LIMIT, baseConfig.enableRateLimit),
    enableCors: parseBool(process.env.ENABLE_CORS, baseConfig.enableCors),
    enableCompression: parseBool(process.env.ENABLE_COMPRESSION, baseConfig.enableCompression),
    enableBasicAuth: parseBool(process.env.ENABLE_BASIC_AUTH, baseConfig.enableBasicAuth),
    enableAuditLog: parseBool(process.env.ENABLE_AUDIT_LOG, baseConfig.enableAuditLog),
    enableSessionCleanup: parseBool(process.env.ENABLE_SESSION_CLEANUP, baseConfig.enableSessionCleanup),
    
    // Security settings
    forceHttps: parseBool(process.env.FORCE_HTTPS, baseConfig.forceHttps),
    trustProxy: parseBool(process.env.TRUST_PROXY, baseConfig.trustProxy),
    
    // CORS
    corsOrigin: process.env.CORS_ORIGIN || baseConfig.corsOrigin,
    
    // Rate limiting
    rateLimitWindowMs: parseNumber(process.env.RATE_LIMIT_WINDOW_MS, baseConfig.rateLimitWindowMs),
    rateLimitMax: parseNumber(process.env.RATE_LIMIT_MAX, baseConfig.rateLimitMax),
    
    // Basic auth
    basicAuthUser: process.env.BASIC_AUTH_USER,
    basicAuthPass: process.env.BASIC_AUTH_PASS,
    
    // Static files
    staticMaxAge: parseNumber(process.env.STATIC_MAX_AGE, baseConfig.staticMaxAge),
    staticImmutable: parseBool(process.env.STATIC_IMMUTABLE, baseConfig.staticImmutable),
    
    // Logging
    logFormat: process.env.LOG_FORMAT || baseConfig.logFormat,
    
    // Argon2
    argon2Config: {
        type: 2, // argon2id
        memoryCost: parseNumber(process.env.ARGON2_MEMORY_COST, baseConfig.argon2MemoryCost),
        timeCost: parseNumber(process.env.ARGON2_TIME_COST, 3),
        parallelism: parseNumber(process.env.ARGON2_PARALLELISM, 4),
        saltLength: parseNumber(process.env.ARGON2_SALT_LENGTH, 16)
    },
    
    // Authentication settings
    requireUserApproval: parseBool(process.env.REQUIRE_USER_APPROVAL, false),
    maxLoginAttempts: parseNumber(process.env.MAX_LOGIN_ATTEMPTS, 5),
    lockoutDurationMinutes: parseNumber(process.env.LOCKOUT_DURATION_MINUTES, 30)
};

// Validate required settings
if (!config.jwtSecret && config.nodeEnv === 'production') {
    console.error('FATAL ERROR: JWT_SECRET is required in production');
    process.exit(1);
}

// Log configuration in development
if (config.nodeEnv === 'development') {
    console.log('Configuration loaded:');
    console.log(`  Environment: ${config.nodeEnv}`);
    console.log(`  Security Preset: ${config.securityPreset}`);
    console.log(`  Server: ${config.host}:${config.port}`);
    console.log(`  Features: Helmet=${config.enableHelmet}, RateLimit=${config.enableRateLimit}, CORS=${config.enableCors}`);
}

module.exports = config;