/**
 * Security Monitoring Module
 * Tracks and logs suspicious authentication attempts
 * Specifically designed to catch non-English character attacks
 */

const fs = require('fs');
const path = require('path');

class SecurityMonitor {
    constructor() {
        this.logFile = path.join(__dirname, 'security-audit.log');
        this.suspiciousIPs = new Map();
        this.attackPatterns = [];
    }

    // Log security event
    logSecurityEvent(event) {
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            type: event.type,
            ip: event.ip || 'unknown',
            details: event.details,
            severity: event.severity || 'medium'
        };

        // Write to security log
        const logLine = JSON.stringify(logEntry) + '\n';
        fs.appendFileSync(this.logFile, logLine);

        // Track suspicious IPs
        if (event.type === 'NON_ENGLISH_ATTEMPT') {
            this.trackSuspiciousIP(event.ip);
        }

        // Console warning for high severity
        if (event.severity === 'high') {
            console.error(`[SECURITY ALERT] ${event.type} from ${event.ip}`);
        }
    }

    // Track IPs with multiple non-English attempts
    trackSuspiciousIP(ip) {
        if (!this.suspiciousIPs.has(ip)) {
            this.suspiciousIPs.set(ip, {
                attempts: 0,
                firstSeen: new Date(),
                lastSeen: new Date()
            });
        }

        const ipData = this.suspiciousIPs.get(ip);
        ipData.attempts++;
        ipData.lastSeen = new Date();

        // Alert on multiple attempts
        if (ipData.attempts >= 3) {
            this.logSecurityEvent({
                type: 'REPEATED_NON_ENGLISH',
                ip: ip,
                details: `${ipData.attempts} non-English attempts`,
                severity: 'high'
            });
        }
    }

    // Analyze patterns in failed attempts
    detectAttackPattern(username, password) {
        // Check for common Unicode attack patterns
        const patterns = {
            homograph: /[\u0400-\u04FF]/, // Cyrillic
            rtlOverride: /[\u202A-\u202E]/, // RTL/LTR overrides
            zeroWidth: /[\u200B-\u200F]/, // Zero-width characters
            chinese: /[\u4E00-\u9FFF]/, // Chinese characters
            arabic: /[\u0600-\u06FF]/, // Arabic
            emoji: /[\u{1F300}-\u{1F6FF}]/u, // Emoji
            combining: /[\u0300-\u036F]/ // Combining diacriticals
        };

        const detectedPatterns = [];
        for (const [name, regex] of Object.entries(patterns)) {
            if (regex.test(username) || regex.test(password)) {
                detectedPatterns.push(name);
            }
        }

        if (detectedPatterns.length > 0) {
            return {
                detected: true,
                patterns: detectedPatterns,
                severity: detectedPatterns.includes('homograph') ? 'high' : 'medium'
            };
        }

        return { detected: false };
    }

    // Check if IP should be blocked
    shouldBlockIP(ip) {
        const ipData = this.suspiciousIPs.get(ip);
        if (!ipData) return false;

        // Block after 5 non-English attempts
        if (ipData.attempts >= 5) {
            return true;
        }

        // Block if multiple attempts in short time
        const timeDiff = (new Date() - ipData.firstSeen) / 1000; // seconds
        if (ipData.attempts >= 3 && timeDiff < 60) { // 3 attempts in 1 minute
            return true;
        }

        return false;
    }

    // Generate security report
    generateReport() {
        const report = {
            timestamp: new Date().toISOString(),
            suspiciousIPs: Array.from(this.suspiciousIPs.entries()).map(([ip, data]) => ({
                ip,
                attempts: data.attempts,
                firstSeen: data.firstSeen,
                lastSeen: data.lastSeen,
                shouldBlock: this.shouldBlockIP(ip)
            })),
            totalEvents: this.suspiciousIPs.size
        };

        return report;
    }

    // Clean old entries (run periodically)
    cleanup() {
        const now = new Date();
        const oneHourAgo = new Date(now - 60 * 60 * 1000);

        // Remove IPs that haven't been seen in an hour
        for (const [ip, data] of this.suspiciousIPs.entries()) {
            if (data.lastSeen < oneHourAgo && data.attempts < 3) {
                this.suspiciousIPs.delete(ip);
            }
        }
    }
}

// Middleware to integrate with Express
function createSecurityMiddleware(monitor) {
    return (req, res, next) => {
        // Store original json method
        const originalJson = res.json;

        // Override json method to detect generic errors
        res.json = function(data) {
            // Check if this is a security-triggered generic error
            if (data && data.error && 
                (data.error === 'Invalid credentials' || 
                 data.error === 'Registration failed. Please try again.' ||
                 data.error === 'Invalid password format')) {
                
                // Check if request contains non-English
                const username = req.body.username || '';
                const password = req.body.password || '';
                
                const patternCheck = monitor.detectAttackPattern(username, password);
                if (patternCheck.detected) {
                    monitor.logSecurityEvent({
                        type: 'NON_ENGLISH_ATTEMPT',
                        ip: req.ip,
                        details: {
                            endpoint: req.path,
                            patterns: patternCheck.patterns,
                            userAgent: req.get('user-agent')
                        },
                        severity: patternCheck.severity
                    });
                }
            }

            // Call original method
            return originalJson.call(this, data);
        };

        next();
    };
}

module.exports = { SecurityMonitor, createSecurityMiddleware };