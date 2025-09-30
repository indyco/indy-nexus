# Security Operations Guide - Hidden Validation Strategy

## CONFIDENTIAL - FOR AUTHORIZED ADMINISTRATORS ONLY

### Overview
This system implements a **silent rejection** strategy for non-English characters. Attackers using Unicode, Cyrillic, Chinese, or other non-ASCII characters will receive generic error messages that don't reveal why their attempts failed.

## Strategy: Obfuscation Through Generic Errors

### What Users See:
- **Legitimate users** with English-only passwords: Normal error messages
- **Attackers** with non-English characters: Generic "Invalid credentials" errors
- **No mention** of English-only requirements in any user-facing content

### What Actually Happens:
1. System silently checks for non-English characters
2. If detected, immediately returns generic error
3. Attack is logged to `security-audit.log`
4. Attacker wastes time trying variations that will never work

## Security Benefits

### 1. **Delay Tactics**
- Attackers don't know their Unicode tricks are detected
- They waste computational resources on doomed attempts
- Increases time-to-compromise significantly

### 2. **Intelligence Gathering**
- We log all non-English attempts
- Build profiles of attack patterns
- Identify persistent threat actors

### 3. **Reduced Attack Surface**
- No Unicode normalization vulnerabilities
- No homograph attacks possible
- No bidirectional text exploits

## Monitoring Non-English Attempts

### Log Locations:
- **Security Audit Log**: `/opt/indy-nexus/security-audit.log`
- **System Console**: High-severity alerts only
- **Node.js Logs**: `[SECURITY]` prefixed warnings

### What Gets Logged:
```json
{
    "timestamp": "2024-01-01T00:00:00.000Z",
    "type": "NON_ENGLISH_ATTEMPT",
    "ip": "192.168.1.100",
    "details": {
        "endpoint": "/api/login",
        "patterns": ["cyrillic", "homograph"],
        "userAgent": "Mozilla/5.0..."
    },
    "severity": "high"
}
```

## Detection Patterns

### Tracked Attack Types:
| Pattern | Description | Example | Severity |
|---------|-------------|---------|----------|
| Homograph | Cyrillic looking like Latin | раssword (р is Cyrillic) | HIGH |
| RTL Override | Right-to-left text tricks | ‮drowssap‬ | HIGH |
| Zero-width | Invisible characters | pass​word | MEDIUM |
| Chinese | Chinese characters | 密码2024 | MEDIUM |
| Arabic | Arabic script | كلمة السر | MEDIUM |
| Emoji | Emoji in credentials | Pass😀word | LOW |
| Combining | Diacritical marks | pássẅörd | MEDIUM |

## Response Strategies

### Immediate Actions:
1. **1-2 attempts**: Log and monitor
2. **3-4 attempts**: Flag IP as suspicious
3. **5+ attempts**: Consider blocking IP
4. **Multiple IPs same pattern**: Possible coordinated attack

### Generic Error Messages Used:
- Login: `"Invalid credentials"`
- Registration: `"Registration failed. Please try again."`
- Password validation: `"Invalid password format"`

These messages are **identical** to legitimate validation failures.

## Operational Procedures

### Daily Review:
```bash
# Check today's non-English attempts
grep "NON_ENGLISH" /opt/indy-nexus/security-audit.log | grep "$(date +%Y-%m-%d)"

# Count attempts by IP
grep "NON_ENGLISH" security-audit.log | jq -r '.ip' | sort | uniq -c | sort -rn

# Check for patterns
grep "homograph\|rtlOverride" security-audit.log
```

### Weekly Analysis:
```bash
# Generate security report
node -e "
const { SecurityMonitor } = require('./security-monitor.js');
const monitor = new SecurityMonitor();
console.log(JSON.stringify(monitor.generateReport(), null, 2));
"
```

### If Attack Detected:

1. **DO NOT** change error messages (maintains obfuscation)
2. **DO NOT** reveal detection to attacker
3. **DO** increase monitoring of source IP
4. **DO** check for data exfiltration attempts
5. **DO** preserve logs for forensics

## Database Queries for Security

### Find Suspicious Accounts:
```sql
-- Check for any non-ASCII usernames (should be empty)
SELECT id, username, created_at, last_login
FROM users
WHERE username != CAST(username AS BLOB);

-- Recent registrations with quick failures
SELECT username, created_at, failed_attempts
FROM users
WHERE created_at > datetime('now', '-24 hours')
  AND failed_attempts > 0
ORDER BY failed_attempts DESC;

-- Accounts created but never successfully logged in
SELECT username, created_at
FROM users
WHERE last_login IS NULL
  AND created_at < datetime('now', '-1 hour');
```

## Testing the System (Authorized Only)

### Test Non-English Detection:
```bash
# Test Cyrillic (will fail silently)
curl -X POST http://127.0.0.1:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "tеst", "password": "Pаssword123!@#WithMin20Chars"}'
# Note: 'е' and 'а' are Cyrillic, not Latin

# Test Chinese (will fail silently)
curl -X POST http://127.0.0.1:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "test用户", "email": "test@example.com", "password": "Password2024!@#世界MinChars"}'

# Check logs after testing
tail -f /opt/indy-nexus/security-audit.log
```

## Maintaining Secrecy

### CRITICAL Rules:
1. **NEVER** mention English-only requirement in:
   - Error messages
   - Documentation visible to users
   - Client-side code comments
   - API responses

2. **ONLY** document this in:
   - This operations guide
   - Security audit logs
   - Internal admin communications

3. **Train authorized users** separately about English-only requirement

## Indicators of Compromise

### Watch for:
- Sudden spike in "Invalid credentials" errors
- Multiple IPs testing same Unicode patterns
- Registration attempts with incrementing Unicode variations
- Timing attacks combined with Unicode attempts

### Alert Thresholds:
- **Info**: 1-2 non-English attempts per hour
- **Warning**: 3-5 attempts per hour
- **Critical**: 10+ attempts per hour or coordinated pattern

## Emergency Response

### If Under Active Unicode Attack:

1. **Enable enhanced logging**:
   ```javascript
   // In server.js, temporarily add:
   console.log('[SECURITY-DEBUG]', JSON.stringify({
       username: username.length,
       password: password.length,
       headers: req.headers
   }));
   ```

2. **Block attacking IPs**:
   ```bash
   # Add to firewall
   iptables -A INPUT -s <ATTACKER_IP> -j DROP
   ```

3. **Notify security team** with:
   - Attack pattern details
   - Source IPs
   - Timeline of attempts
   - Current defensive status

## Success Metrics

### The Strategy is Working When:
- ✅ Zero successful logins with non-English characters
- ✅ Attackers show confusion in attempt patterns
- ✅ Multiple failed attempts from same IP
- ✅ No mentions of character restrictions in reconnaissance

### Red Flags:
- ❌ Attacker stops after one attempt (may have detected our detection)
- ❌ Sudden cessation of Unicode attempts (strategy discovered)
- ❌ Public discussion of English-only requirement

## Remember

**This security strategy depends on secrecy. The moment attackers know we're blocking non-English characters, they'll adjust their tactics. Maintain operational security at all times.**

---

*Last Updated: System Deployment*
*Classification: CONFIDENTIAL*
*Distribution: System Administrators Only*