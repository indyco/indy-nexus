# Indy Nexus Security Configuration

## Character Set Restrictions

### Why English-Only?
For a small, controlled user base, restricting to English characters provides several security benefits:

1. **Prevents Unicode Attacks**: No risk of homograph attacks (e.g., Cyrillic 'а' looking like Latin 'a')
2. **Simplifies Validation**: Easier to audit and validate inputs
3. **Reduces Attack Surface**: No complex Unicode normalization issues
4. **Database Consistency**: Ensures consistent storage and comparison
5. **Prevents Encoding Issues**: Avoids UTF-8/Unicode encoding vulnerabilities

### Username Requirements
- **Length**: 3-30 characters
- **Allowed Characters**: 
  - English letters (A-Z, a-z)
  - Numbers (0-9)
  - Underscore (_)
- **Regex Pattern**: `^[a-zA-Z0-9_]{3,30}$`
- **ASCII Range**: 0x00-0x7F only

### Password Requirements
- **Length**: 20-84 characters
- **Allowed Characters**:
  - English uppercase letters (A-Z)
  - English lowercase letters (a-z)
  - Numbers (0-9)
  - Special characters: `!@#$%^&*()_+-=[]{}|;':",./<>?`
  - Space character (for passphrase support)
- **Required Elements**:
  - At least 1 uppercase letter
  - At least 1 lowercase letter
  - At least 1 number
  - At least 1 special character
- **Regex Pattern**: `^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?\\s]{20,84}$`

## Security Implementation Details

### Server-Side Validation (Node.js)
```javascript
// Username validation
const validUsername = /^[a-zA-Z0-9_]{3,30}$/.test(username);
const asciiOnly = /^[\x00-\x7F]*$/.test(username);

// Password validation
const englishOnly = /^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?\\s]+$/.test(password);
```

### Client-Side Validation (JavaScript)
- Real-time feedback during registration
- Pre-submission validation
- Clear error messages for non-English characters

### Database Considerations
- **Collation**: Using default SQLite collation (binary comparison)
- **Storage**: All passwords stored as bcrypt hashes (ASCII-safe base64)
- **Usernames**: Case-sensitive storage and comparison

## Attack Prevention

### What This Prevents:
1. **Homograph Attacks**: е (Cyrillic) vs e (Latin)
2. **Bidirectional Text Attacks**: RTL/LTR override characters
3. **Zero-Width Characters**: ZWSP, ZWNJ attacks
4. **Normalization Attacks**: NFC/NFD/NFKC/NFKD issues
5. **Encoding Bypasses**: UTF-8 overlong encoding
6. **SQL Injection Variants**: Unicode-based SQLi attempts

### Additional Security Layers:
- **bcrypt Hashing**: 12 rounds (2^12 iterations)
- **Rate Limiting**: 5 attempts per 15 minutes
- **Account Lockout**: 30 minutes after 5 failed attempts
- **JWT Tokens**: 24-hour expiry
- **Session Tracking**: IP and User-Agent logging

## Configuration for Small User Base

### Advantages of Strict Requirements:
1. **Memorability**: Users can be trained on specific password patterns
2. **Reduced Support**: No international character issues
3. **Audit Trail**: Easier to log and audit authentication attempts
4. **Compliance**: Simple to document and verify security controls

### Recommended Password Patterns:
For your small user base, consider these patterns:
- **Pattern 1**: `[Word][Number][Word][Symbol]` (e.g., "Security2024Management!@#")
- **Pattern 2**: `[Phrase with spaces]` (e.g., "The quick brown fox jumps 2024!")
- **Pattern 3**: `[Acronym][Number][Symbol]` (e.g., "INDYNEX2024SecureAccess!@#$")

## Testing Character Restrictions

### Test Valid Usernames:
```bash
# Valid
"john_doe"      ✓
"user123"       ✓
"admin_2024"    ✓

# Invalid
"jöhn"          ✗ (non-English character)
"user@123"      ✗ (@ not allowed)
"пользователь"  ✗ (Cyrillic)
"用户"          ✗ (Chinese)
```

### Test Valid Passwords:
```bash
# Valid
"MySecurePassword2024!@#"              ✓
"The quick brown fox 123!"             ✓
"P@ssw0rd_With_Underscores_2024"       ✓

# Invalid  
"Pássw0rd2024!@#"                      ✗ (á is not English)
"Password2024!@#世界"                   ✗ (Chinese characters)
"Пароль2024!@#"                        ✗ (Cyrillic)
"MyPassword2024"                       ✗ (missing special character)
"mypassword2024!@#"                    ✗ (missing uppercase)
"MYPASSWORD2024!@#"                    ✗ (missing lowercase)
"Short!@#"                             ✗ (too short)
```

## Monitoring and Alerts

### Log These Events:
1. Any attempt to use non-English characters
2. Repeated validation failures from same IP
3. Patterns suggesting automated attacks
4. Unusual character combinations

### Alert Triggers:
- 3+ non-English character attempts from same IP
- 10+ validation failures in 1 hour
- Any SQL injection patterns detected

## Implementation Checklist

- [x] Server-side English-only validation
- [x] Client-side English-only validation  
- [x] Clear error messages for violations
- [x] Real-time password requirement feedback
- [x] Documentation of allowed characters
- [x] Test cases for edge cases
- [x] Logging of validation failures

## Emergency Procedures

### If Unicode Attack Detected:
1. Check logs for source IP
2. Verify no accounts were created with non-ASCII usernames
3. Run database query to find non-ASCII entries:
   ```sql
   SELECT * FROM users WHERE username != CAST(username AS BLOB);
   ```
4. Block IP at firewall level if necessary

### Database Cleanup:
```sql
-- Find any non-ASCII usernames (should return empty)
SELECT id, username, hex(username) 
FROM users 
WHERE length(username) != length(cast(username as blob));

-- Check for hidden characters
SELECT id, username, length(username) 
FROM users 
WHERE username LIKE '%' || char(0) || '%' 
   OR username LIKE '%' || char(9) || '%';
```

## Notes for Administrators

1. **Training**: Ensure all users understand the English-only requirement
2. **Password Managers**: Recommend password managers that support ASCII-only generation
3. **Regular Audits**: Monthly check for any non-conforming entries
4. **Backup Before Changes**: Always backup before modifying validation rules

## Contact for Security Issues

If you discover any security issues related to character validation:
1. Do not attempt to exploit
2. Document the issue clearly
3. Contact system administrator immediately
4. Preserve logs for analysis