# User Approval System Documentation

## Overview
The Indy Nexus authentication system includes a **manual approval workflow** where administrators must explicitly approve each new user before they can access the system.

## How It Works

### 1. User Registration
- User creates account with username, email, and password
- Account is created with `is_approved = 0` (not approved)
- User sees: **"Registration successful! Your account is pending approval."**
- User is redirected to login page

### 2. Login Attempt (Before Approval)
- User tries to login with correct credentials
- System checks `is_approved` status
- If not approved, user sees: **"Awaiting approval"**
- HTTP 403 (Forbidden) status is returned
- Login is blocked until approved

### 3. Admin Approval
- Administrator uses `admin.js` tool to review pending users
- Admin can approve, reject, or view details
- Approval is logged with timestamp, admin name, and notes

### 4. Post-Approval
- User can now login normally
- All features are available
- Approval status is permanent (unless manually changed)

## Admin Tool Usage

### Interactive Mode
```bash
node admin.js
```
This opens an interactive menu with options:
- List pending users
- List all users
- Approve user
- Reject user
- View user details
- Deactivate user
- Approve all pending
- Show statistics

### Quick Commands
```bash
# List pending users
node admin.js list

# Approve a specific user
node admin.js approve 1 "John Admin" "Verified identity"

# Reject a user (deletes them)
node admin.js reject 2

# View system statistics
node admin.js stats

# Get help
node admin.js help
```

## Database Schema

### Approval-Related Columns
```sql
is_approved BOOLEAN DEFAULT 0    -- 0 = pending, 1 = approved
approved_at DATETIME              -- When approved
approved_by TEXT                  -- Admin who approved
approval_notes TEXT               -- Optional notes
```

## Approval Workflow Examples

### Example 1: Normal Approval
```bash
$ node admin.js
═══════════════════════════════════════════════════════
           INDY NEXUS ADMIN CONSOLE
═══════════════════════════════════════════════════════

Commands:
1. List pending users
2. List all users
3. Approve user
...

Enter choice (1-9): 1

Users Awaiting Approval:
────────────────────────────────────────────
ID: 1 | Username: john_doe
    Email: john@example.com
    Created: 10/30/2024, 2:30:15 PM
    Status: ⏳ Pending | Active

Enter choice (1-9): 3
Enter user ID to approve: 1
Approval notes (optional): Verified via email
Your name (for records): Admin

✓ User 'john_doe' (ID: 1) has been approved!
```

### Example 2: Batch Approval
```bash
$ node admin.js
Enter choice (1-9): 7

⚠️  WARNING: This will approve 5 pending users!
Are you sure? (yes/no): yes
Enter admin name for approval records: Admin

✓ User 'user1' (ID: 1) has been approved!
✓ User 'user2' (ID: 2) has been approved!
✓ User 'user3' (ID: 3) has been approved!
...

✓ Approved 5 users.
```

## Security Benefits

### 1. **Complete Access Control**
- No user can access the system without explicit approval
- Prevents automated bot registrations
- Ensures only trusted users get access

### 2. **Audit Trail**
- Every approval is logged with:
  - Timestamp
  - Admin who approved
  - Optional notes
- Helps with compliance and security audits

### 3. **Flexible Management**
- Can reject (delete) suspicious accounts
- Can deactivate users without deletion
- Can add approval notes for future reference

## User Experience

### Registration Flow
1. User fills out registration form
2. Submits with valid password (20-84 chars)
3. Sees: **"Registration successful! Your account is pending approval."**
4. Redirected to login page

### Login Flow (Pending)
1. User enters correct credentials
2. System checks approval status
3. Sees: **"Awaiting approval. Please contact the administrator."**
4. Cannot access system

### Login Flow (Approved)
1. User enters correct credentials
2. System verifies approval status
3. Normal login proceeds
4. Access granted

## Admin Best Practices

### 1. **Regular Review**
Check pending users daily:
```bash
node admin.js list
```

### 2. **Document Approvals**
Always add notes when approving:
```bash
node admin.js approve 1 "Admin" "Verified via company email"
```

### 3. **Quick Rejection**
Remove suspicious accounts immediately:
```bash
node admin.js reject 2
```

### 4. **Monitor Statistics**
Check system health regularly:
```bash
node admin.js stats
```

Output:
```
System Statistics:
────────────────────────────────────────
Total Users: 25
Approved: 20
Pending Approval: 3
Inactive: 2
Registrations (last 7 days): 5
```

## SQL Queries for Direct Database Access

### View Pending Users
```sql
SELECT id, username, email, created_at 
FROM users 
WHERE is_approved = 0 
ORDER BY created_at DESC;
```

### Approve User Directly
```sql
UPDATE users 
SET is_approved = 1, 
    approved_at = datetime('now'),
    approved_by = 'Admin',
    approval_notes = 'Manual approval'
WHERE id = 1;
```

### Check Approval Status
```sql
SELECT username, is_approved, approved_by, approved_at 
FROM users 
WHERE username = 'john_doe';
```

### Find Recently Approved
```sql
SELECT username, approved_by, approved_at 
FROM users 
WHERE is_approved = 1 
ORDER BY approved_at DESC 
LIMIT 10;
```

## Deployment Notes

### For Debian Container

1. **Transfer admin.js to server:**
```bash
scp admin.js root@<SERVER_IP>:/opt/indy-nexus/
```

2. **Run admin tool on server:**
```bash
cd /opt/indy-nexus
node admin.js
```

3. **Set up alias for convenience:**
```bash
echo "alias indyadmin='cd /opt/indy-nexus && node admin.js'" >> ~/.bashrc
source ~/.bashrc
# Now just type: indyadmin
```

### For Windows Development

Run directly in PowerShell:
```powershell
node admin.js
```

## Troubleshooting

### Issue: "User with ID X not found"
**Solution**: User may have been deleted. Check with `node admin.js list`

### Issue: Can't approve user
**Solution**: Check if user is already approved with `node admin.js 5` (view details)

### Issue: Approved user still can't login
**Possible causes**:
1. User entering wrong password
2. Account is deactivated (`is_active = 0`)
3. Account is locked (too many failed attempts)

Check with:
```sql
SELECT * FROM users WHERE username = 'username_here';
```

## Emergency Procedures

### Approve All Users (Emergency Only)
```sql
UPDATE users SET is_approved = 1, approved_by = 'Emergency' 
WHERE is_approved = 0;
```

### Disable Approval System (Temporary)
Comment out the approval check in server.js:
```javascript
// if (!user.is_approved) {
//     return res.status(403).json({ error: 'Awaiting approval' });
// }
```

### Reset All Approvals
```sql
UPDATE users SET is_approved = 0, approved_at = NULL, 
approved_by = NULL, approval_notes = NULL;
```

## Summary

The approval system ensures:
- ✅ **No unauthorized access** - Every user needs manual approval
- ✅ **Clear communication** - Users know they're awaiting approval
- ✅ **Full audit trail** - Every approval is logged
- ✅ **Flexible management** - Approve, reject, or deactivate as needed
- ✅ **Simple administration** - Easy-to-use CLI tool

This system is perfect for small, controlled user bases where security is paramount and you want complete control over who accesses your system.