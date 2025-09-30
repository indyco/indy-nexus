#!/usr/bin/env node

/**
 * Admin CLI Tool for Indy Nexus
 * Used for approving users and managing the system
 */

const Database = require('better-sqlite3');
const readline = require('readline');
const crypto = require('crypto');
const argon2 = require('argon2');

// ANSI color codes for terminal output
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    cyan: '\x1b[36m',
    magenta: '\x1b[35m'
};

// Connect to database
const db = new Database('./users.db');

// Create readline interface
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

// Helper function for colored output
function log(message, color = 'reset') {
    console.log(colors[color] + message + colors.reset);
}

// Helper function to prompt user
function prompt(question) {
    return new Promise(resolve => {
        rl.question(question, answer => {
            resolve(answer);
        });
    });
}

// Display header
function showHeader() {
    console.clear();
    log('═══════════════════════════════════════════════════════', 'green');
    log('           INDY NEXUS ADMIN CONSOLE', 'bright');
    log('═══════════════════════════════════════════════════════', 'green');
    console.log('');
}

// List all users
function listUsers(showAll = false) {
    const users = showAll 
        ? db.prepare('SELECT id, username, email, created_at, is_approved, is_active FROM users ORDER BY created_at DESC').all()
        : db.prepare('SELECT id, username, email, created_at, is_approved, is_active FROM users WHERE is_approved = 0 ORDER BY created_at DESC').all();
    
    if (users.length === 0) {
        log(showAll ? 'No users found.' : 'No pending users awaiting approval.', 'yellow');
        return;
    }
    
    log(`\n${showAll ? 'All Users:' : 'Users Awaiting Approval:'}`, 'cyan');
    log('─'.repeat(80), 'cyan');
    
    users.forEach(user => {
        const status = user.is_approved ? '✓ Approved' : '⏳ Pending';
        const statusColor = user.is_approved ? 'green' : 'yellow';
        const active = user.is_active ? 'Active' : 'Inactive';
        
        console.log(`ID: ${user.id} | Username: ${colors.bright}${user.username}${colors.reset}`);
        console.log(`    Email: ${user.email}`);
        console.log(`    Created: ${new Date(user.created_at).toLocaleString()}`);
        log(`    Status: ${status} | ${active}`, statusColor);
        console.log('');
    });
}

// Approve a user
function approveUser(userId, adminName = 'admin', notes = '') {
    try {
        const user = db.prepare('SELECT username FROM users WHERE id = ?').get(userId);
        
        if (!user) {
            log(`User with ID ${userId} not found.`, 'red');
            return false;
        }
        
        const result = db.prepare(`
            UPDATE users 
            SET is_approved = 1, 
                approved_at = CURRENT_TIMESTAMP,
                approved_by = ?,
                approval_notes = ?
            WHERE id = ?
        `).run(adminName, notes, userId);
        
        if (result.changes > 0) {
            log(`✓ User '${user.username}' (ID: ${userId}) has been approved!`, 'green');
            return true;
        } else {
            log(`Failed to approve user ID ${userId}`, 'red');
            return false;
        }
    } catch (error) {
        log(`Error approving user: ${error.message}`, 'red');
        return false;
    }
}

// Reject/Delete a user
function rejectUser(userId) {
    try {
        const user = db.prepare('SELECT username FROM users WHERE id = ?').get(userId);
        
        if (!user) {
            log(`User with ID ${userId} not found.`, 'red');
            return false;
        }
        
        const result = db.prepare('DELETE FROM users WHERE id = ?').run(userId);
        
        if (result.changes > 0) {
            log(`✗ User '${user.username}' (ID: ${userId}) has been rejected and removed.`, 'yellow');
            return true;
        } else {
            log(`Failed to reject user ID ${userId}`, 'red');
            return false;
        }
    } catch (error) {
        log(`Error rejecting user: ${error.message}`, 'red');
        return false;
    }
}

// Deactivate a user (soft delete)
function deactivateUser(userId) {
    try {
        const result = db.prepare('UPDATE users SET is_active = 0 WHERE id = ?').run(userId);
        
        if (result.changes > 0) {
            log(`User ID ${userId} has been deactivated.`, 'yellow');
            return true;
        } else {
            log(`Failed to deactivate user ID ${userId}`, 'red');
            return false;
        }
    } catch (error) {
        log(`Error deactivating user: ${error.message}`, 'red');
        return false;
    }
}

// View detailed user info
function viewUser(userId) {
    try {
        const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
        
        if (!user) {
            log(`User with ID ${userId} not found.`, 'red');
            return;
        }
        
        log('\nUser Details:', 'cyan');
        log('─'.repeat(40), 'cyan');
        console.log(`ID: ${user.id}`);
        console.log(`Username: ${colors.bright}${user.username}${colors.reset}`);
        console.log(`Email: ${user.email}`);
        console.log(`Created: ${new Date(user.created_at).toLocaleString()}`);
        console.log(`Last Login: ${user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}`);
        console.log(`Failed Attempts: ${user.failed_attempts}`);
        console.log(`Active: ${user.is_active ? 'Yes' : 'No'}`);
        console.log(`Approved: ${user.is_approved ? 'Yes' : 'No'}`);
        
        if (user.is_approved) {
            console.log(`Approved By: ${user.approved_by || 'Unknown'}`);
            console.log(`Approved At: ${user.approved_at ? new Date(user.approved_at).toLocaleString() : 'Unknown'}`);
            console.log(`Approval Notes: ${user.approval_notes || 'None'}`);
        }
        
        // Check for recent sessions
        const sessions = db.prepare('SELECT * FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 5').all(userId);
        if (sessions.length > 0) {
            log('\nRecent Sessions:', 'cyan');
            sessions.forEach(session => {
                console.log(`  - ${new Date(session.created_at).toLocaleString()} from ${session.ip_address}`);
            });
        }
    } catch (error) {
        log(`Error viewing user: ${error.message}`, 'red');
    }
}

// Quick approve all pending users (use with caution!)
async function approveAllPending() {
    const pending = db.prepare('SELECT id, username FROM users WHERE is_approved = 0').all();
    
    if (pending.length === 0) {
        log('No pending users to approve.', 'yellow');
        return;
    }
    
    log(`\n⚠️  WARNING: This will approve ${pending.length} pending users!`, 'yellow');
    const confirm = await prompt('Are you sure? (yes/no): ');
    
    if (confirm.toLowerCase() !== 'yes') {
        log('Cancelled.', 'yellow');
        return;
    }
    
    const adminName = await prompt('Enter admin name for approval records: ');
    
    pending.forEach(user => {
        approveUser(user.id, adminName, 'Bulk approval');
    });
    
    log(`\n✓ Approved ${pending.length} users.`, 'green');
}

// Show statistics
function showStats() {
    const stats = db.prepare(`
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN is_approved = 1 THEN 1 ELSE 0 END) as approved,
            SUM(CASE WHEN is_approved = 0 THEN 1 ELSE 0 END) as pending,
            SUM(CASE WHEN is_active = 0 THEN 1 ELSE 0 END) as inactive
        FROM users
    `).get();
    
    log('\nSystem Statistics:', 'cyan');
    log('─'.repeat(40), 'cyan');
    console.log(`Total Users: ${stats.total}`);
    console.log(`Approved: ${stats.approved}`);
    console.log(`Pending Approval: ${stats.pending}`);
    console.log(`Inactive: ${stats.inactive}`);
    
    // Recent activity
    const recentRegs = db.prepare(`
        SELECT COUNT(*) as count 
        FROM users 
        WHERE datetime(created_at) > datetime('now', '-7 days')
    `).get();
    
    console.log(`Registrations (last 7 days): ${recentRegs.count}`);
}

// Main menu
async function mainMenu() {
    showHeader();
    
    log('Commands:', 'cyan');
    console.log('1. List pending users');
    console.log('2. List all users');
    console.log('3. Approve user');
    console.log('4. Reject user');
    console.log('5. View user details');
    console.log('6. Deactivate user');
    console.log('7. Approve all pending');
    console.log('8. Show statistics');
    console.log('9. Exit');
    console.log('');
    
    const choice = await prompt('Enter choice (1-9): ');
    
    switch(choice) {
        case '1':
            listUsers(false);
            break;
            
        case '2':
            listUsers(true);
            break;
            
        case '3':
            listUsers(false);
            const approveId = await prompt('\nEnter user ID to approve: ');
            if (approveId) {
                const notes = await prompt('Approval notes (optional): ');
                const adminName = await prompt('Your name (for records): ') || 'admin';
                approveUser(parseInt(approveId), adminName, notes);
            }
            break;
            
        case '4':
            listUsers(false);
            const rejectId = await prompt('\nEnter user ID to reject: ');
            if (rejectId) {
                const confirmReject = await prompt('Are you sure? This will delete the user. (yes/no): ');
                if (confirmReject.toLowerCase() === 'yes') {
                    rejectUser(parseInt(rejectId));
                }
            }
            break;
            
        case '5':
            const viewId = await prompt('Enter user ID to view: ');
            if (viewId) {
                viewUser(parseInt(viewId));
            }
            break;
            
        case '6':
            const deactivateId = await prompt('Enter user ID to deactivate: ');
            if (deactivateId) {
                deactivateUser(parseInt(deactivateId));
            }
            break;
            
        case '7':
            await approveAllPending();
            break;
            
        case '8':
            showStats();
            break;
            
        case '9':
            log('\nGoodbye!', 'green');
            rl.close();
            process.exit(0);
            break;
            
        default:
            log('Invalid choice!', 'red');
    }
    
    console.log('');
    await prompt('Press Enter to continue...');
    mainMenu();
}

// Handle command line arguments for quick actions
const args = process.argv.slice(2);

if (args.length > 0) {
    const command = args[0].toLowerCase();
    
    switch(command) {
        case 'list':
            showHeader();
            listUsers(false);
            process.exit(0);
            break;
            
        case 'approve':
            if (args[1]) {
                showHeader();
                const userId = parseInt(args[1]);
                const adminName = args[2] || 'admin';
                const notes = args[3] || '';
                approveUser(userId, adminName, notes);
            } else {
                console.log('Usage: node admin.js approve <user_id> [admin_name] [notes]');
            }
            process.exit(0);
            break;
            
        case 'reject':
            if (args[1]) {
                showHeader();
                rejectUser(parseInt(args[1]));
            } else {
                console.log('Usage: node admin.js reject <user_id>');
            }
            process.exit(0);
            break;
            
        case 'stats':
            showHeader();
            showStats();
            process.exit(0);
            break;
            
        case 'help':
            console.log('Indy Nexus Admin Tool');
            console.log('');
            console.log('Usage:');
            console.log('  node admin.js              - Interactive mode');
            console.log('  node admin.js list         - List pending users');
            console.log('  node admin.js approve <id> [admin] [notes] - Approve user');
            console.log('  node admin.js reject <id>  - Reject user');
            console.log('  node admin.js stats        - Show statistics');
            process.exit(0);
            break;
            
        default:
            console.log('Unknown command. Use "node admin.js help" for usage.');
            process.exit(1);
    }
} else {
    // Start interactive mode
    mainMenu();
}