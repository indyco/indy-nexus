# Indy Nexus Local Development Server with Full Authentication Backend
# Serves both static files and runs the Node.js backend for Windows development

param(
    [switch]$SkipInstall,
    [switch]$Production,
    [switch]$Enhanced,
    [switch]$CreateAdmin,
    [switch]$OpenBrowser
)

$ErrorActionPreference = "Stop"

# Configuration
$frontendPort = 46228
$backendPort = 46228
$root = Get-Location

# Colors for output
function Write-ColorHost($message, $color = "White") {
    Write-Host $message -ForegroundColor $color
}

# Banner
Clear-Host
Write-ColorHost "═══════════════════════════════════════════════════════" "Green"
Write-ColorHost "           INDY NEXUS LOCAL DEVELOPMENT SERVER         " "Cyan"
Write-ColorHost "═══════════════════════════════════════════════════════" "Green"
Write-ColorHost ""

# Check for Node.js
Write-ColorHost "[1/6] Checking prerequisites..." "Yellow"
try {
    $nodeVersion = node --version 2>$null
    if ($nodeVersion) {
        Write-ColorHost "  ✓ Node.js found: $nodeVersion" "Green"
    } else {
        throw "Node.js not found"
    }
} catch {
    Write-ColorHost "  ✗ Node.js is not installed!" "Red"
    Write-ColorHost "    Please install Node.js from: https://nodejs.org/" "Yellow"
    Write-ColorHost "    Recommended: Node.js v20 LTS" "Yellow"
    exit 1
}

# Check for npm
try {
    $npmVersion = npm --version 2>$null
    if ($npmVersion) {
        Write-ColorHost "  ✓ npm found: v$npmVersion" "Green"
    }
} catch {
    Write-ColorHost "  ✗ npm not found!" "Red"
    exit 1
}

# Install dependencies if needed
if (-not $SkipInstall) {
    Write-ColorHost "[2/6] Installing dependencies..." "Yellow"
    
    if (-not (Test-Path "node_modules")) {
        Write-ColorHost "  Installing npm packages..." "Cyan"
        npm install
        if ($LASTEXITCODE -ne 0) {
            Write-ColorHost "  ✗ Failed to install dependencies" "Red"
            exit 1
        }
        Write-ColorHost "  ✓ Dependencies installed" "Green"
    } else {
        Write-ColorHost "  ✓ Dependencies already installed (use -SkipInstall to skip check)" "Green"
    }
} else {
    Write-ColorHost "[2/6] Skipping dependency installation" "Gray"
}

# Setup environment file
Write-ColorHost "[3/6] Setting up environment..." "Yellow"

if (-not (Test-Path ".env")) {
    Write-ColorHost "  Creating .env file..." "Cyan"
    
    # Generate secure JWT secret
    $jwtSecret = -join ((1..64) | ForEach {'{0:X}' -f (Get-Random -Max 256)})
    
    $envContent = @"
# Server Configuration
PORT=$backendPort
NODE_ENV=$(if ($Production) { 'production' } else { 'development' })

# Security
JWT_SECRET=$jwtSecret

# Database
DATABASE_PATH=./users.db

# Authentication Settings
REQUIRE_USER_APPROVAL=false
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=30
SESSION_DURATION_HOURS=24

# Rate Limiting (relaxed for development)
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=$(if ($Production) { '5' } else { '100' })

# CORS
ALLOWED_ORIGINS=http://localhost:$frontendPort,http://127.0.0.1:$frontendPort,http://localhost:$backendPort
"@
    
    Set-Content -Path ".env" -Value $envContent
    Write-ColorHost "  ✓ Created .env file with secure JWT_SECRET" "Green"
} else {
    Write-ColorHost "  ✓ Using existing .env file" "Green"
}

# Create admin user if requested
if ($CreateAdmin) {
    Write-ColorHost "[4/6] Creating admin user..." "Yellow"
    
    $adminScript = @'
require('dotenv').config();
const Database = require('better-sqlite3');
const argon2 = require('argon2');

const db = new Database('./users.db');

async function createAdmin() {
    try {
        // Check if any users exist
        const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
        if (userCount && userCount.count > 0) {
            console.log('  ⚠ Users already exist, skipping admin creation');
            return;
        }
        
        // Check if is_approved column exists
        const columns = db.prepare("PRAGMA table_info(users)").all();
        const hasApprovalColumn = columns.some(col => col.name === 'is_approved');
        
        const username = 'admin';
        const email = 'admin@localhost';
        const password = 'AdminPassAdminPass2024!@#$';
        
        const passwordHash = await argon2.hash(password, {
            type: argon2.argon2id,
            memoryCost: 65536,
            timeCost: 3,
            parallelism: 4
        });
        
        // Insert with or without is_approved based on schema
        if (hasApprovalColumn) {
            db.prepare(`
                INSERT INTO users (username, email, password_hash, is_approved)
                VALUES (?, ?, ?, 1)
            `).run(username, email, passwordHash);
        } else {
            // Old schema without approval system
            db.prepare(`
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
            `).run(username, email, passwordHash);
        }
        
        console.log('  ✓ Admin user created:');
        console.log('    Username: admin');
        console.log('    Password: AdminPassAdminPass2024!@#$');
        console.log('    ⚠ CHANGE THIS PASSWORD AFTER FIRST LOGIN!');
    } catch (err) {
        console.log('  ⚠ Admin creation skipped: ' + err.message);
    }
    db.close();
}

createAdmin();
'@
    
    Set-Content -Path "create-admin-temp.js" -Value $adminScript
    node create-admin-temp.js
    Remove-Item "create-admin-temp.js" -Force
} else {
    Write-ColorHost "[4/6] Skipping admin user creation (use -CreateAdmin to create)" "Gray"
}

# Start the backend server
Write-ColorHost "[5/6] Starting backend server..." "Yellow"

$serverFile = if ($Enhanced) { "server-enhanced.js" } else { "server.js" }
if (-not (Test-Path $serverFile)) {
    Write-ColorHost "  ✗ $serverFile not found!" "Red"
    exit 1
}

# Start Node.js backend in background
$backendJob = Start-Job -ScriptBlock {
    param($path, $server)
    Set-Location $path
    node $server
} -ArgumentList $root, $serverFile

Write-ColorHost "  ✓ Backend server started (Job ID: $($backendJob.Id))" "Green"
Write-ColorHost "  Backend API: http://localhost:$backendPort" "Cyan"

# Wait a moment for backend to initialize
Start-Sleep -Seconds 2

# Check if backend is responding
try {
    $health = Invoke-RestMethod -Uri "http://localhost:$backendPort/api/health" -Method Get -ErrorAction SilentlyContinue
    Write-ColorHost "  ✓ Backend health check passed" "Green"
} catch {
    Write-ColorHost "  ⚠ Backend may still be starting..." "Yellow"
}

# Start frontend server
Write-ColorHost "[6/6] Starting frontend server..." "Yellow"

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$frontendPort/")
$listener.Prefixes.Add("http://127.0.0.1:$frontendPort/")

try {
    $listener.Start()
    Write-ColorHost "  ✓ Frontend server started" "Green"
} catch {
    Write-ColorHost "  ✗ Failed to start frontend server on port $frontendPort" "Red"
    Write-ColorHost "    Port might be in use. Check with: netstat -an | findstr :$frontendPort" "Yellow"
    Stop-Job $backendJob
    Remove-Job $backendJob
    exit 1
}

Write-ColorHost ""
Write-ColorHost "═══════════════════════════════════════════════════════" "Green"
Write-ColorHost "✓ Development Server Running!" "Green"
Write-ColorHost "═══════════════════════════════════════════════════════" "Green"
Write-ColorHost ""
Write-ColorHost "📍 Access Points:" "Cyan"
Write-ColorHost "   Main Site:    http://localhost:$frontendPort" "White"
Write-ColorHost "   Login:        http://localhost:$frontendPort/login.html" "White"
Write-ColorHost "   Register:     http://localhost:$frontendPort/register.html" "White"
Write-ColorHost "   API Backend:  http://localhost:$backendPort" "White"
Write-ColorHost ""
Write-ColorHost "🛠 Admin Tools:" "Cyan"
Write-ColorHost "   Admin CLI:    node admin.js" "White"
Write-ColorHost ""
Write-ColorHost "📊 Monitoring:" "Cyan"
Write-ColorHost "   Backend Logs: Get-Job $($backendJob.Id) | Receive-Job" "White"
Write-ColorHost "   Health Check: Invoke-RestMethod http://localhost:$backendPort/api/health" "White"
Write-ColorHost ""
Write-ColorHost "Press Ctrl+C to stop all servers" "Yellow"
Write-ColorHost ""

# Open browser if requested
if ($OpenBrowser) {
    Start-Process "http://localhost:$frontendPort"
}

# Main server loop
try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        $requestUrl = $request.Url.LocalPath
        $timestamp = Get-Date -Format "HH:mm:ss"
        
        # API proxy - forward /api/* requests to backend
        if ($requestUrl -like "/api/*") {
            try {
                # Proxy to backend
                $backendUrl = "http://localhost:$backendPort$requestUrl"
                $method = $request.HttpMethod
                
                Write-Host "[$timestamp] API: $method $requestUrl -> Backend" -ForegroundColor Magenta
                
                # Read request body if present
                $requestBody = $null
                if ($request.HasEntityBody) {
                    $reader = New-Object System.IO.StreamReader($request.InputStream)
                    $requestBody = $reader.ReadToEnd()
                    $reader.Close()
                }
                
                # Create backend request
                $webRequest = [System.Net.HttpWebRequest]::Create($backendUrl)
                $webRequest.Method = $method
                $webRequest.ContentType = $request.ContentType
                
                # Copy headers
                foreach ($header in $request.Headers.AllKeys) {
                    if ($header -notin @("Host", "Content-Length", "Connection")) {
                        try {
                            $webRequest.Headers.Add($header, $request.Headers[$header])
                        } catch {}
                    }
                }
                
                # Send request body if present
                if ($requestBody) {
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($requestBody)
                    $webRequest.ContentLength = $bytes.Length
                    $stream = $webRequest.GetRequestStream()
                    $stream.Write($bytes, 0, $bytes.Length)
                    $stream.Close()
                }
                
                # Get backend response
                try {
                    $backendResponse = $webRequest.GetResponse()
                    $reader = New-Object System.IO.StreamReader($backendResponse.GetResponseStream())
                    $responseContent = $reader.ReadToEnd()
                    $reader.Close()
                    
                    # Forward response
                    $response.StatusCode = [int]$backendResponse.StatusCode
                    $response.ContentType = $backendResponse.ContentType
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseContent)
                    $response.ContentLength64 = $buffer.Length
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                    
                    Write-Host "  -> $([int]$backendResponse.StatusCode) OK" -ForegroundColor Green
                } catch [System.Net.WebException] {
                    $errorResponse = $_.Exception.Response
                    if ($errorResponse) {
                        $response.StatusCode = [int]$errorResponse.StatusCode
                        Write-Host "  -> $([int]$errorResponse.StatusCode)" -ForegroundColor Red
                    } else {
                        $response.StatusCode = 502
                        Write-Host "  -> 502 Bad Gateway" -ForegroundColor Red
                    }
                }
            } catch {
                Write-Host "  -> Proxy Error: $_" -ForegroundColor Red
                $response.StatusCode = 500
            }
        } else {
            # Serve static files
            Write-Host "[$timestamp] GET $requestUrl" -ForegroundColor Cyan
            
            # Default to index.html for root
            if ($requestUrl -eq "/") {
                $requestUrl = "/index.html"
            }
            
            # Build file path
            $filePath = Join-Path $root $requestUrl.TrimStart('/')
            
            if (Test-Path $filePath -PathType Leaf) {
                # Determine content type
                $extension = [System.IO.Path]::GetExtension($filePath)
                $contentType = switch ($extension) {
                    ".html" { "text/html" }
                    ".css" { "text/css" }
                    ".js" { "application/javascript" }
                    ".json" { "application/json" }
                    ".png" { "image/png" }
                    ".jpg" { "image/jpeg" }
                    ".jpeg" { "image/jpeg" }
                    ".gif" { "image/gif" }
                    ".svg" { "image/svg+xml" }
                    ".ico" { "image/x-icon" }
                    default { "application/octet-stream" }
                }
                
                # Send file
                $buffer = [System.IO.File]::ReadAllBytes($filePath)
                $response.ContentType = $contentType
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
                $response.StatusCode = 200
                Write-Host "  -> 200 OK" -ForegroundColor Green
            } else {
                # 404 Not Found
                $response.StatusCode = 404
                $errorHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>404 - Not Found</title>
    <style>
        body { background: #000; color: #0f0; font-family: monospace; padding: 50px; }
        h1 { color: #0f0; }
    </style>
</head>
<body>
    <h1>404 - File Not Found</h1>
    <p>The requested file was not found: $requestUrl</p>
    <p><a href="/" style="color: #0f0;">Return to Home</a></p>
</body>
</html>
"@
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($errorHtml)
                $response.ContentType = "text/html"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
                Write-Host "  -> 404 Not Found" -ForegroundColor Red
            }
        }
        
        $response.Close()
    }
} catch {
    Write-ColorHost "Server error: $_" "Red"
} finally {
    Write-ColorHost ""
    Write-ColorHost "Shutting down servers..." "Yellow"
    
    # Stop frontend
    if ($listener) {
        $listener.Stop()
        Write-ColorHost "  ✓ Frontend server stopped" "Green"
    }
    
    # Stop backend
    if ($backendJob) {
        Stop-Job $backendJob
        Remove-Job $backendJob -Force
        Write-ColorHost "  ✓ Backend server stopped" "Green"
    }
    
    Write-ColorHost ""
    Write-ColorHost "All servers stopped. Goodbye!" "Cyan"
}
