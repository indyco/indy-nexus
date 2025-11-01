# Indy Nexus Development Server Wrapper for Windows
# Simple wrapper that uses the unified server configuration

param(
    [int]$Port = 3000,
    [ValidateSet("basic", "enhanced")]
    [string]$SecurityPreset = "basic",
    [switch]$SkipInstall,
    [switch]$OpenBrowser,
    [switch]$Production
)

$ErrorActionPreference = "Stop"

# Colors for output
function Write-ColorHost($message, $color = "White") {
    Write-Host $message -ForegroundColor $color
}

# Banner
Clear-Host
Write-ColorHost "═══════════════════════════════════════════════════════" "Green"
Write-ColorHost "         INDY NEXUS UNIFIED DEVELOPMENT SERVER         " "Cyan"
Write-ColorHost "═══════════════════════════════════════════════════════" "Green"
Write-ColorHost ""

# Check for Node.js
Write-ColorHost "[1/4] Checking prerequisites..." "Yellow"
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
    Write-ColorHost "[2/4] Checking dependencies..." "Yellow"
    
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
    Write-ColorHost "[2/4] Skipping dependency installation" "Gray"
}

# Install cross-env if not present
if (-not (Test-Path "node_modules/cross-env")) {
    Write-ColorHost "  Installing cross-env for cross-platform support..." "Cyan"
    npm install --save-dev cross-env
}

# Setup environment file
Write-ColorHost "[3/4] Setting up environment..." "Yellow"

if (-not (Test-Path ".env")) {
    Write-ColorHost "  Creating .env file from .env.example..." "Cyan"
    
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        
        # Generate a secure JWT secret if the placeholder is present
        $envContent = Get-Content ".env"
        if ($envContent -match "JWT_SECRET=your") {
            $jwtSecret = -join ((1..64) | ForEach {'{0:X}' -f (Get-Random -Max 256)})
            $envContent = $envContent -replace "JWT_SECRET=.*", "JWT_SECRET=$jwtSecret"
            Set-Content -Path ".env" -Value $envContent
            Write-ColorHost "  ✓ Generated secure JWT_SECRET" "Green"
        }
        
        Write-ColorHost "  ✓ Created .env file" "Green"
    } else {
        Write-ColorHost "  ⚠ .env.example not found, creating minimal .env" "Yellow"
        
        $jwtSecret = -join ((1..64) | ForEach {'{0:X}' -f (Get-Random -Max 256)})
        $envContent = @"
NODE_ENV=$(if ($Production) { 'production' } else { 'development' })
SECURITY_PRESET=$SecurityPreset
PORT=$Port
JWT_SECRET=$jwtSecret
DATABASE_PATH=./users.db
"@
        Set-Content -Path ".env" -Value $envContent
        Write-ColorHost "  ✓ Created minimal .env file" "Green"
    }
} else {
    Write-ColorHost "  ✓ Using existing .env file" "Green"
}

# Set environment variables
$env:NODE_ENV = if ($Production) { 'production' } else { 'development' }
$env:SECURITY_PRESET = $SecurityPreset
$env:PORT = $Port

# Start the server
Write-ColorHost "[4/4] Starting server..." "Yellow"
Write-ColorHost ""
Write-ColorHost "Configuration:" "Cyan"
Write-ColorHost "  Environment: $($env:NODE_ENV)" "White"
Write-ColorHost "  Security Preset: $SecurityPreset" "White"
Write-ColorHost "  Port: $Port" "White"
Write-ColorHost ""

if ($OpenBrowser) {
    Start-Sleep -Seconds 2
    Start-Process "http://localhost:$Port"
}

# Run the server
if ($Production) {
    Write-ColorHost "Starting in PRODUCTION mode with enhanced security..." "Yellow"
    npm run start:enhanced
} else {
    Write-ColorHost "Starting in DEVELOPMENT mode..." "Yellow"
    if ($SecurityPreset -eq "enhanced") {
        npm run dev:enhanced
    } else {
        npm run dev
    }
}