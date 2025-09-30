# Simple PowerShell Web Server for indy.nexus
# Serves static files on port 46228

$port = 46228
$root = Get-Location

Write-Host "Starting web server for indy.nexus..." -ForegroundColor Green
Write-Host "Server root: $root" -ForegroundColor Cyan
Write-Host "Access the site at: http://localhost:$port" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Gray
Write-Host ""

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$port/")
$listener.Prefixes.Add("http://127.0.0.1:$port/")
$listener.Start()

Write-Host "Server is running on port $port..." -ForegroundColor Green

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        $requestUrl = $request.Url.LocalPath
        Write-Host "Request: $requestUrl" -ForegroundColor Cyan
        
        # Default to index.html for root requests
        if ($requestUrl -eq "/") {
            $requestUrl = "/index.html"
        }
        
        # Build the file path
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
            
            # Read and send the file
            $buffer = [System.IO.File]::ReadAllBytes($filePath)
            $response.ContentType = $contentType
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
            $response.StatusCode = 200
            Write-Host "  -> 200 OK ($contentType)" -ForegroundColor Green
        }
        else {
            # File not found
            $response.StatusCode = 404
            $errorMessage = "<h1>404 - File Not Found</h1><p>The requested file was not found.</p>"
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($errorMessage)
            $response.ContentType = "text/html"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
            Write-Host "  -> 404 Not Found" -ForegroundColor Red
        }
        
        $response.Close()
    }
}
finally {
    $listener.Stop()
    Write-Host "Server stopped." -ForegroundColor Yellow
}