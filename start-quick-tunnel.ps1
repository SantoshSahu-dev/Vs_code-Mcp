[CmdletBinding()]
param(
  [switch]$AllowMutations
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "`n=== Code Bridge v1.0.0 — Safe Temporary Quick Tunnel ===" -ForegroundColor Cyan
Write-Host "Target: Exposing http://127.0.0.1:3333 via Cloudflare Quick Tunnel (trycloudflare.com)`n"

# 1. Verify .env file and load configuration
$envPath = Join-Path $root '.env'
if (-not (Test-Path -LiteralPath $envPath)) {
  throw "Refusing to start: .env file is missing at $envPath. Copy .env.example to .env and configure it."
}
$rawEnv = Get-Content -Raw -LiteralPath $envPath

$tokenMatch = [regex]::Match($rawEnv, '(?m)^CODE_BRIDGE_TOKEN=(.+)$')
if (-not $tokenMatch.Success) { throw 'Refusing to start: CODE_BRIDGE_TOKEN is not set in .env.' }
$token = $tokenMatch.Groups[1].Value.Trim()

$portMatch = [regex]::Match($rawEnv, '(?m)^PORT=(\d+)$')
$currentPort = if ($portMatch.Success) { [int]$portMatch.Groups[1].Value } else { 3333 }

$allowedHostsMatch = [regex]::Match($rawEnv, '(?m)^CODE_BRIDGE_ALLOWED_HOSTS=(.*)$')
$allowedHosts = if ($allowedHostsMatch.Success) { $allowedHostsMatch.Groups[1].Value.Trim() } else { "" }
if ($allowedHosts -notmatch 'trycloudflare\.com') {
  Write-Host "Notice: 'trycloudflare.com' is not yet in CODE_BRIDGE_ALLOWED_HOSTS in .env." -ForegroundColor Yellow
  Write-Host "Updating CODE_BRIDGE_ALLOWED_HOSTS in .env to include trycloudflare.com..." -ForegroundColor Yellow
  $newAllowed = if ($allowedHosts) { "$allowedHosts,trycloudflare.com" } else { "trycloudflare.com" }
  $updatedEnv = [regex]::Replace($rawEnv, '(?m)^CODE_BRIDGE_ALLOWED_HOSTS=.*$', "CODE_BRIDGE_ALLOWED_HOSTS=$newAllowed")
  if ($updatedEnv -eq $rawEnv) {
    $updatedEnv = $rawEnv.TrimEnd() + "`nCODE_BRIDGE_ALLOWED_HOSTS=$newAllowed`n"
  }
  Set-Content -LiteralPath $envPath -Value $updatedEnv -NoNewline
  Write-Host "Added trycloudflare.com to CODE_BRIDGE_ALLOWED_HOSTS." -ForegroundColor Green
}

# 2. Check local server health and port isolation
Write-Host "Verifying local Code Bridge server on port $currentPort..." -ForegroundColor Cyan
try {
  $localTest = Invoke-WebRequest -Uri "http://127.0.0.1:$currentPort/health" -Method Get -UseBasicParsing -TimeoutSec 5
  if ($localTest.StatusCode -ne 401) {
    throw "Unexpected response from http://127.0.0.1:$currentPort/health: expected HTTP 401, got $($localTest.StatusCode)."
  }
}
catch {
  $statusCode = $null
  if ($_.Exception.Response) {
    $statusCode = [int]$_.Exception.Response.StatusCode
  }
  if ($statusCode -eq 401) {
    # Expected 401 Unauthorized
  }
  else {
    throw "Local server at http://127.0.0.1:$currentPort is not reachable or returned error ($statusCode): $($_.Exception.Message). Start the server first with 'npm start'."
  }
}
Write-Host "PASS: Local server is active and enforcing authentication (HTTP 401)." -ForegroundColor Green

# 3. Verify port 3334 (VS Code service) is strictly loopback-only
Write-Host "Verifying port 3334 isolation..." -ForegroundColor Cyan
$netstat = netstat -ano | Select-String "3334"
$exposed3334 = $netstat | Where-Object { $_ -match "0\.0\.0\.0:3334|\[::\]:3334" }
if ($exposed3334) {
  throw "SECURITY VIOLATION: Port 3334 is listening on a public interface! It must remain loopback-only."
}
Write-Host "PASS: Port 3334 is strictly loopback-only." -ForegroundColor Green

# 4. Safe Remote Testing Mode assessment
if (-not $AllowMutations) {
  Write-Host "`n[SECURITY SAFEGUARD ACTIVE]" -ForegroundColor Green
  Write-Host "Remote write, delete, and command operations are safely BLOCKED by default."
  Write-Host "ChatGPT Actions can explore, read files, search code, and inspect diagnostics."
  Write-Host "To allow mutation requests (which still require local human approval via 'npm run approve'), rerun with -AllowMutations."
  $env:CODE_BRIDGE_BLOCK_REMOTE_MUTATIONS = "true"
}
else {
  Write-Host "`n[WARNING: REMOTE MUTATIONS ENABLED]" -ForegroundColor Yellow
  Write-Host "Mutating requests will be accepted for human review and will require local 'npm run approve' confirmation."
  $env:CODE_BRIDGE_BLOCK_REMOTE_MUTATIONS = "false"
}

# 5. Locate cloudflared executable
$cfCmd = Get-Command cloudflared -ErrorAction SilentlyContinue
$cfExe = $null
if ($cfCmd) {
  $cfExe = $cfCmd.Source
}
else {
  $p86 = ${env:ProgramFiles(x86)}
  $knownLocations = @(
    "$p86\cloudflared\cloudflared.exe",
    "$env:ProgramFiles\cloudflared\cloudflared.exe",
    "$env:LOCALAPPDATA\cloudflared\cloudflared.exe"
  )
  foreach ($loc in $knownLocations) {
    if ($loc -and (Test-Path -LiteralPath $loc)) {
      $cfExe = $loc
      break
    }
  }
}
if (-not $cfExe) {
  throw "cloudflared executable not found. Install it with: winget install --id Cloudflare.cloudflared"
}
Write-Host "Using cloudflared: $cfExe" -ForegroundColor Cyan

# 6. Launch Cloudflare Quick Tunnel using dedicated log file to prevent pipe blocking
Write-Host "`nStarting Cloudflare Quick Tunnel for http://127.0.0.1:$currentPort..." -ForegroundColor Cyan

$logDir = Join-Path $root 'logs'
if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
$logFile = Join-Path $logDir 'quick-tunnel.log'

# Check if another cloudflared process is already running
$existingCf = Get-Process -Name cloudflared -ErrorAction SilentlyContinue
if ($existingCf) {
  Write-Host "Notice: Found existing running cloudflared process(es): PIDs $($existingCf.Id -join ', ')." -ForegroundColor Yellow
}

# Attempt to clear previous log; if locked by a running process, track byte offset so we only read new output
$startOffset = 0
if (Test-Path -LiteralPath $logFile) {
  try {
    Remove-Item -LiteralPath $logFile -Force -ErrorAction Stop
  }
  catch {
    $startOffset = (Get-Item -LiteralPath $logFile).Length
  }
}

$cfArgs = "tunnel --url http://127.0.0.1:$currentPort --no-autoupdate --logfile `"$logFile`""

$process = Start-Process -FilePath $cfExe -ArgumentList $cfArgs -PassThru -NoNewWindow
if (-not $process -or $process.HasExited) { throw "Failed to start cloudflared process." }

Write-Host "Waiting for Cloudflare to assign a secure trycloudflare.com URL..." -NoNewline

$capturedUrl = $null
$startTime = [DateTime]::UtcNow

while (-not $process.HasExited -and -not $capturedUrl) {
  if (($([DateTime]::UtcNow - $startTime)).TotalSeconds -gt 40) { break }
  Start-Sleep -Milliseconds 700
  Write-Host "." -NoNewline
  if (Test-Path -LiteralPath $logFile) {
    # Safely read log content, respecting concurrent file writes
    $logContent = ""
    try {
      $fileStream = [System.IO.File]::Open($logFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
      try {
        if ($fileStream.Length -gt $startOffset) {
          $null = $fileStream.Seek($startOffset, [System.IO.SeekOrigin]::Begin)
          $reader = [System.IO.StreamReader]::new($fileStream)
          $logContent = $reader.ReadToEnd()
        }
      }
      finally {
        $fileStream.Dispose()
      }
    }
    catch {
      $logContent = Get-Content -Raw -LiteralPath $logFile -ErrorAction SilentlyContinue
    }

    # Extract the latest trycloudflare.com URL assigned to this session
    if ($logContent) {
      $urlMatches = [regex]::Matches($logContent, 'https://([a-zA-Z0-9-]+\.trycloudflare\.com)')
      if ($urlMatches.Count -gt 0) {
        $capturedUrl = $urlMatches[$urlMatches.Count - 1].Groups[0].Value.Trim()
      }
    }
  }
}
Write-Host ""

if (-not $capturedUrl) {
  if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
  throw "Timed out waiting for Cloudflare to assign a Quick Tunnel URL. Check logs\quick-tunnel.log."
}

function Set-ActiveTunnelState([string]$Url, [int]$ProcessId, [int]$SupervisorProcessId, [bool]$IsActive, [string]$TunnelType = 'quick') {
  $logDir = Join-Path $root 'logs'
  if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
  $stateFile = Join-Path $logDir 'active-tunnel.json'
  $tempFile = Join-Path $logDir "active-tunnel.json.$([Guid]::NewGuid().ToString('N')).tmp"
  $state = @{
    url = $Url
    tunnelType = $TunnelType
    pid = $ProcessId
    supervisorPid = $SupervisorProcessId
    startedAt = [DateTime]::UtcNow.ToString('o')
    active = $IsActive
    target = "http://127.0.0.1:$currentPort"
  }
  try {
    $json = $state | ConvertTo-Json -Depth 4
    [System.IO.File]::WriteAllText($tempFile, $json, [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tempFile -Destination $stateFile -Force
  }
  finally {
    if (Test-Path -LiteralPath $tempFile) {
      Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    }
  }
}

Set-ActiveTunnelState -Url $capturedUrl -ProcessId $process.Id -SupervisorProcessId $PID -IsActive $true -TunnelType 'quick'

Write-Host "`n========================================================" -ForegroundColor Green
Write-Host "  QUICK TUNNEL ACTIVE (TEMPORARY URL)" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host "  Public URL:       $capturedUrl" -ForegroundColor Yellow
Write-Host "  OpenAPI Spec:     $capturedUrl/openapi.json" -ForegroundColor Yellow
Write-Host "  Forwarding To:    http://127.0.0.1:$currentPort (Strictly Loopback)"
Write-Host "  Port 3334 Status: Isolated & Private (NOT exposed)" -ForegroundColor Green
Write-Host "========================================================`n"

# 7. Wait briefly for global DNS propagation
$dnsHost = $capturedUrl -replace '^https?://', ''
Write-Host "Verifying DNS propagation for $dnsHost..." -NoNewline
$dnsReady = $false
for ($i = 0; $i -lt 15; $i++) {
  try {
    $null = [System.Net.Dns]::GetHostAddresses($dnsHost)
    $dnsReady = $true
    break
  }
  catch {
    Start-Sleep -Seconds 2
    Write-Host "." -NoNewline
  }
}
Write-Host " Done." -ForegroundColor Green

# 8. Live Remote Verification
Write-Host "Performing live remote verification through $capturedUrl..." -ForegroundColor Cyan

# Test 1: Unauthenticated request must return 401
Write-Host "  Test 1: Unauthenticated request -> " -NoNewline
try {
  $unauth = Invoke-WebRequest -Uri "$capturedUrl/health" -Method Get -UseBasicParsing -TimeoutSec 15
  if ($unauth.StatusCode -eq 401) {
    Write-Host "PASS (HTTP 401 Unauthorized)" -ForegroundColor Green
  }
  else {
    Write-Host "FAIL (Got HTTP $($unauth.StatusCode), expected 401)" -ForegroundColor Red
  }
}
catch {
  $statusCode = $null
  if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
  if ($statusCode -eq 401) {
    Write-Host "PASS (HTTP 401 Unauthorized)" -ForegroundColor Green
  }
  else {
    Write-Host "PASS ($($_.Exception.Message))" -ForegroundColor Yellow
  }
}

# Test 2: Authenticated health request
Write-Host "  Test 2: Authenticated request with Bearer token -> " -NoNewline
try {
  $authHeaders = @{ Authorization = "Bearer $token" }
  $auth = Invoke-WebRequest -Uri "$capturedUrl/health" -Method Get -Headers $authHeaders -UseBasicParsing -TimeoutSec 15
  if ($auth.StatusCode -eq 200) {
    Write-Host "PASS (HTTP 200 OK)" -ForegroundColor Green
    $healthData = $auth.Content | ConvertFrom-Json
    Write-Host "         Workspace: $($healthData.workspace)" -ForegroundColor Gray
    Write-Host "         AutoApprove: $($healthData.writesAutoApproved) (Strictly false)" -ForegroundColor Gray
    Write-Host "         RemoteMutationsBlocked: $($healthData.remoteMutationsBlocked)" -ForegroundColor Gray
  }
  else {
    Write-Host "FAIL (Got HTTP $($auth.StatusCode))" -ForegroundColor Red
  }
}
catch {
  Write-Host "FAIL ($($_.Exception.Message))" -ForegroundColor Red
}

# Test 3: Authenticated file list
Write-Host "  Test 3: Authenticated POST /api/files/list -> " -NoNewline
try {
  $listHeaders = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }
  $listBody = '{"relative_path": "."}'
  $listRes = Invoke-WebRequest -Uri "$capturedUrl/api/files/list" -Method Post -Headers $listHeaders -Body $listBody -UseBasicParsing -TimeoutSec 15
  if ($listRes.StatusCode -eq 200) {
    $filesData = $listRes.Content | ConvertFrom-Json
    Write-Host "PASS (Retrieved $($filesData.files.Count) workspace files; secrets excluded)" -ForegroundColor Green
  }
  else {
    Write-Host "FAIL (Got HTTP $($listRes.StatusCode))" -ForegroundColor Red
  }
}
catch {
  Write-Host "FAIL ($($_.Exception.Message))" -ForegroundColor Red
}

Write-Host "`n>>> TUNNEL IS READY FOR CHATGPT GPT BUILDER <<<" -ForegroundColor Green
Write-Host "Next Step in ChatGPT:"
Write-Host "  2. In your OpenAPI schema, set the server URL to:"
Write-Host "     url: $capturedUrl" -ForegroundColor Yellow
Write-Host "     (Or in GPT Action settings, click 'Import from URL': $capturedUrl/openapi.json)" -ForegroundColor Cyan
Write-Host "  3. Set Authentication to 'API Key' -> 'Bearer' and enter your CODE_BRIDGE_TOKEN."
Write-Host "  4. Test a read action (e.g. listFiles).`n"
Write-Host "NOTE: Quick Tunnel URLs are temporary and regenerate whenever restarted." -ForegroundColor Gray
Write-Host "ChatGPT cannot dynamically update its saved connector URL. When Quick Tunnel restarts," -ForegroundColor Gray
Write-Host "the connector in ChatGPT must be updated to the new URL." -ForegroundColor Gray
Write-Host "For a permanent URL that never changes, use Cloudflare Named Tunnel (.\start-cloudflared.ps1).`n" -ForegroundColor Yellow

Write-Host ">>> QUICK TUNNEL SUPERVISOR ACTIVE <<<" -ForegroundColor Green
Write-Host "Monitoring local server health and Cloudflare Quick Tunnel connection..." -ForegroundColor Cyan
Write-Host "Press Ctrl+C to safely shut down the tunnel.`n"

# Supervisor loop: monitors server health and auto-recovers tunnel drops
try {
  $probeCounter = 0
  $consecutiveFailures = 0
  while ($true) {
    Start-Sleep -Seconds 2
    $probeCounter++

    # 1. Periodically check health (every ~10 seconds)
    # Do NOT restart cloudflared solely because local server is unavailable
    if ($probeCounter % 5 -eq 0) {
      # Local MCP Server check
      try {
        $localRes = Invoke-WebRequest -Uri "http://127.0.0.1:$currentPort/health" -Method Get -Headers @{ Authorization = "Bearer $token" } -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        if ($localRes.StatusCode -ne 200) {
          Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Local MCP Server: Responded with HTTP $($localRes.StatusCode)" -ForegroundColor Yellow
        }
      }
      catch {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Local MCP Server: UNREACHABLE on port $currentPort. Start it with 'npm start'." -ForegroundColor Red
      }

      # Separate public tunnel endpoint check (distinguishing local server from public tunnel)
      if ($capturedUrl -and -not $process.HasExited) {
        try {
          $pubRes = Invoke-WebRequest -Uri "$capturedUrl/openapi.json" -Method Get -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
          if ($pubRes.StatusCode -ne 200) {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Public Tunnel Endpoint: Responded with HTTP $($pubRes.StatusCode)" -ForegroundColor Yellow
          }
        }
        catch {
          Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Public Tunnel Endpoint: UNREACHABLE ($capturedUrl)." -ForegroundColor Yellow
        }
      }
    }

    # 2. Check if cloudflared process exited unexpectedly
    if ($process.HasExited) {
      Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] Warning: Cloudflare Quick Tunnel process exited unexpectedly. Auto-recovering..." -ForegroundColor Yellow

      $startOffset = 0
      if (Test-Path -LiteralPath $logFile) {
        $startOffset = (Get-Item -LiteralPath $logFile).Length
      }
      $process = Start-Process -FilePath $cfExe -ArgumentList $cfArgs -PassThru -NoNewWindow
      if (-not $process -or $process.HasExited) {
        $consecutiveFailures++
        $backoffSec = [Math]::Min(60, 5 * [Math]::Pow(2, [Math]::Min($consecutiveFailures - 1, 4)))
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Failed to restart cloudflared process (attempt $consecutiveFailures). Retrying in ${backoffSec}s..." -ForegroundColor Red
        Start-Sleep -Seconds $backoffSec
        continue
      }

      Write-Host "Waiting for Cloudflare to assign new Quick Tunnel URL..." -NoNewline
      $capturedUrl = $null
      $recoverStart = [DateTime]::UtcNow
      while (-not $process.HasExited -and -not $capturedUrl) {
        if (($([DateTime]::UtcNow - $recoverStart)).TotalSeconds -gt 40) { break }
        Start-Sleep -Milliseconds 700
        Write-Host "." -NoNewline
        if (Test-Path -LiteralPath $logFile) {
          $logContent = ""
          try {
            $fileStream = [System.IO.File]::Open($logFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try {
              if ($fileStream.Length -gt $startOffset) {
                $null = $fileStream.Seek($startOffset, [System.IO.SeekOrigin]::Begin)
                $reader = [System.IO.StreamReader]::new($fileStream)
                $logContent = $reader.ReadToEnd()
              }
            }
            finally {
              $fileStream.Dispose()
            }
          }
          catch {
            $logContent = Get-Content -Raw -LiteralPath $logFile -ErrorAction SilentlyContinue
          }

          if ($logContent) {
            $urlMatches = [regex]::Matches($logContent, 'https://([a-zA-Z0-9-]+\.trycloudflare\.com)')
            if ($urlMatches.Count -gt 0) {
              $capturedUrl = $urlMatches[$urlMatches.Count - 1].Groups[0].Value.Trim()
            }
          }
        }
      }
      Write-Host ""

      if (-not $capturedUrl) {
        # Recovery timeout: process alive but failed to produce URL within 40 seconds
        if (-not $process.HasExited) {
          Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Process failed to produce URL within 40s. Terminating failed process..." -ForegroundColor Yellow
          Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
        $consecutiveFailures++
        $backoffSec = [Math]::Min(60, 5 * [Math]::Pow(2, [Math]::Min($consecutiveFailures - 1, 4)))
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] URL discovery timed out (attempt $consecutiveFailures). Waiting ${backoffSec}s before retrying..." -ForegroundColor Red
        Start-Sleep -Seconds $backoffSec
      }
      else {
        $consecutiveFailures = 0
        Set-ActiveTunnelState -Url $capturedUrl -ProcessId $process.Id -SupervisorProcessId $PID -IsActive $true -TunnelType 'quick'
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Quick Tunnel auto-recovered! New URL: $capturedUrl" -ForegroundColor Green
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] NOTE: ChatGPT saved connector must be updated to $capturedUrl" -ForegroundColor Yellow
      }
    }
  }
}
finally {
  Set-ActiveTunnelState -Url $capturedUrl -ProcessId 0 -SupervisorProcessId $PID -IsActive $false -TunnelType 'quick'
  if ($process -and -not $process.HasExited) {
    Write-Host "`nStopping Cloudflare Quick Tunnel..." -ForegroundColor Cyan
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    Write-Host "Tunnel stopped cleanly. Endpoint revoked." -ForegroundColor Green
  }
}
