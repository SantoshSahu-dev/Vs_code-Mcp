[CmdletBinding()]
param(
  [switch]$KeepRunning,
  [switch]$SkipTokenRotation
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
$results = [System.Collections.Generic.List[object]]::new()
function Pass([string]$Name) { $results.Add([pscustomobject]@{ Check=$Name; Result='PASS' }) }
function Fail([string]$Name, [object]$Reason) { $results.Add([pscustomobject]@{ Check=$Name; Result="FAIL: $Reason" }) }
function Require([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }

$serverProcess = $null
try {
  # Get-Command returns a CommandInfo object. Convert the existence check
  # explicitly so PowerShell never tries to bind that object to [bool].
  Require -Condition ($null -ne (Get-Command node -ErrorAction SilentlyContinue)) -Message 'Node.js 20+ is required.'
  Require -Condition ($null -ne (Get-Command npm -ErrorAction SilentlyContinue)) -Message 'npm is required.'
  Pass 'Node.js and npm found'

  $envPath = Join-Path $root '.env'
  Require (Test-Path -LiteralPath $envPath) '.env is missing. Copy .env.example and set CODE_BRIDGE_WORKSPACE first.'
  $rawEnv = Get-Content -Raw -LiteralPath $envPath
  $workspaceMatch = [regex]::Match($rawEnv, '(?m)^CODE_BRIDGE_WORKSPACE=(.+)$')
  Require $workspaceMatch.Success 'CODE_BRIDGE_WORKSPACE is missing.'
  $workspace = $workspaceMatch.Groups[1].Value.Trim().TrimEnd('>')
  Require (Test-Path -LiteralPath $workspace -PathType Container) "Configured workspace does not exist: $workspace"
  $workspace = (Resolve-Path -LiteralPath $workspace).Path
  Pass 'Configured workspace exists'

  if (-not $SkipTokenRotation) {
    $backupDir = Join-Path $root 'backups'
    New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
    $backup = Join-Path $backupDir ('.env.' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.bak')
    Copy-Item -LiteralPath $envPath -Destination $backup -ErrorAction Stop
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $newToken = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
    $rawEnv = [regex]::Replace($rawEnv, '(?m)^CODE_BRIDGE_WORKSPACE=.*$', "CODE_BRIDGE_WORKSPACE=$workspace")
    $rawEnv = [regex]::Replace($rawEnv, '(?m)^CODE_BRIDGE_TOKEN=.*$', "CODE_BRIDGE_TOKEN=$newToken")
    Set-Content -LiteralPath $envPath -Value $rawEnv -NoNewline
    # The extension prioritizes this user environment variable after VS Code restarts.
    [Environment]::SetEnvironmentVariable('CODE_BRIDGE_TOKEN', $newToken, 'User')
    $env:CODE_BRIDGE_TOKEN = $newToken
    # Keep the private Antigravity loopback connector synchronized if it exists.
    $antigravityConfig = Join-Path $HOME '.gemini\config\mcp_config.json'
    if (Test-Path -LiteralPath $antigravityConfig) {
      try {
        $ag = Get-Content -Raw -LiteralPath $antigravityConfig | ConvertFrom-Json
        if ($ag.mcpServers.'code-bridge') {
          $agBackup = "$antigravityConfig.code-bridge-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
          Copy-Item -LiteralPath $antigravityConfig -Destination $agBackup
          $ag.mcpServers.'code-bridge'.headers.'x-code-bridge-token' = $newToken
          [System.IO.File]::WriteAllText($antigravityConfig, (($ag | ConvertTo-Json -Depth 12) + [Environment]::NewLine), [System.Text.UTF8Encoding]::new($false))
        }
      } catch { throw "Token rotation updated .env but could not safely synchronize Antigravity config: $($_.Exception.Message)" }
    }
    Pass 'Compromised bridge token rotated (value not displayed)'
  }

  $tokenLine = Get-Content -LiteralPath $envPath | Where-Object { $_ -match '^CODE_BRIDGE_TOKEN=' } | Select-Object -First 1
  $token = $tokenLine.Substring('CODE_BRIDGE_TOKEN='.Length)
  Require ($token.Length -ge 32) 'CODE_BRIDGE_TOKEN is missing or too short.'
  $env:CODE_BRIDGE_WORKSPACE = $workspace
  $env:CODE_BRIDGE_TOKEN = $token

  if (-not (Test-Path (Join-Path $root 'node_modules'))) { npm install } else { npm install --ignore-scripts }
  npm run build
  npm run test
  npm run build:extension
  npm run package:extension
  Pass 'Build, transport, and security tests'

  $port = 3333
  if ($rawEnv -match '(?m)^PORT=(\d+)$') { $port = [int]$Matches[1] }
  $existing = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
  Require (-not $existing) "Port $port is already in use; stop the existing bridge before verification."
  $serverProcess = Start-Process -FilePath node -ArgumentList 'dist/server.js' -WorkingDirectory $root -WindowStyle Hidden -PassThru
  $healthUrl = "http://127.0.0.1:$port/health"
  $deadline = (Get-Date).AddSeconds(15)
  do { Start-Sleep -Milliseconds 300; try { $health = Invoke-RestMethod -Uri $healthUrl -Headers @{ 'x-code-bridge-token'=$token }; break } catch {} } while ((Get-Date) -lt $deadline)
  Require ($null -ne $health -and $health.ok -eq $true) 'Authenticated health check did not succeed.'
  Pass 'Authenticated loopback health check'

  try { Invoke-WebRequest -Uri $healthUrl -UseBasicParsing | Out-Null; throw 'Unauthenticated request unexpectedly succeeded.' } catch { Require ($_.Exception.Response.StatusCode.value__ -eq 401) 'Unauthenticated request did not return HTTP 401.' }
  Pass 'Unauthenticated request rejected with 401'
  try { Invoke-WebRequest -Uri $healthUrl -Headers @{ 'x-code-bridge-token' = 'invalid-test-token' } -UseBasicParsing | Out-Null; throw 'Invalid-token request unexpectedly succeeded.' } catch { Require ($_.Exception.Response.StatusCode.value__ -eq 401) 'Invalid-token request did not return HTTP 401.' }
  Pass 'Invalid-token request rejected with 401'

  $headers = @{ 'x-code-bridge-token'=$token; Accept='application/json, text/event-stream' }
  $init = @{ jsonrpc='2.0'; id=1; method='initialize'; params=@{ protocolVersion='2025-03-26'; capabilities=@{}; clientInfo=@{ name='setup-and-test'; version='1.0' } } } | ConvertTo-Json -Depth 8
  $initResponse = Invoke-RestMethod -Uri "http://127.0.0.1:$port/mcp" -Method Post -Headers $headers -ContentType 'application/json' -Body $init
  Require ($initResponse.result.serverInfo.name -eq 'Code Bridge') 'MCP initialization did not return Code Bridge.'
  $list = @{ jsonrpc='2.0'; id=2; method='tools/list'; params=@{} } | ConvertTo-Json -Depth 5
  $listResponse = Invoke-RestMethod -Uri "http://127.0.0.1:$port/mcp" -Method Post -Headers $headers -ContentType 'application/json' -Body $list
  Require (($listResponse.result.tools.name) -contains 'read_file') 'MCP tools/list did not return read_file.'
  $read = @{ jsonrpc='2.0'; id=3; method='tools/call'; params=@{ name='list_files'; arguments=@{ relative_path='.'; max_depth=0 } } } | ConvertTo-Json -Depth 8
  $readResponse = Invoke-RestMethod -Uri "http://127.0.0.1:$port/mcp" -Method Post -Headers $headers -ContentType 'application/json' -Body $read
  Require ($null -ne $readResponse.result) 'Read-only MCP tool call failed.'
  Pass 'MCP initialize, tools/list, and read-only tools/call'

  $traversal = @{ jsonrpc='2.0'; id=31; method='tools/call'; params=@{ name='read_file'; arguments=@{ relative_path='../outside.txt' } } } | ConvertTo-Json -Depth 8
  $traversalResponse = Invoke-RestMethod -Uri "http://127.0.0.1:$port/mcp" -Method Post -Headers $headers -ContentType 'application/json' -Body $traversal
  Require ($traversalResponse.result.isError -eq $true) 'Workspace traversal was not rejected.'
  $arbitraryCommand = @{ jsonrpc='2.0'; id=32; method='tools/call'; params=@{ name='run_project_command'; arguments=@{ command='powershell -NoProfile -Command whoami' } } } | ConvertTo-Json -Depth 8
  $commandResponse = Invoke-RestMethod -Uri "http://127.0.0.1:$port/mcp" -Method Post -Headers $headers -ContentType 'application/json' -Body $arbitraryCommand
  Require ($commandResponse.result.isError -eq $true) 'Arbitrary command was not rejected.'
  Pass 'Traversal and arbitrary command rejected'

  $marker = ".code-bridge-unapproved-$([guid]::NewGuid().ToString('N')).txt"
  $write = @{ jsonrpc='2.0'; id=4; method='tools/call'; params=@{ name='write_file'; arguments=@{ relative_path=$marker; content='must never be written without approval' } } } | ConvertTo-Json -Depth 8
  $writeResponse = Invoke-RestMethod -Uri "http://127.0.0.1:$port/mcp" -Method Post -Headers $headers -ContentType 'application/json' -Body $write
  Require ($writeResponse.result.isError -eq $true) 'Unapproved write was not rejected.'
  Require (-not (Test-Path -LiteralPath (Join-Path $workspace $marker))) 'Unapproved write created a file.'
  Pass 'Unapproved write rejected without modifying workspace'

  $editor = Get-NetTCPConnection -LocalPort 3334 -State Listen -ErrorAction SilentlyContinue
  if ($editor) { Pass 'VS Code extension is loopback listener on 3334' } else { $results.Add([pscustomobject]@{ Check='VS Code extension port 3334'; Result='INFO: extension is not currently running' }) }

  # This marker is intentionally metadata-only; start-cloudflared.ps1 requires it
  # before it will consider exposing the MCP listener.
  $logDir = Join-Path $root 'logs'
  New-Item -ItemType Directory -Force -Path $logDir | Out-Null
  [pscustomobject]@{ passedAt=(Get-Date).ToUniversalTime().ToString('o'); workspace=$workspace; mcpPort=$port; autoApproveWrites=$false; tests='authenticated-health,missing-auth-401,invalid-auth-401,mcp-initialize,tools-list,list-files,traversal-rejection,command-allowlist,unapproved-write' } |
    ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $logDir 'local-security-pass.json') -NoNewline
} catch {
  Fail 'Setup or verification' $_.Exception.Message
} finally {
  if ($serverProcess -and -not $KeepRunning) { Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue }
}

$results | Format-Table -AutoSize
if ($results.Result -match '^FAIL') { exit 1 }
if (-not $KeepRunning) { Write-Host 'PASS: local verification completed; service was stopped. Use .\setup-and-test.ps1 -KeepRunning to leave it running.' }
