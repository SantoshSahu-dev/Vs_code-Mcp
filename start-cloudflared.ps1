[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)] [string]$ConfigPath
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

# 1. Verify existence of local security pass report
$localReport = Join-Path $root 'logs\local-security-pass.json'
if (-not (Test-Path -LiteralPath $localReport)) {
  throw 'Refusing to start a public tunnel: local security report not found. Run .\setup-and-test.ps1 first to generate a valid PASS report.'
}

# 2. Parse and validate report structure
try {
  $report = Get-Content -Raw -LiteralPath $localReport | ConvertFrom-Json
} catch {
  throw "Refusing to start a public tunnel: local security report ($localReport) is malformed JSON. Re-run .\setup-and-test.ps1."
}

if (-not $report.passedAt -or -not $report.workspace -or -not $report.mcpPort -or $null -eq $report.autoApproveWrites -or -not $report.tests) {
  throw 'Refusing to start a public tunnel: local security report is missing mandatory verification fields. Re-run .\setup-and-test.ps1.'
}

# 3. Verify report recency (must be within last 24 hours, not future-dated)
try {
  $passedTime = [DateTime]::Parse($report.passedAt, $null, [System.Globalization.DateTimeStyles]::RoundtripKind)
} catch {
  throw "Refusing to start a public tunnel: invalid passedAt timestamp in security report: $($report.passedAt). Re-run .\setup-and-test.ps1."
}
$age = [DateTime]::UtcNow - $passedTime
if ($age.TotalHours -gt 24 -or $age.TotalSeconds -lt -300) {
  throw "Refusing to start a public tunnel: security PASS report has expired (age: $([Math]::Round($age.TotalHours, 1)) hours, issued $($report.passedAt)). Re-run .\setup-and-test.ps1 to re-verify current state."
}

# 4. Verify report corresponds to current .env configuration and workspace
$envPath = Join-Path $root '.env'
if (-not (Test-Path -LiteralPath $envPath)) {
  throw 'Refusing to start a public tunnel: .env file is missing. Configure .env and run .\setup-and-test.ps1.'
}
$rawEnv = Get-Content -Raw -LiteralPath $envPath
$wsMatch = [regex]::Match($rawEnv, '(?m)^CODE_BRIDGE_WORKSPACE=(.+)$')
if (-not $wsMatch.Success) { throw 'Refusing to start: CODE_BRIDGE_WORKSPACE is not set in .env.' }
$currentWs = $wsMatch.Groups[1].Value.Trim().TrimEnd('>')
if (-not (Test-Path -LiteralPath $currentWs -PathType Container)) {
  throw "Refusing to start: configured workspace directory does not exist: $currentWs"
}
$resolvedWs = (Resolve-Path -LiteralPath $currentWs).Path
if ($report.workspace -ne $resolvedWs) {
  throw "Refusing to start: security PASS was issued for workspace '$($report.workspace)', but current .env workspace is '$resolvedWs'. Re-run .\setup-and-test.ps1."
}

$portMatch = [regex]::Match($rawEnv, '(?m)^PORT=(\d+)$')
$currentPort = if ($portMatch.Success) { [int]$portMatch.Groups[1].Value } else { 3333 }
if ([int]$report.mcpPort -ne $currentPort) {
  throw "Refusing to start: security PASS was issued for port $($report.mcpPort), but current .env PORT is $currentPort. Re-run .\setup-and-test.ps1."
}

if ($report.autoApproveWrites -ne $false) {
  throw 'Refusing to start: security PASS report indicates autoApproveWrites was not disabled. Code Bridge strictly requires explicit human approvals.'
}
$autoApproveMatch = [regex]::Match($rawEnv, '(?m)^CODE_BRIDGE_AUTO_APPROVE_WRITES=(.+)$')
if ($autoApproveMatch.Success) {
  $val = $autoApproveMatch.Groups[1].Value.Trim().ToLower()
  if ($val -and $val -notin @('false', '0', 'no')) {
    throw 'Refusing to start: CODE_BRIDGE_AUTO_APPROVE_WRITES is enabled in .env. It must be false or omitted.'
  }
}

$requiredTests = @('authenticated-health','missing-auth-401','invalid-auth-401','mcp-initialize','tools-list','list-files','traversal-rejection','command-allowlist','unapproved-write')
$passedTests = ($report.tests -split ',').Trim()
foreach ($t in $requiredTests) {
  if ($passedTests -notcontains $t) {
    throw "Refusing to start: security PASS report is missing verification for required test '$t'. Re-run .\setup-and-test.ps1."
  }
}

# 5. Verify cloudflared executable is available (checking PATH and standard install directories)
$cfCmd = Get-Command cloudflared -ErrorAction SilentlyContinue
$cfExe = $null
if ($cfCmd) {
  $cfExe = $cfCmd.Source
} else {
  $p86 = ${env:ProgramFiles(x86)}
  $knownLocations = @(
    "$p86\cloudflared\cloudflared.exe",
    "$env:ProgramFiles\cloudflared\cloudflared.exe",
    "$env:LOCALAPPDATA\cloudflared\cloudflared.exe",
    "$env:USERPROFILE\.cloudflared\cloudflared.exe"
  )
  foreach ($loc in $knownLocations) {
    if ($loc -and (Test-Path -LiteralPath $loc)) {
      $cfExe = $loc
      break
    }
  }
}
if (-not $cfExe) {
  throw 'cloudflared is not installed or is not on PATH. Install it only from Cloudflare, then retry.'
}

# 6. Validate tunnel ingress configuration and allowed hostname alignment
if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Tunnel config not found: $ConfigPath" }
$configText = Get-Content -Raw -LiteralPath $ConfigPath
if ($configText -match 'REPLACE_WITH') {
  throw 'Refusing to start: tunnel config contains REPLACE_WITH placeholders. Provide your actual Cloudflare tunnel UUID and domain.'
}
if ($configText -match '3334') {
  throw 'Refusing to start: port 3334 must NEVER be exposed or referenced in tunnel config.'
}
$expectedService = "service:\s*http://127\.0\.0\.1:$currentPort"
if ($configText -notmatch $expectedService) {
  throw "Refusing to start: config must forward ingress strictly to http://127.0.0.1:$currentPort."
}
if ($configText -notmatch 'service:\s*http_status:404') {
  throw 'Refusing to start: config must include a catch-all 404 rule (- service: http_status:404).'
}

# Verify tunnel hostnames are declared in .env CODE_BRIDGE_ALLOWED_HOSTS
$hostMatches = [regex]::Matches($configText, '(?m)^\s*-\s*hostname:\s*([^\s\r\n]+)')
$allowedHostsMatch = [regex]::Match($rawEnv, '(?m)^CODE_BRIDGE_ALLOWED_HOSTS=(.*)$')
$allowedHostsList = if ($allowedHostsMatch.Success) {
  ($allowedHostsMatch.Groups[1].Value -split ',').ForEach({ $_.Trim().ToLower() }).Where({ $_ })
} else { @() }

foreach ($hm in $hostMatches) {
  $tunnelHost = $hm.Groups[1].Value.Trim().ToLower()
  if ($tunnelHost -and $tunnelHost -notmatch 'example\.com|replace' -and $tunnelHost -notin $allowedHostsList) {
    throw "Refusing to start: tunnel hostname '$tunnelHost' is not configured in CODE_BRIDGE_ALLOWED_HOSTS in .env. Add it to .env so the server allows requests for this host."
  }
}

# 7. Validate ingress rules with cloudflared and start tunnel
& $cfExe --config $ConfigPath tunnel ingress validate
if ($LASTEXITCODE -ne 0) { throw 'Tunnel ingress validation failed.' }
Write-Host "Local security verification validated (passed $($report.passedAt) for $resolvedWs). Starting Cloudflare tunnel..."
& $cfExe --config $ConfigPath tunnel run
