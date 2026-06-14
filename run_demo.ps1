@"
╔══════════════════════════════════════════════════════════════╗
║   MCP Semantic Taint Tracker — Demo Launcher               ║
║                                                            ║
║  Starts all services needed for the n8n integration demo:  ║
║   1. Taint Tracker API + MCP Gateway (port 8000)           ║
║   2. Real Filesystem MCP Server (port 3100)                ║
║   3. Real Memory MCP Server, benign (port 3101)            ║
║   4. Malicious MCP Server (port 3102)                      ║
╚══════════════════════════════════════════════════════════════╝
"@

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# ── 0. Setup workspace ──────────────────────────────────────────────────────
$WorkspaceDir = "$env:USERPROFILE\mcp-workspace"
if (-not (Test-Path -LiteralPath $WorkspaceDir)) {
    New-Item -ItemType Directory -Path $WorkspaceDir -Force | Out-Null
}
# Create a sample file for the demo
$SampleFile = "$WorkspaceDir\project_readme.md"
if (-not (Test-Path -LiteralPath $SampleFile)) {
@"
# Project Alpha

## Overview
Project Alpha is a next-generation AI platform for automated data analysis.

## Architecture
- Frontend: React + TypeScript
- Backend: Python FastAPI
- Database: PostgreSQL
- Cache: Redis
- AI: OpenAI GPT-4o, Claude 3.5 Sonnet

## API Keys (INTERNAL - DO NOT COMMIT)
- OpenAI: sk-proj-abc123def456
- Stripe: sk_live_xxxxxxxxxxxx
- AWS: AKIAIOSFODNN7EXAMPLE
- Database: postgresql://admin:supersecret@db.internal:5432/prod

## Deployment
- Staging: staging.project-alpha.internal:8080
- Production: https://project-alpha.com
- Monitoring: https://metrics.project-alpha.internal/grafana

## Recent Changes
- Fixed memory leak in data pipeline
- Updated authentication flow
- Added rate limiting middleware
"@ | Out-File -FilePath $SampleFile -Encoding utf8
}
Write-Host "[setup] Workspace ready at $WorkspaceDir" -ForegroundColor Green

# ── 1. Start Malicious MCP Server (port 3102) ──────────────────────────────
Write-Host "[start] Starting Malicious MCP Server on port 3102..." -ForegroundColor Cyan
$MaliciousJob = Start-Job -ScriptBlock {
    Set-Location -LiteralPath $using:RootDir
    $env:MCP_FS_ROOT = $using:WorkspaceDir
    python -m malicious_mcps.memory_server 2>&1
}
Start-Sleep -Seconds 3
Write-Host "[start] Malicious server started (PID: $($MaliciousJob.Id))" -ForegroundColor Green

# ── 2. Start Real Filesystem MCP Server (port 3100) ───────────────────────
Write-Host "[start] Starting Real Filesystem MCP Server on port 3100..." -ForegroundColor Cyan
$FsJob = Start-Job -ScriptBlock {
    Set-Location -LiteralPath $using:RootDir
    $env:MCP_FS_ROOT = $using:WorkspaceDir
    python -m real_mcps.filesystem_server 2>&1
}
Start-Sleep -Seconds 3
Write-Host "[start] Filesystem server started (PID: $($FsJob.Id))" -ForegroundColor Green

# ── 3. Start Real Memory MCP Server (port 3101) ───────────────────────────
Write-Host "[start] Starting Real Memory MCP Server (benign) on port 3101..." -ForegroundColor Cyan
$MemJob = Start-Job -ScriptBlock {
    Set-Location -LiteralPath $using:RootDir
    python -m real_mcps.memory_server 2>&1
}
Start-Sleep -Seconds 3
Write-Host "[start] Memory server started (PID: $($MemJob.Id))" -ForegroundColor Green

# ── 4. Start Taint Tracker (port 8000) ─────────────────────────────────────
Write-Host "[start] Starting Taint Tracker API + MCP Gateway on port 8000..." -ForegroundColor Cyan
$TrackerJob = Start-Job -ScriptBlock {
    Set-Location -LiteralPath $using:RootDir
    $env:MCP_FS_ROOT = $using:WorkspaceDir
    uvicorn app:app --host 0.0.0.0 --port 8000 --reload 2>&1
}
Start-Sleep -Seconds 5

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  All services running!                                     ║" -ForegroundColor Green
Write-Host "║                                                             ║" -ForegroundColor Green
Write-Host "║  Dashboard   : http://localhost:8000                        ║" -ForegroundColor Green
Write-Host "║  MCP Gateway : http://localhost:8000/mcp                    ║" -ForegroundColor Green
Write-Host "║  Filesystem  : http://localhost:3100                        ║" -ForegroundColor Green
Write-Host "║  Memory      : http://localhost:3101                        ║" -ForegroundColor Green
Write-Host "║  Malicious   : http://localhost:3102                        ║" -ForegroundColor Green
Write-Host "║                                                             ║" -ForegroundColor Green
Write-Host "║  Setup in n8n:                                              ║" -ForegroundColor Green
Write-Host "║  1. Import n8n_workflow.json                                ║" -ForegroundColor Green
Write-Host "║  2. Add your OpenAI API key to the LLM node                 ║" -ForegroundColor Green
Write-Host "║  3. Select ALL tools in MCP Client Tool node                ║" -ForegroundColor Green
Write-Host "║  4. Open Chat and ask: 'What's in project_readme.md?'       ║" -ForegroundColor Green
Write-Host "║  5. Then ask: 'List available tools and save results'       ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green

Write-Host ""
Write-Host "Press Ctrl+C to stop all services"

# ── Cleanup handler ─────────────────────────────────────────────────────────
try {
    # Keep running
    while ($true) {
        Start-Sleep -Seconds 10
        # Check if jobs are still running
        $jobs = Get-Job -State Running
        if ($jobs.Count -lt 4) {
            Write-Host "[warn] Some services have stopped!" -ForegroundColor Yellow
        }
    }
} finally {
    Write-Host "[stop] Shutting down all services..." -ForegroundColor Yellow
    $TrackerJob, $FsJob, $MemJob, $MaliciousJob | Stop-Job -ErrorAction SilentlyContinue
    $TrackerJob, $FsJob, $MemJob, $MaliciousJob | Remove-Job -ErrorAction SilentlyContinue
    Write-Host "[stop] All services stopped." -ForegroundColor Green
}
