$ErrorActionPreference = "Stop"
$py = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"

$demos = @(
    @("Demo 1: admin has control plane but no data plane, and cannot self-grant (req 1, 7)", "demo1_admin_denied.py"),
    @("Demo 2: orchestrator session with egress lockdown and app-layer encryption (req 9-11, 15, 20, 22)", "demo2_orchestrator_session.py"),
    @("Demo 3: image pin check, isolation, wipe, orphan cleanup (req 3, 4, 13, 14, 16, 21, 24)", "demo3_controls.py"),
    @("Demo 4: per-operation session authentication (req 10)", "demo4_session_auth.py")
)

foreach ($demo in $demos) {
    Write-Host "`n==================== $($demo[0]) ====================" -ForegroundColor Cyan
    & $py -u (Join-Path $PSScriptRoot $demo[1])
    if ($LASTEXITCODE -ne 0) { throw "$($demo[1]) failed" }
    Read-Host "`nPress Enter for the next demo"
}
