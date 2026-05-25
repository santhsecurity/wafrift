# scripts/dogfood-sweep.ps1
#
# Windows / PowerShell sibling of dogfood-sweep.sh.
# Runs every wired surface end-to-end, captures bench number,
# diffs against the pre-sweep baseline.

[CmdletBinding()]
param(
    [string]$BenchTarget = "https://testing.santh.dev",
    [int]$Variants       = 10,
    [switch]$SkipBench,
    [int]$TimeboxSec     = 30
)

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir
$Wafrift   = Join-Path $RepoRoot 'target\release\wafrift.exe'
$ResultDir = Join-Path $RepoRoot 'wafrift-bench\results'
$Timestamp = (Get-Date -Format 'yyyyMMdd-HHmmss')
$Report    = Join-Path $ResultDir "dogfood-$Timestamp.json"

if (-not (Test-Path $ResultDir)) { New-Item -ItemType Directory -Path $ResultDir | Out-Null }

function Log     ($m) { Write-Host ("{0} [dogfood] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m) -ForegroundColor Yellow }
function Ok      ($m) { Write-Host ("{0} [dogfood] OK {1}" -f (Get-Date -Format 'HH:mm:ss'), $m) -ForegroundColor Green }
function Bad     ($m) { Write-Host ("{0} [dogfood] -- {1}" -f (Get-Date -Format 'HH:mm:ss'), $m) -ForegroundColor Red }

# --- 1. snapshot ---------------------------------------------------
Push-Location $RepoRoot
try {
    $HeadSha = (git rev-parse --short HEAD 2>$null)
    $HeadMsg = (git log -1 --pretty=%s 2>$null)
    $Dirty   = ((git status --porcelain 2>$null) | Measure-Object).Count
} finally { Pop-Location }

Log "HEAD=$HeadSha `"$HeadMsg`" (dirty=$Dirty)"

# --- 2-4. parallel build + lint -----------------------------------
Log "starting cargo build/test/clippy in parallel..."

$BuildLog  = Join-Path $ResultDir "dogfood-$Timestamp-build.log"
$TestLog   = Join-Path $ResultDir "dogfood-$Timestamp-test.log"
$ClippyLog = Join-Path $ResultDir "dogfood-$Timestamp-clippy.log"

$JobBuild = Start-Job -ScriptBlock {
    param($root, $log)
    Set-Location $root
    cargo build --release --bin wafrift *>&1 | Out-File -Encoding utf8 $log
    $LASTEXITCODE
} -ArgumentList $RepoRoot, $BuildLog

$JobTest = Start-Job -ScriptBlock {
    param($root, $log)
    Set-Location $root
    cargo test --workspace --release *>&1 | Out-File -Encoding utf8 $log
    $LASTEXITCODE
} -ArgumentList $RepoRoot, $TestLog

$JobClippy = Start-Job -ScriptBlock {
    param($root, $log)
    Set-Location $root
    cargo clippy --workspace --all-targets --release -- -D warnings *>&1 | Out-File -Encoding utf8 $log
    $LASTEXITCODE
} -ArgumentList $RepoRoot, $ClippyLog

$null = Wait-Job $JobBuild, $JobTest, $JobClippy
$RcBuild  = Receive-Job $JobBuild  -Keep | Select-Object -Last 1
$RcTest   = Receive-Job $JobTest   -Keep | Select-Object -Last 1
$RcClippy = Receive-Job $JobClippy -Keep | Select-Object -Last 1
Remove-Job $JobBuild, $JobTest, $JobClippy -Force

if ($RcBuild  -eq 0) { Ok "build green"  } else { Bad "build RED -- see $BuildLog" }
if ($RcTest   -eq 0) { Ok "tests green"  } else { Bad "tests RED -- see $TestLog" }
if ($RcClippy -eq 0) { Ok "clippy green" } else { Bad "clippy RED -- see $ClippyLog" }

if (-not (Test-Path $Wafrift)) {
    Bad "wafrift binary missing -- abort"
    exit 2
}

# --- 5-8. subcommand probes ---------------------------------------
$SurfacesOk      = @()
$SurfacesMissing = @()

function Probe-Subcommand ($Label, $Args) {
    $proc = Start-Process -FilePath $Wafrift -ArgumentList ($Args + @('--help')) `
        -NoNewWindow -PassThru -RedirectStandardOutput "$env:TEMP\dogfood-probe.out" `
        -RedirectStandardError "$env:TEMP\dogfood-probe.err"
    if (-not $proc.WaitForExit($TimeboxSec * 1000)) {
        try { $proc.Kill() } catch {}
        Bad "$Label hung past $TimeboxSec s"
        return $false
    }
    if ($proc.ExitCode -eq 0) {
        Ok "$Label reachable"
        return $true
    }
    Bad "$Label NOT reachable (exit=$($proc.ExitCode))"
    return $false
}

$probes = @(
    @{ Label = 'wafrift --help';        Args = @() },
    @{ Label = 'wafrift bench-waf';     Args = @('bench-waf') },
    @{ Label = 'wafrift scan';          Args = @('scan') },
    @{ Label = 'wafrift evade';         Args = @('evade') },
    @{ Label = 'wafrift audit';         Args = @('audit') },
    @{ Label = 'wafrift harden';        Args = @('harden') },
    @{ Label = 'wafrift detect';        Args = @('detect') },
    @{ Label = 'wafrift recon';         Args = @('recon') }
)

foreach ($p in $probes) {
    if (Probe-Subcommand $p.Label $p.Args) { $SurfacesOk += $p.Label }
    else                                   { $SurfacesMissing += $p.Label }
}

# --- 9. bench -----------------------------------------------------
$BenchJson = $null
if ($SkipBench) {
    Log "SkipBench -- bench step skipped"
} else {
    Log "running bench-waf against $BenchTarget (variants=$Variants)..."
    $BenchOut = Join-Path $ResultDir "dogfood-$Timestamp-bench.json"
    $BenchLog = Join-Path $ResultDir "dogfood-$Timestamp-bench.log"
    $proc = Start-Process -FilePath $Wafrift `
        -ArgumentList @('bench-waf', '--base-url', $BenchTarget, '--evade',
                        '--variants', $Variants, '--output', $BenchOut) `
        -NoNewWindow -PassThru -RedirectStandardOutput $BenchLog -RedirectStandardError $BenchLog.Replace('.log', '.err.log')
    if (-not $proc.WaitForExit(1800 * 1000)) {
        try { $proc.Kill() } catch {}
        Bad "bench timed out at 1800s -- see $BenchLog"
    } elseif ($proc.ExitCode -eq 0) {
        Ok "bench complete -- see $BenchOut"
        $BenchJson = $BenchOut
    } else {
        Bad "bench failed (exit=$($proc.ExitCode)) -- see $BenchLog"
    }
}

# --- 10. diff vs previous ----------------------------------------
$PrevRate = $null
$CurrRate = $null
if ($BenchJson) {
    $PrevBench = Get-ChildItem -Path $ResultDir -Filter 'dogfood-*-bench.json' |
        Where-Object { $_.FullName -ne $BenchJson } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($PrevBench) {
        Log "diffing against $($PrevBench.FullName)"
        try { $PrevRate = (Get-Content $PrevBench.FullName -Raw | ConvertFrom-Json).bypass_rate } catch {}
        try { $CurrRate = (Get-Content $BenchJson -Raw            | ConvertFrom-Json).bypass_rate } catch {}
        if ($PrevRate -ne $null) { Write-Host "  PREV: $PrevRate" }
        if ($CurrRate -ne $null) { Write-Host "  CURR: $CurrRate" }
    }
}

# --- 11. report --------------------------------------------------
$summary = [ordered]@{
    timestamp           = $Timestamp
    head_sha            = $HeadSha
    head_msg            = $HeadMsg
    dirty_paths         = $Dirty
    surfaces_reachable  = $SurfacesOk
    surfaces_missing    = $SurfacesMissing
    bench_target        = $BenchTarget
    bench_variants      = $Variants
    bench_json          = $BenchJson
    bench_rate_prev     = $PrevRate
    bench_rate_curr     = $CurrRate
}
$summary | ConvertTo-Json -Depth 4 | Out-File -Encoding utf8 $Report

Write-Host ""
Write-Host "=== dogfood sweep complete ==="
Write-Host "report: $Report"
Write-Host ("reachable surfaces: {0}/{1}" -f $SurfacesOk.Count, ($SurfacesOk.Count + $SurfacesMissing.Count))
if ($SurfacesMissing.Count -gt 0) {
    Write-Host ("missing surfaces:   {0}" -f ($SurfacesMissing -join ', '))
}
if ($BenchJson) {
    Write-Host "bench rate:         prev=$PrevRate  curr=$CurrRate"
}
