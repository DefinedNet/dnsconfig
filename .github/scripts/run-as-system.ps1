<#
.SYNOPSIS
Runs a command as LocalSystem, streams its output, and propagates its exit code.

.DESCRIPTION
GitHub-hosted Windows runners execute as an elevated administrator account, not
as LocalSystem. Some APIs -- notably userenv.dll!GenerateGPNotification, which
is how the DNS Client is told to re-read the Group Policy NRPT store -- carry an
internal access check that elevation alone does not satisfy. This wrapper closes
that gap.

The mechanism is the built-in Task Scheduler: a one-shot task with /ru SYSTEM.
schtasks ships with Windows, so unlike PsExec there is nothing to download and
no EULA to accept.

Two details make it reliable rather than merely plausible:

  * The task runs a generated .cmd shim instead of an inline command line.
    schtasks /tr nests quotes and truncates at 261 characters; a shim sidesteps
    both, and gives somewhere to set the working directory, which LocalSystem
    does not inherit.

  * Completion and the exit code are read from a sentinel file the shim writes,
    not from `schtasks /query`. Polling Status races the scheduler (a just-run
    task still reads "Ready" for a moment) and both Status and Last Result are
    localized. The sentinel is neither.

.PARAMETER Command
The command line to run. Must be a single command -- no `&&`, `|`, or `>`; the
shim supplies its own redirection. Quote any path containing spaces.

.PARAMETER WorkingDirectory
Directory to run in. Defaults to the caller's. LocalSystem starts in
C:\Windows\System32 otherwise.

.PARAMETER TimeoutSeconds
Give up waiting for the sentinel after this long and fail.

.EXAMPLE
.\run-as-system.ps1 -Command "whoami"

.EXAMPLE
.\run-as-system.ps1 -Command "`"$PWD\bin\probe.exe`" -flag"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Command,

    [string]$WorkingDirectory = $PWD.Path,

    [int]$TimeoutSeconds = 1800
)

$ErrorActionPreference = 'Stop'

# The caller sees only this script's invocation line for a terminating error,
# so name the failing line before it propagates.
trap { Write-Host "run-as-system: $($_.ScriptStackTrace)"; break }

# schtasks writes some of its chatter to stderr, and stderr merged into the
# pipeline raises a terminating NativeCommandError while the preference is Stop.
# Relax it around the call itself and judge the result by the exit code instead.
function Invoke-Schtasks {
    param([string[]]$ArgList)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = & schtasks.exe @ArgList 2>&1
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $prev
    [pscustomobject]@{ Output = ($out | Out-String).Trim(); ExitCode = $rc }
}

# C:\Windows\Temp rather than $env:TEMP: the shim, log, and sentinel must be
# readable and writable by SYSTEM, whose profile is not the caller's.
$tag      = [Guid]::NewGuid().ToString('N').Substring(0, 12)
$taskName = "dnsconfig-ras-$tag"
$shim     = "C:\Windows\Temp\ras-$tag.cmd"
$log      = "C:\Windows\Temp\ras-$tag.log"
$sentinel = "C:\Windows\Temp\ras-$tag.rc"

# Written with an explicit ASCII encoding: cmd.exe reads a batch file in the OEM
# codepage and chokes on the BOM PowerShell would otherwise prepend.
#
# `call` so a quoted program path survives (bare `cmd /c "..." args` gets its
# quotes stripped), and the space before `>` so a numeric %ERRORLEVEL% is not
# parsed as a stream-handle redirect.
$shimBody = @"
@echo off
cd /d "$WorkingDirectory"
call $Command > "$log" 2>&1
echo %ERRORLEVEL% > "$sentinel"
"@
Set-Content -LiteralPath $shim -Value $shimBody -Encoding ASCII
New-Item -ItemType File -Path $log -Force | Out-Null

Write-Host "run-as-system: task=$taskName cwd=$WorkingDirectory"
Write-Host "run-as-system: command: $Command"

$exitCode = $null
try {
    # /sc ONSTART needs no /st, dodging schtasks' locale-dependent time parsing
    # and its refusal to schedule a start time already in the past. The task is
    # never triggered by a boot -- it is started explicitly below and deleted in
    # the finally block.
    $create = Invoke-Schtasks @('/create', '/tn', $taskName, '/ru', 'SYSTEM', '/sc', 'ONSTART', '/rl', 'HIGHEST', '/f', '/tr', $shim)
    if ($create.ExitCode -ne 0) {
        throw "schtasks /create failed ($($create.ExitCode)): $($create.Output)"
    }

    $run = Invoke-Schtasks @('/run', '/tn', $taskName)
    if ($run.ExitCode -ne 0) {
        throw "schtasks /run failed ($($run.ExitCode)): $($run.Output)"
    }

    # Poll for the sentinel, tailing whatever the child has written so far so
    # long-running commands are not silent.
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $emitted  = 0
    while ($true) {
        $lines = @(Get-Content -LiteralPath $log -ErrorAction SilentlyContinue)
        if ($lines.Count -gt $emitted) {
            $lines[$emitted..($lines.Count - 1)] | ForEach-Object { Write-Host $_ }
            $emitted = $lines.Count
        }

        if (Test-Path -LiteralPath $sentinel) {
            # An empty or failed read means the shim is mid-write; take the
            # next pass. Interpolate rather than cast: in Windows PowerShell
            # 5.1, [string] of a read that returns nothing is $null.
            $raw = "$(Get-Content -LiteralPath $sentinel -Raw -ErrorAction SilentlyContinue)".Trim()
            if ($raw -match '^-?\d+$') {
                $exitCode = [int]$raw
                break
            }
        }

        if ((Get-Date) -gt $deadline) {
            throw "timed out after ${TimeoutSeconds}s waiting for the SYSTEM task to finish"
        }
        Start-Sleep -Milliseconds 500
    }

    # Drain anything written between the last tail and the sentinel appearing.
    $lines = @(Get-Content -LiteralPath $log -ErrorAction SilentlyContinue)
    if ($lines.Count -gt $emitted) {
        $lines[$emitted..($lines.Count - 1)] | ForEach-Object { Write-Host $_ }
    }
}
finally {
    Invoke-Schtasks @('/delete', '/tn', $taskName, '/f') | Out-Null
    Remove-Item -LiteralPath $shim, $log, $sentinel -Force -ErrorAction SilentlyContinue
}

Write-Host "run-as-system: exit code $exitCode"
exit $exitCode
