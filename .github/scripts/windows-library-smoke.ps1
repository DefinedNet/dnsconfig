# Exercise the library on a newly owned adapter, then run the existing NRPT row.
param([Parameter(Mandatory=$true)][ValidateSet('W1','W2','W3','W4','W5','W6','W7')][string]$Row)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
. "$PSScriptRoot/windows-owned-adapter.ps1"
$outputDirectory = "$env:RUNNER_TEMP/windows-library-$Row"
New-Item -ItemType Directory -Force $outputDirectory | Out-Null
Start-Transcript -Path "$outputDirectory/transcript.txt" | Out-Null
$globalPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
$policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
$binary = "$outputDirectory/dnsconfigctl.exe"
$script:sequence = 0
$server = $null
$adapter = $null
$originalGlobal = $null
$capturedGlobal = $false
$split = $Row -in @('W2','W4')
# W6 owns two adapters and runs only the harness's two-identity row; the
# single-adapter scenario below assumes one adapter and the default identity.
$pair = $Row -eq 'W6'
# W7 runs only the harness's repair row, which holds its own live Manager.
$harnessOnly = $pair -or $Row -eq 'W7'

function Read-Value($path, $name) {
    $key = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if ($null -eq $key -or $key.GetValueNames() -notcontains $name) { return $null }
    return $key.GetValue($name, $null, 'DoNotExpandEnvironmentNames')
}
function Write-Global($value) {
    if ($null -eq $value) {
        Remove-ItemProperty -LiteralPath $globalPath -Name SearchList -ErrorAction SilentlyContinue
    } else {
        New-ItemProperty -LiteralPath $globalPath -Name SearchList -PropertyType String -Value $value -Force | Out-Null
    }
    # Notify Windows after fixture global-list edits, before library writes.
    # Set and suffix replacement receive no helper registration afterward.
    & ipconfig /registerdns | Out-Host
    if ($LASTEXITCODE) { throw 'registerdns failed' }
    Clear-DnsClientCache
}
function Invoke-Ctl([string[]]$Arguments) {
    $script:sequence++
    $out = "$outputDirectory/ctl-$script:sequence.out"
    $err = "$outputDirectory/ctl-$script:sequence.err"
    $quoted = @($Arguments | ForEach-Object { '"' + $_.Replace('"','\"') + '"' })
    $start = [Diagnostics.ProcessStartInfo]::new($binary)
    $start.Arguments = $quoted -join ' '
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (!$process.WaitForExit(60000)) { $process.Kill(); $process.WaitForExit(); throw "command timed out: $Arguments" }
    $result = [pscustomobject]@{ code=$process.ExitCode; stdout=$stdoutTask.GetAwaiter().GetResult(); stderr=$stderrTask.GetAwaiter().GetResult() }
    $result.stdout | Set-Content $out
    $result.stderr | Set-Content $err
    Write-Output "LIBRARY-COMMAND: $Arguments exit=$($result.code)" | Out-Host
    $result.stdout | Out-Host
    $result.stderr | Out-Host
    $process.Dispose()
    return $result
}
function Require-OK($result) {
    if ($result.code -ne 0) { throw "dnsconfigctl failed: $($result.stderr)" }
}
function Set-Library($suffixes, [switch]$Close) {
    $args = @('-backend','windows','-interface','dnsconfig-smoke','set','--ns','127.0.0.1','--search',$suffixes)
    if ($split) { $args += @('--match','dnsconfig-smoke.example') }
    if ($Close) { $args += '--close-immediately' } else { $args += '--detach' }
    Require-OK (Invoke-Ctl $args)
}
function Reset-Library([string]$InterfaceName = 'dnsconfig-smoke') {
    $result = Invoke-Ctl @('-backend','windows','-interface',$InterfaceName,'reset')
    Require-OK $result
    # Exact line: the nothing-to-reset reply also starts with 'reset OK'.
    $lines = @(([string]$result.stdout) -split '\r?\n' | ForEach-Object { $_.Trim() })
    if ($lines -cnotcontains 'reset OK') { throw 'cross-process reset removed nothing' }
}
function Assert-Lookup($name, $sentinel, [switch]$Once) {
    # Global fixture edits can settle asynchronously. Replacement activation
    # uses Once so a delayed adapter update cannot pass through retries.
    $deadline = (Get-Date).AddSeconds(10)
    while ($true) {
        Clear-DnsClientCache
        $result = Invoke-Ctl @('lookup','--timeout','8s',$name)
        $matched = $result.code -eq 0 -and @(([string]$result.stdout).Trim() -split '[\r\n]+' -contains '192.0.2.42')
        if ($Once -or -not $sentinel -or [bool]$matched -or (Get-Date) -ge $deadline) { break }
        Start-Sleep -Milliseconds 500
    }
    if ([bool]$matched -ne $sentinel) { throw "lookup $name sentinel=$matched expected=$sentinel" }
    Write-Output "LIBRARY-LOOKUP: name=$name sentinel=$matched expected=$sentinel"
}
function Assert-Global($expected) {
    if ((Read-Value $globalPath 'SearchList') -cne $expected) { throw 'library changed the global SearchList' }
}
function Read-UnmanagedDNS {
    $values = @()
    foreach ($family in @('Tcpip','Tcpip6')) {
        $parent = "HKLM:\SYSTEM\CurrentControlSet\Services\$family\Parameters\Interfaces"
        foreach ($key in @(Get-ChildItem $parent -ErrorAction SilentlyContinue | Sort-Object Name)) {
            foreach ($name in @('NameServer','SearchList','Domain')) {
                if ($key.PSChildName -ieq $script:adapterGUID -and $name -ne 'Domain') { continue }
                $values += [ordered]@{ path=$key.Name; name=$name; value=(Read-Value $key.PSPath $name) }
            }
        }
    }
    foreach ($name in @('NameServer','Domain','NV Domain')) {
        $values += [ordered]@{ path=$globalPath; name=$name; value=(Read-Value $globalPath $name) }
    }
    return ($values | ConvertTo-Json -Compress -Depth 5)
}
function Assert-AdapterValue($path, $name, $expected, $message) {
    $actual = Read-Value $path $name
    # An empty value is Windows's own unset form; the library leaves it in place.
    if ($null -eq $expected -and -not $actual) { return }
    if ($actual -cne $expected) { throw $message }
}
function Assert-Adapter($suffixes, [switch]$Cleared) {
    foreach ($family in @('Tcpip','Tcpip6')) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$family\Parameters\Interfaces\$script:adapterGUID"
        $expectedNS = if (!$Cleared -and !$split -and $family -eq 'Tcpip') { '127.0.0.1' } else { $null }
        Assert-AdapterValue $path 'SearchList' $suffixes "adapter suffix mismatch in $family"
        Assert-AdapterValue $path 'NameServer' $expectedNS "adapter DNS server mismatch in $family"
    }
    if ((Read-UnmanagedDNS) -cne $script:unmanagedBefore) { throw 'unmanaged adapter/global DNS values changed' }
    $owned = @()
    foreach ($base in @('HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig','HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig')) {
        $owned += @(Get-ChildItem $base -ErrorAction SilentlyContinue | Where-Object PSChildName -like 'dnsconfig-*')
    }
    if ($Cleared -and $owned.Count) { throw 'NRPT recovery records survived cleanup' }
    if (!$Cleared -and !$owned.Count) { throw 'NRPT recovery records disappeared while applied' }
    if (@($owned | Where-Object PSChildName -like 'dnsconfig-*-pending').Count) { throw 'pending recovery record survived successful apply or reset' }

}
try {
    Write-Output "LIBRARY-COMMIT: $env:GITHUB_SHA ROW: $Row"
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture | Format-List | Out-Host
    if (Read-Value $policyPath 'SearchList') { throw 'fixture requires no managed policy suffix list' }
    if (@(Get-DnsClientNrptRule).Count) { throw 'fixture requires an empty NRPT' }
    $originalGlobal = Read-Value $globalPath 'SearchList'
    $capturedGlobal = $true
    $adapter = New-OwnedAdapter -Preferred
    $script:adapterGUID = ([guid]$adapter.InterfaceGuid).ToString('B')
    $script:unmanagedBefore = Read-UnmanagedDNS
    & go build -o $binary ./internal/cmd/dnsconfigctl
    if ($LASTEXITCODE) { throw 'build failed' }
    if ($harnessOnly) {
        if ($pair) { $null = New-OwnedAdapter -Name 'dnsconfig-smoke-b' -AllowExisting }
        & go run ./internal/cmd/smoketest -rows $Row
        if ($LASTEXITCODE) { throw "smoke row $Row failed" }
        return
    }
    $records = @('target.dnsconfig-smoke.example','oldonly.old.dnsconfig-smoke.example','newonly.new.dnsconfig-smoke.example','secondonly.second.dnsconfig-smoke.example','globalonly.global.dnsconfig-smoke.example','adminonly.admin.dnsconfig-smoke.example')
    $serverArgs = @('-v','serve','--addr','127.0.0.1:53')
    foreach ($record in $records) { $serverArgs += @('--record',"$record=192.0.2.42") }
    $server = Start-Process -FilePath $binary -ArgumentList $serverArgs -PassThru -RedirectStandardOutput "$outputDirectory/server.out" -RedirectStandardError "$outputDirectory/server.err"
    Require-OK (Invoke-Ctl @('probe-dns','--addr','127.0.0.1:53','--name','target.dnsconfig-smoke.example','--timeout','10s'))

    foreach ($state in @('absent','seeded','administrator-edit')) {
        Write-Output "LIBRARY-STATE: $state"
        $expectedGlobal = if ($state -eq 'seeded') { 'global.dnsconfig-smoke.example' } else { $null }
        Write-Global $expectedGlobal
        Set-Library 'old.dnsconfig-smoke.example,second.dnsconfig-smoke.example'
        Assert-Adapter 'old.dnsconfig-smoke.example,second.dnsconfig-smoke.example'
        Assert-Global $expectedGlobal
        Assert-Lookup 'target.dnsconfig-smoke.example.' $true
        Assert-Lookup 'oldonly' ($null -eq $expectedGlobal)
        Assert-Lookup 'secondonly' ($null -eq $expectedGlobal)
        if ($state -eq 'seeded') { Assert-Lookup 'globalonly' $true }
        if ($split) {
            $control = Invoke-Ctl @('lookup','--timeout','10s','microsoft.com.')
            Require-OK $control
            if ($control.stdout -match '192\.0\.2\.42') { throw 'split control reached sentinel' }
        }
        # A process that never sets, including its Close, must preserve this process's apply.
        $idle = Invoke-Ctl @('-backend','windows','watch','--expect-apply=false','--ns','127.0.0.1','--timeout','2s')
        Require-OK $idle
        if ($idle.stdout -notmatch 'WATCH: negative-ok') { throw 'idle Manager did not confirm it changed nothing' }
        Assert-Adapter 'old.dnsconfig-smoke.example,second.dnsconfig-smoke.example'
        $missing = Invoke-Ctl @('-backend','windows','set','--ns','127.0.0.1','--detach')
        if ($missing.code -eq 0 -or $missing.stderr -notmatch 'interface') { throw 'Set without interface was not refused' }
        Assert-Adapter 'old.dnsconfig-smoke.example,second.dnsconfig-smoke.example'
        if ($state -eq 'absent') {
            # A fresh Set using the old name is read-only; its error-path Close
            # must not clear the predecessor's still-configured renamed adapter.
            Rename-NetAdapter -Name 'dnsconfig-smoke' -NewName 'dnsconfig-smoke-renamed'
            try {
                $missing = Invoke-Ctl @('-backend','windows','-interface','dnsconfig-smoke','set','--ns','127.0.0.1','--detach')
                if ($missing.code -eq 0 -or $missing.stderr -notmatch 'interface') { throw 'Set with stale friendly name was not refused' }
                Assert-Adapter 'old.dnsconfig-smoke.example,second.dnsconfig-smoke.example'
                Assert-Lookup 'oldonly' $true
                Reset-Library 'dnsconfig-smoke-renamed'
                Assert-Adapter $null -Cleared
            } finally { Rename-NetAdapter -Name 'dnsconfig-smoke-renamed' -NewName 'dnsconfig-smoke' }
            Set-Library 'old.dnsconfig-smoke.example,second.dnsconfig-smoke.example'
        }
        if ($state -eq 'administrator-edit') {
            $expectedGlobal = 'admin.dnsconfig-smoke.example'
            Write-Global $expectedGlobal
        }
        Set-Library 'new.dnsconfig-smoke.example,second.dnsconfig-smoke.example'
        Assert-Global $expectedGlobal
        Assert-Adapter 'new.dnsconfig-smoke.example,second.dnsconfig-smoke.example'
        Assert-Lookup 'newonly' ($null -eq $expectedGlobal)
        Assert-Lookup 'oldonly' $false
        Assert-Lookup 'oldonly.old.dnsconfig-smoke.example.' $true
        if ($state -eq 'administrator-edit') { Assert-Lookup 'adminonly' $true }
        Reset-Library
        Assert-Adapter $null -Cleared
        Assert-Global $expectedGlobal
    }
    Write-Global $null
    Set-Library 'old.dnsconfig-smoke.example,second.dnsconfig-smoke.example'
    Assert-Lookup 'oldonly' $true
    # Repeated replacements must activate before the first application lookup;
    # the DNS Client does not pick up adapter value writes on its own.
    foreach ($iteration in 1..3) {
        foreach ($suffix in @('new','old')) {
            Set-Library "$suffix.dnsconfig-smoke.example,second.dnsconfig-smoke.example"
            Assert-Adapter "$suffix.dnsconfig-smoke.example,second.dnsconfig-smoke.example"
            Assert-Lookup "${suffix}only" $true -Once
        }
    }
    Reset-Library
    Assert-Adapter $null -Cleared
    Assert-Lookup 'oldonly' $false
    Set-Library 'new.dnsconfig-smoke.example'
    Assert-Lookup 'newonly' $true
    Reset-Library
    Assert-Adapter $null -Cleared
    Set-Library 'new.dnsconfig-smoke.example' -Close
    Assert-Adapter $null -Cleared
    Assert-Global $null
    Stop-Process -Id $server.Id -Force
    $server = $null
    Write-Global $originalGlobal
    & go run ./internal/cmd/smoketest -rows $Row
    if ($LASTEXITCODE) { throw "existing smoke row $Row failed" }
} finally {
    $cleanupErrors = @()
    if ($adapter -and (Test-Path $binary)) {
        if ($pair) {
            try { Require-OK (Invoke-Ctl @('-backend','windows','-identity','net-a','-interface','dnsconfig-smoke','reset')) } catch { $cleanupErrors += $_ }
            try { Require-OK (Invoke-Ctl @('-backend','windows','-identity','net-b','-interface','dnsconfig-smoke-b','reset')) } catch { $cleanupErrors += $_ }
        } else {
            try { Require-OK (Invoke-Ctl @('-backend','windows','-interface','dnsconfig-smoke','reset')) } catch { $cleanupErrors += $_ }
        }
    }
    if ($server) { try { Stop-Process -Id $server.Id -Force -ErrorAction Stop } catch { $cleanupErrors += $_ } }
    if ($capturedGlobal) { try { Write-Global $originalGlobal } catch { $cleanupErrors += $_ } }
    try { Remove-OwnedAdapter } catch { $cleanupErrors += $_ }
    Stop-Transcript | Out-Null
    if ($cleanupErrors.Count) { throw ($cleanupErrors -join "`n") }
}
