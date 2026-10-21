# The fixture owns a newly created inbox loopback device on an ephemeral runner.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public static class OwnedAdapterNative {
    [StructLayout(LayoutKind.Sequential)]
    struct DeviceInfo { public uint Size; public Guid ClassGuid; public uint DevInst; public IntPtr Reserved; }
    [DllImport("setupapi.dll", SetLastError=true)]
    static extern IntPtr SetupDiCreateDeviceInfoList(ref Guid guid, IntPtr parent);
    [DllImport("setupapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool SetupDiCreateDeviceInfo(IntPtr set, string name, ref Guid guid, string description, IntPtr parent, uint flags, ref DeviceInfo info);
    [DllImport("setupapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool SetupDiSetDeviceRegistryProperty(IntPtr set, ref DeviceInfo info, uint property, byte[] data, uint size);
    [DllImport("setupapi.dll", SetLastError=true)]
    static extern bool SetupDiCallClassInstaller(uint operation, IntPtr set, ref DeviceInfo info);
    [DllImport("setupapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool SetupDiGetDeviceInstanceId(IntPtr set, ref DeviceInfo info, StringBuilder id, uint size, out uint required);
    [DllImport("setupapi.dll", SetLastError=true)]
    static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
    [DllImport("newdev.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool UpdateDriverForPlugAndPlayDevices(IntPtr parent, string hardware, string inf, uint flags, out bool reboot);
    static void Check(bool ok) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    public static string CreateAdapter(string inf) {
        Guid guid = new Guid("4d36e972-e325-11ce-bfc1-08002be10318");
        IntPtr set = SetupDiCreateDeviceInfoList(ref guid, IntPtr.Zero);
        if (set == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
        DeviceInfo info = new DeviceInfo { Size = (uint)Marshal.SizeOf(typeof(DeviceInfo)) };
        bool registered = false;
        try {
            Check(SetupDiCreateDeviceInfo(set, "Net", ref guid, "dnsconfig smoke adapter", IntPtr.Zero, 1, ref info));
            byte[] hardware = Encoding.Unicode.GetBytes("*MSLOOP\0\0");
            Check(SetupDiSetDeviceRegistryProperty(set, ref info, 1, hardware, (uint)hardware.Length));
            Check(SetupDiCallClassInstaller(0x19, set, ref info));
            registered = true;
            StringBuilder id = new StringBuilder(512); uint required;
            Check(SetupDiGetDeviceInstanceId(set, ref info, id, 512, out required));
            bool reboot;
            Check(UpdateDriverForPlugAndPlayDevices(IntPtr.Zero, "*MSLOOP", inf, 1, out reboot));
            if (reboot) throw new Exception("loopback fixture requires a reboot");
            return id.ToString();
        } catch {
            if (registered) SetupDiCallClassInstaller(5, set, ref info);
            throw;
        } finally { SetupDiDestroyDeviceInfoList(set); }
    }

}
'@

# New-OwnedAdapter creates one owned loopback device. Driver binding selects
# by hardware ID, so the first call requires no existing MSLOOP device; a
# second owned device (-AllowExisting) rebinds the same inbox driver, which
# is a no-op for the device already bound. Each device gets its own address.
function New-OwnedAdapter([switch]$Preferred, [string]$Name = 'dnsconfig-smoke', [switch]$AllowExisting) {
    if (@(Get-NetAdapter -IncludeHidden | Where-Object Name -eq $Name).Count) { throw 'fixture name already exists' }
    if (!$AllowExisting -and (Get-CimInstance Win32_PnPEntity | Where-Object { $_.HardwareID -contains '*MSLOOP' })) {
        throw 'fixture requires no existing MSLOOP device because driver binding selects by hardware ID'
    }
    $deviceID = [OwnedAdapterNative]::CreateAdapter("$env:windir\INF\netloop.inf")
    $script:ownedDeviceIDs = @(@($script:ownedDeviceIDs) | Where-Object { $_ }) + $deviceID
    $adapter = $null
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        $device = Get-CimInstance Win32_NetworkAdapter | Where-Object PNPDeviceID -eq $deviceID
        if ($device.GUID) {
            $adapter = Get-NetAdapter -IncludeHidden | Where-Object { [guid]$_.InterfaceGuid -eq [guid]$device.GUID }
            if ($adapter) { break }
        }
        Start-Sleep -Seconds 1
    }
    if (!$adapter) { throw 'owned loopback adapter did not appear' }
    $adapter | Rename-NetAdapter -NewName $Name
    $adapter = Get-NetAdapter -Name $Name
    $address = if ($AllowExisting) { '203.0.113.101' } else { '203.0.113.100' }
    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $address -PrefixLength 32 -SkipAsSource $true | Out-Null
    Set-DnsClient -InterfaceIndex $adapter.ifIndex -RegisterThisConnectionsAddress $false
    if ($Preferred) {
        Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AutomaticMetric Disabled -InterfaceMetric 1
        $others = @(Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.ConnectionState -eq 'Connected' -and $_.InterfaceIndex -ne $adapter.ifIndex -and $_.InterfaceIndex -ne 1 })
        if (@($others | Where-Object InterfaceMetric -le 1).Count) { throw 'fixture is not the preferred connected IPv4 adapter' }
        if ((Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).InterfaceMetric -ne 1) { throw 'fixture metric did not apply' }
    }
    if ($adapter.Status -ne 'Up') { throw 'owned adapter is not Up' }
    Get-NetIPInterface | Sort-Object InterfaceIndex,AddressFamily | Format-Table InterfaceAlias,InterfaceIndex,AddressFamily,ConnectionState,AutomaticMetric,InterfaceMetric | Out-Host
    return $adapter
}
function Remove-OwnedAdapter {
    $failed = @()
    foreach ($deviceID in @(@($script:ownedDeviceIDs) | Where-Object { $_ })) {
        & pnputil /remove-device $deviceID | Out-Host
        if ($LASTEXITCODE) { $failed += $deviceID }
    }
    $script:ownedDeviceIDs = @()
    if ($failed.Count) { throw "owned device removal failed: $($failed -join ', ')" }
}
