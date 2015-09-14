function Invoke-ExplorerNetonly {
    <#
    .SYNOPSIS
    Enables explorer.exe to be used through runas /netonly by
    setting a particular registry key.

    .PARAMETER Restore
    Restore the registry key to its original value.
    #>

    [CmdletBinding()]
    param(
        [switch]
        $Restore
    )

    # make sure everything stops if there's an error
    $ErrorActionPreference = "Stop"

    # check to ensure the script's being run from an elevated context
    if(!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
        throw "[!] This script must be run from an elevated context!"
    }

    $definition = @"
using System;
using System.Runtime.InteropServices; 

namespace Win32Api
{

	public class NtDll
	{
		[DllImport("ntdll.dll", EntryPoint="RtlAdjustPrivilege")]
		public static extern int RtlAdjustPrivilege(ulong Privilege, bool Enable, bool CurrentThread, ref bool Enabled);
	}
}
"@ 

    $null = Add-Type -TypeDefinition $definition -PassThru

    $bEnabled = $false

    #Elevate our privs on the process so we can change the owner of this key
    try {
        $Null = [Win32Api.NtDll]::RtlAdjustPrivilege(9, $true, $false, [ref]$bEnabled)
        Write-Verbose "Privileges elevated with RtlAdjustPrivilege"
    }
    catch {
        throw "Error running RtlAdjustPrivilege to elevate privileges"
    }

    try {
        #First grant ownership to ourselves
        $key = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey("AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::takeownership)
        $acl = $key.GetAccessControl()
        $acl.SetOwner([System.Security.Principal.NTAccount]$env:UserName)
        $key.SetAccessControl($acl)
        Write-Verbose "Ownership of key 'AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' granted to current user '$env:UserName'"
    }
    catch {
        throw "Error opening key 'AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}'"
    }

    #Re-open the key so we can change permissions this time
    $key = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey("AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions)
    $acl = $key.GetAccessControl()

    #Grant FullControl to our user
    $args = $env:UserName, "FullControl", "Allow"
    $newrule = New-Object Security.AccessControl.RegistryAccessRule $args
    $acl.SetAccessRule($newrule)
    $key.SetAccessControl($acl)
    Write-Verbose "Full control of key 'AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' granted to current user '$env:UserName'"
    
    #Add a PSDrive for KHCR
    $null = New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT

    if($Restore) {
        #rename the key back to its original setting
        Rename-ItemProperty -Path "HKCR:\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}" -Name _RunAs -NewName RunAs
        Write-Verbose "'_RunAs' key in 'AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' renamed to 'RunAs'"
        "Key restored"
    }
    else {
        #rename the key
        Rename-ItemProperty -Path "HKCR:\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}" -Name RunAs -NewName _RunAs
        Write-Verbose "'RunAs' key in 'AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' renamed to '_RunAs'"
        "Key set successfully, launch explorer with 'runas /netonly /user:DOMAIN\user explorer.exe'"
    }
    Remove-PSDrive -Name HKCR
}
