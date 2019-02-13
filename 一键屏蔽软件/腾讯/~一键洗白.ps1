# Self-Elevating script
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
  # Relaunch as an elevated process:
  Start-Process powershell.exe "-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
  exit
}

# For each cert in the folder, delete it from the disallowed store
$certList = Get-ChildItem -Recurse $PSScriptRoot -Filter *.cer | Where { ! $_.PSIsContainer } | Select Name,FullName,Length
foreach ($cert in $certList) 
    {
        $certPrint = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $certPrint.Import($cert.FullName)
	certutil -user -delstore "Disallowed" $certPrint.Thumbprint
    }