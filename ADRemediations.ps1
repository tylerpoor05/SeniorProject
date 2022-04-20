#Password Policy Hardening
Get-ADUser -Filter * -SearchBase “OU=Users,DC=CSUDC01,DC=csu.local” | Set-ADUser -CannotChangePassword:$false -PasswordNeverExpires:$false -ChangePasswordAtLogon:$true
Set-ADUser -Identity Administrator -ChangePasswordAtLogon $true

#Disabling SMBv1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 –Force

#Disabling LLMNR
REG ADD  “HKLM\Software\policies\Microsoft\Windows NT\DNSClient”
REG ADD  “HKLM\Software\policies\Microsoft\Windows NT\DNSClient” /v ” EnableMulticast” /t REG_DWORD /d “0” /f

#Disabling NetBIOS
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}
