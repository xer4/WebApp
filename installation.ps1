#Test connection
if (!(Test-Connection 8.8.8.8 -Quiet)) {
    throw "No internet Connection"
}

# Enable ISS role and add features required for vulnerable web app
Import-Module ServerManager
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationDevelopment
Enable-WindowsOptionalFeature -online -FeatureName NetFx4Extended-ASPNET45
Enable-WindowsOptionalFeature -Online -FeatureName IIS-NetFxExtensibility45
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45 -All

#Create Web App Pool
Import-Module WebAdministration 
Remove-WebAppPool -Name "DefaultAppPool"
Get-Website | Remove-Website
$binding = "testApi.com"
$cert = New-SelfSignedCertificate -DnsName "$binding" -CertStoreLocation "cert:\LocalMachine\My"

$DestStore = new-object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::Root,"localmachine")
$DestStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$DestStore.Add($cert)
$DestStore.Close()

# Create web-site on port 43000/https, add certificate, and turn off SNI 
$appPoolName = "testApi-pool"
$appPool = New-WebAppPool $appPoolName
$siteName="testApi-web"
$webRootPath="C:\inetpub\wwwroot"
New-Website -Name $siteName -PhysicalPath $webRootPath -ApplicationPool $appPoolName -Port 43000 -SslFlags 0 -HostHeader $binding -Ssl
(Get-WebBinding -Name $siteName -Port 43000 -Protocol "https" -HostHeader $binding).AddSslCertificate($cert.Thumbprint, "my")

# Remove default ISS web page files
cd C:\inetpub\wwwroot\
Remove-Item .\* -Recurse -Force

# Download 7zip to extract content of password protected zip archive
$dlurl = 'https://7-zip.org/' + (Invoke-WebRequest -UseBasicParsing -Uri 'https://7-zip.org/' | Select-Object -ExpandProperty Links | Where-Object {($_.outerHTML -match 'Download')-and ($_.href -like "a/*") -and ($_.href -like "*-x64.exe")} | Select-Object -First 1 | Select-Object -ExpandProperty href)
# above code from: https://perplexity.nl/windows-powershell/installing-or-updating-7-zip-using-powershell/
$installerPath = Join-Path $env:TEMP (Split-Path $dlurl -Leaf)
Invoke-WebRequest $dlurl -OutFile $installerPath
Start-Process -FilePath $installerPath -Args "/S" -Verb RunAs -Wait
Remove-Item $installerPath

# Download vulnerable web application 
curl https://raw.githubusercontent.com/xer4/WebApp/main/final.zip -o final.zip
set-alias sz "$env:ProgramFiles\7-Zip\7z.exe"
sz x .\final.zip  -p7bDZ$bLX7bHW25o44SzHvBm2n#TBJY98@E7TgAzGBAZ$!N2 -aoa
Remove-Item .\final.zip

# Create flags
# IIS User
cd \
cmd.exe /c "echo FLAG: Ducking-Padlock-Tightrope0-Autograph-Richness > iis_user_flag.txt"
# Set read-only attribute
attrib +r C:\iis_user_flag.txt /s /d


$fPath="C:\system_secrets"
New-Item -type directory -path $fPath -force

# Get IIS App Pool security principal identity to set ACL on a folder
$sid = New-Object System.Security.Principal.SecurityIdentifier (
    Get-Item IIS:\AppPools\$appPoolName  | select -ExpandProperty applicationPoolSid
)
$identity = $sid.Translate([System.Security.Principal.NTAccount])
$identity.Value 


# Get the ACL for an existing folder
$existingAcl = Get-Acl -Path $fPath

# Set the DENY permissions to the folder
$permissions = $identity.Value, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Deny'

# Create a new FileSystemAccessRule object
$rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $permissions

# Modify the existing ACL to include the new rule
$existingAcl.SetAccessRule($rule)

# Apply the modified access rule to the folder
$existingAcl | Set-Acl -Path $fPath

cd $fPath
set-content -path system_flag.txt -Value "FLAG: Disloyal-Snowplow-Cobalt-Wobbling-Concert2"
set-content -path hidden_flag.txt -Value "That's not it, but you're almost there :)"
set-content -path hidden_flag.txt -Stream real_hidden_flag.txt -Value "FLAG: Jam-Gibberish-Surround-Campfire6-Thrash"

attrib +r $fPath"\*" /s /d

# Disable Firewall
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False

# Disable Defenders' real time minitoring feature
Set-MpPreference -DisableRealtimeMonitoring $true

$T = Get-Date
set-date "10/3/2019 2:00pm"

# Create new user
net user "f003xrp-ad1" "J20z19eF" /ADD /comment:"Local account for Jozef"

Set-Date -Date $T
# Clear powershell history 
Clear-History

#File with powershell history
Remove-Item (Get-PSReadlineOption).HistorySavePath -force

# Install updates
cmd.exe /c Wuauclt /detectnow
#$Updates = Start-WUScan -SearchCriteria "IsInstalled=0 AND IsHidden=0 AND IsAssigned=1"
#Install-WUUpdates -Updates $Updates
#$au = Invoke-CimMethod -Namespace root/microsoft/windows/windowsupdate  -ClassName MSFT_WUOperations -MethodName  #ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=0"}
#Invoke-CimMethod -Namespace root/microsoft/windows/windowsupdate  -ClassName MSFT_WUOperations -MethodName  #InstallUpdates -Arguments @{Updates = $au.Updates}

#$UpdateCleanupSuccessful = $false
#if (Test-Path $env:SystemRoot\Logs\CBS\DeepClean.log) {
#    $UpdateCleanupSuccessful = Select-String -Path $env:SystemRoot\Logs\CBS\DeepClean.log -Pattern 'Total size of superseded packages:' -Quiet
#}

SHUTDOWN.EXE /r /f /t 0 /c 'Init....'
