$s = Get-WmiObject -Query "Select * from Win32_Service"

$services = $s | Select-Object @{n="timestamp";e={Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K"}},AcceptPause,AcceptStop,Caption,DelayedAutoStart,Description,DesktopInteract,DisplayName,ErrorControl,ExitCode,InstallDate,Name,PathName,ProcessId,ServiceType,Started,StartMode,StartName,State,Status

$executables = $s | ForEach-Object {$_.PathName.SubString(0,$_.PathName.ToLower().IndexOf(".exe")+4)}

$executables = ($executables | Select-Object @{n="PathName";e={$_.ToLower()} } -Unique) | Where-Object {$_.PathName -ne $null -and (Test-Path $_.PathName -ErrorAction SilentlyContinue)}

foreach($exe in $executables)
{
    Add-Member -InputObject $exe -MemberType NoteProperty -Name SHA256Hash -Value (Get-FileHash $exe.PathName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    Add-Member -InputObject $exe -MemberType NoteProperty -Name MD5Hash -Value (Get-FileHash $exe.PathName -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
    Add-Member -InputObject $exe -MemberType NoteProperty -Name SHA1Hash -Value (Get-FileHash $exe.PathName -Algorithm SHA1 -ErrorAction SilentlyContinue).Hash
    Add-Member -InputObject $exe -MemberType NoteProperty -Name SHA512Hash -Value (Get-FileHash $exe.PathName -Algorithm SHA512 -ErrorAction SilentlyContinue).Hash
    $fileinfo = Get-AuthenticodeSignature $exe.PathName 
    $certificateinfo = $fileinfo | Select-Object SignerCertificate,TimeStamperCertificate,Status,StatusMessage
    $certificateinfo.SignerCertificate = $fileinfo.SignerCertificate | Select-object Subject, FriendlyNamem, Issuer, @{n="NotAfter";e={$_.NotAfter.ToString("o")}}, @{n="NotBefore";e={$_.NotBefore.ToString("o")}}, SerialNumber, Thumbprint, DnsNameList,EnhancedKeyUsageList, SendAsTrustedIssuer
    $certificateinfo.TimeStamperCertificate = $fileinfo.TimeStamperCertificate | Select-object Subject, FriendlyNamem, Issuer, @{n="NotAfter";e={$_.NotAfter.ToString("o")}}, @{n="NotBefore";e={$_.NotBefore.ToString("o")}}, SerialNumber, Thumbprint, DnsNameList,EnhancedKeyUsageList, SendAsTrustedIssuer
    Add-Member -InputObject $exe -MemberType NoteProperty -Name CertificateInfo -Value $certificateinfo
    $fileversion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe.PathName) | select-object CompanyName,FileVersion,OriginalFilename,Language,InternalName
    Add-Member -InputObject $exe -MemberType NoteProperty -Name ExecutableDetails -Value $fileversion
}

foreach ($p in $services)
{
    $pexec = $p.PathName.SubString(0,$p.PathName.ToLower().IndexOf(".exe")+4)
    $filedetails = $executables | where-object {$_.PathName -eq $pexec}
    if($filedetails -ne $null){

        if($filedetails.count -ne $null){
            $filedetails = $filedetails[0]
        }
        Add-Member -InputObject $p -MemberType NoteProperty -Name SHA256Hash -Value $filedetails.SHA256Hash
        Add-Member -InputObject $p -MemberType NoteProperty -Name MD5Hash -Value $filedetails.MD5Hash
        Add-Member -InputObject $p -MemberType NoteProperty -Name SHA1Hash -Value $filedetails.SHA1Hash
        Add-Member -InputObject $p -MemberType NoteProperty -Name SHA512Hash -Value $filedetails.SHA512Hash

        Add-Member -InputObject $p -MemberType NoteProperty -Name CertificateInfo -Value $filedetails.CertificateInfo

        Add-Member -InputObject $p -MemberType NoteProperty -Name ExecutableDetails -Value $filedetails.ExecutableDetails
    }
}
$services | ForEach-Object {Write-Output ($_ | ConvertTo-Json -Compress)}
