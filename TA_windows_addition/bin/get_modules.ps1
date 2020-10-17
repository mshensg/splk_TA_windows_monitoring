$allProcesses = [System.Diagnostics.Process]::GetProcesses()
$moduledetails = @()
foreach($p in $allProcesses)
{
    $pinfo = $p | Select-Object Name, Id, ProcessName, FileVersion, Path
    foreach($m in $p.Modules){
        if ($m.Company -eq "Microsoft Corporation"){
        }else{
            $filename = $m.FileName.ToLower()
            $existingModule = $moduledetails | Where-Object {$_.FileName -eq $filename}
            if($existingModule){
                if($existingModule.Count){
                    $existingModule = $existingModule[0]
                }
                $existingModule.CallingProcesses += , $pinfo
            }else{
                $obj=$m | Select-Object ModuleName,FileName,ModuleMemorySize,FileVersionInfo,Company,Description,FileVersion,Product,ProductVersion,Size, Processes, CallingProcesses
                $obj.FileName = $filename
                $obj.CallingProcesses = @($pinfo)

                Add-Member -InputObject $obj -MemberType NoteProperty -Name SHA256Hash -Value (Get-FileHash $filename -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                Add-Member -InputObject $obj -MemberType NoteProperty -Name MD5Hash -Value (Get-FileHash $filename -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
                Add-Member -InputObject $obj -MemberType NoteProperty -Name SHA1Hash -Value (Get-FileHash $filename -Algorithm SHA1 -ErrorAction SilentlyContinue).Hash
                Add-Member -InputObject $obj -MemberType NoteProperty -Name SHA512Hash -Value (Get-FileHash $filename -Algorithm SHA512 -ErrorAction SilentlyContinue).Hash
                $fileinfo = Get-AuthenticodeSignature $filename 
                $certificateinfo = $fileinfo | Select-Object SignerCertificate,TimeStamperCertificate,CertificateStatus,CertificateStatusMessage
                $certificateinfo.SignerCertificate = $fileinfo.SignerCertificate | Select-object Subject, FriendlyNamem, Issuer, @{n="NotAfter";e={$_.NotAfter.ToString("o")}}, @{n="NotBefore";e={$_.NotBefore.ToString("o")}}, SerialNumber, Thumbprint, DnsNameList,EnhancedKeyUsageList, SendAsTrustedIssuer
                $certificateinfo.TimeStamperCertificate = $fileinfo.TimeStamperCertificate | Select-object Subject, FriendlyNamem, Issuer, @{n="NotAfter";e={$_.NotAfter.ToString("o")}}, @{n="NotBefore";e={$_.NotBefore.ToString("o")}}, SerialNumber, Thumbprint, DnsNameList,EnhancedKeyUsageList, SendAsTrustedIssuer
                Add-Member -InputObject $obj -MemberType NoteProperty -Name CertificateInfo -Value $certificateinfo
                $fileversion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($filename) | select-object CompanyName,FileVersion,OriginalFilename,Language,InternalName
                Add-Member -InputObject $obj -MemberType NoteProperty -Name ExecutableDetails -Value $fileversion

                $moduledetails += $obj
            }
        }
    }
}

$moduledetails | ForEach-Object {Write-Output ($_ | ConvertTo-Json -Compress)}