$s = Get-WmiObject -Query "Select * from Win32_Process"
$processes = $s | Select-Object @{n="timestamp";e={Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff K"}},Caption,CommandLine,CreationDate,Description,ExecutablePath,ExecutionState,Handle,HandleCount,InstallDate,KernelModeTime,MaximumWorkingSetSize,MinimumWorkingSetSize,Name,OtherOperationCount,OtherTransferCount,PageFaults,PageFileUsage,ParentProcessId,PeakPageFileUsage,PeakVirtualSize,PeakWorkingSetSize,Priority,PrivatePageCount,ProcessId,QuotaNonPagedPoolUsage,QuotaPagedPoolUsage,QuotaPeakNonPagedPoolUsage,QuotaPeakPagedPoolUsage,ReadOperationCount,ReadTransferCount,SessionId,Status,TerminationDate,ThreadCount,UserModeTime,VirtualSize,WorkingSetSize,WriteOperationCount,WriteTransferCount

$executables = ($processes  | select-object @{n="ExecutablePath";e={$_.ExecutablePath.ToLower()} } -Unique) | where-object {$_.ExecutablePath -ne $null -and (Test-Path $_.ExecutablePath -ErrorAction SilentlyContinue)}

foreach($exe in $executables)
{
    Add-Member -InputObject $exe -MemberType NoteProperty -Name SHA256Hash -Value (Get-FileHash $exe.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    Add-Member -InputObject $exe -MemberType NoteProperty -Name MD5Hash -Value (Get-FileHash $exe.ExecutablePath -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
    Add-Member -InputObject $exe -MemberType NoteProperty -Name SHA1Hash -Value (Get-FileHash $exe.ExecutablePath -Algorithm SHA1 -ErrorAction SilentlyContinue).Hash
    Add-Member -InputObject $exe -MemberType NoteProperty -Name SHA512Hash -Value (Get-FileHash $exe.ExecutablePath -Algorithm SHA512 -ErrorAction SilentlyContinue).Hash
    $fileinfo = Get-AuthenticodeSignature $exe.ExecutablePath 
    $certificateinfo = $fileinfo | Select-Object SignerCertificate,TimeStamperCertificate,CertificateStatus,CertificateStatusMessage
    $certificateinfo.SignerCertificate = $fileinfo.SignerCertificate | Select-object Subject, FriendlyNamem, Issuer, @{n="NotAfter";e={$_.NotAfter.ToString("o")}}, @{n="NotBefore";e={$_.NotBefore.ToString("o")}}, SerialNumber, Thumbprint, DnsNameList,EnhancedKeyUsageList, SendAsTrustedIssuer
    $certificateinfo.TimeStamperCertificate = $fileinfo.TimeStamperCertificate | Select-object Subject, FriendlyNamem, Issuer, @{n="NotAfter";e={$_.NotAfter.ToString("o")}}, @{n="NotBefore";e={$_.NotBefore.ToString("o")}}, SerialNumber, Thumbprint, DnsNameList,EnhancedKeyUsageList, SendAsTrustedIssuer
    Add-Member -InputObject $exe -MemberType NoteProperty -Name CertificateInfo -Value $certificateinfo
    $fileversion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe.ExecutablePath) | select-object CompanyName,FileVersion,OriginalFilename,Language,InternalName
    Add-Member -InputObject $exe -MemberType NoteProperty -Name ExecutableDetails -Value $fileversion
}

foreach ($p in $processes)
{
    $ppid = $p.ParentProcessId
    $parentp = $processes | Where-Object {$_.ProcessId -eq $ppid}
    if($parentp -ne $null)
    {
        if($parentp.count -ne $null){
            $parentp = $parentp[0]
        }
        Add-Member -InputObject $p -MemberType NoteProperty -Name ParentProcessName -Value $parentp.Name
        Add-Member -InputObject $p -MemberType NoteProperty -Name ParentProcessCommandLine -Value $parentp.CommandLine
        Add-Member -InputObject $p -MemberType NoteProperty -Name ParentProcessExecutablePath -Value $parentp.ExecutablePath
        $pppid = $parentp.ParentProcessId
        $grandparentp = $processes | Where-Object {$_.ProcessId -eq $pppid}
        if($grandparentp -ne $null)
        {
            if($grandparentp.count -ne $null){
                $grandparentp = $grandparentp[0]
            }
            Add-Member -InputObject $p -MemberType NoteProperty -Name GrandParentProcessId -Value $grandparentp.ProcessId
            Add-Member -InputObject $p -MemberType NoteProperty -Name GrandParentProcessName -Value $grandparentp.Name
            Add-Member -InputObject $p -MemberType NoteProperty -Name GrandParentProcessCommandLine -Value $grandparentp.CommandLine
            Add-Member -InputObject $p -MemberType NoteProperty -Name GrandParentProcessExecutablePath -Value $grandparentp.ExecutablePath
        }
    }
    $pexec = $p.ExecutablePath
    $filedetails = $executables | where-object {$_.ExecutablePath -eq $pexec}
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

$processes | ForEach-Object {Write-Output ($_ | ConvertTo-Json -Compress)}
