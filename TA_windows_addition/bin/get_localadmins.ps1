function Get-RecursiveGroupMembers {
	[CmdletBinding(DefaultParametersetname="DomainGroup")]
    param(
        [Parameter(ValueFromPipeline=$true,ParameterSetName="LocalGroup")]
        [String[]]$ComputerName,
		[Parameter(ParameterSetName="DomainGroup")]
		[String]$Domain,
        [String]$Group = "Administrators"
    )

    begin {
		$Count = 0
		$Array = New-Object System.Collections.Generic.List[System.Object]
        $global:QueryGroup = $Group
	}

    process {
		If($PSCmdlet.ParameterSetName -like "LocalGroup") {
			$Array.add($ComputerName[0])
		}
   }

   end {
		#Private function for recursion
		function Get-Members {
			param(
				[String]$ComputerName,
				[String]$Domain,
				[String]$Group,
				[String[]]$Path
			)
			
			#If it's a domain group, run command from local machine
			If($ComputerName -notlike $Domain) {
				$Members = Get-WmiObject Win32_GroupUser -Filter "GroupComponent=`"Win32_Group.Domain='$Domain',Name='$Group'`"" | %{$_.PartComponent}
			}
			else { 
				$Members = Get-WmiObject -ComputerName $ComputerName  Win32_GroupUser -Filter "GroupComponent=`"Win32_Group.Domain='$Domain',Name='$Group'`"" | %{$_.PartComponent}
			}
			
			Write-Verbose "Filter: GroupComponent=`"Win32_Group.Domain='$Domain',Name='$Group'`""
			Foreach($Member in $Members) {
				Write-Verbose $Member
				#Parsing the string is faster than resolving to a WMI object
				$Regex = [Regex]::Match($Member, '(?i)cimv2:(.+?)\.Domain="(.+?)",Name="(.+?)"')
				$Class  = $Regex.Groups[1].Value
				$Domain = $Regex.Groups[2].Value
				$Name   = $Regex.Groups[3].Value
				
				If($Script:Done -notcontains $Name) {
					$Script:Done.add($Name)
					If($Class -like "Win32_Group") {
						#Don't loop into the current group
						If($Name -notlike $Group) {
							Write-Verbose "Calling get-members with group $Name"
							Get-Members -ComputerName $ComputerName -Domain $Domain -Group $Name -Path ($Path + "$Domain\$Name")
						}
					}
					ElseIf($Name) {
						New-Object PSObject -Property @{
                            time = Get-Date -Format "yyyy-MM-dd HH:mm:ss";
                            QueryGroup = $global:QueryGroup;
							ComputerName = $ComputerName;
							User = "$Domain\$Name";
							MemberPath = ($Path -join("|"));}
					}
				}
			}
		}
		
		$Total = $Array.count
		$ComputerName = $Array

		If($PSCmdlet.ParameterSetName -like "LocalGroup") {
			#Local group, need remote administrator access to the computer
			Foreach($Computer in $ComputerName) {
				Write-Progress -Activity "Collecting users" -PercentComplete ($Count/$Total*100) -Status "$Count/$Total : $Computer"
				$Script:Done  = New-Object System.Collections.Generic.List[System.Object]

				#Actual name of the PC could be different and break the filter (DNS mixup)
				$RealName = (Get-WmiObject -ComputerName $Computer Win32_ComputerSystem).Name

				Get-Members -ComputerName $RealName -Domain $RealName -Group $Group -Path @($Group)
				
				$Count++
			}
		}
		Else {
			$Script:Done  = New-Object System.Collections.Generic.List[System.Object]
			
			If(!($Domain)) {
				$Domain = $env:USERDOMAIN
			}

			Get-Members -Domain $Domain -Group $Group -Path @($Group)
		}
   }
}

$results=Get-RecursiveGroupMembers -ComputerName $env:COMPUTERNAME
$results | % { Write-Host ($_ | ConvertTo-Json -Compress)}


