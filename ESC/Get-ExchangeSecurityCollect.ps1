<#
Disclaimer:
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims
all implied warranties including, without limitation, any implied warranties of merchantability
or of fitness for a particular purpose. The entire risk arising out of the use or performance of
the sample scripts and documentation remains with you. In no event shall Microsoft, its authors,
or anyone else involved in the creation, production, or delivery of the scripts be liable for any
damages whatsoever (including, without limitation, damages for loss of business profits, business
interruption, loss of business information, or other pecuniary loss) arising out of the use of or
inability to use the sample scripts or documentation, even if Microsoft has been advised of the
possibility of such damages

Version : 2.0
Released : 09/11/2022
Develop by ksangui@microsoft.com
Thanks for those who helped me !
Especially Nicolas Lepagnez and Lucas Zinck

The method to export data to Excel was inspired from the script Exchange Data Collector (ExDC) from
https://github.com/stemy-msft/exchange-data-collector
stemy-MS
#>

<#
.SYNOPSIS
    This script collect Exchange information related to Security. The ESC_XLS.PS1 script will next be used to generated an Excel file with collected data
.DESCRIPTION
    This script use the CSV file InputESC.csv to determine by section all information that will be collected with selected settings
.PARAMETER .path
    Specify the folder where the txt file will be stored. The format could be d;\ESC\output or d:\ESC\Output\. If not specify, the script will create an Output folder to store TXT files
.PARAMETER Inputcsvpath
    Specify the folder where the CSV file are store. The format could be d;\ESC\input or d:\ESC\input\. If not specify, the script will use the current folder
.PARAMETER DumpConfig
    Set this setting to $True if you want to dump Exchange configuration settings
.PARAMETER Quickmode
    Set this setting to $True to bypass all the tests that take time by connecting to servers
.PARAMETER EPS2010
Set this setting to $True if Exchange Management Shell 2010 is currently used
.PARAMETER EDGE
Set this setting to $True if the script is launched on an edge server
.PARAMETER CloudEXO
Set this setting to $True if you want to dump EXO configurations
.NOTES
    Version:        1.0
    Author:         Karine Sanguinet
    Creation Date:  03/20/2021
    Update :   03/25/2021
    Updater:   Lucas Zink
    Purpose/Change: Script Version 1.0
    Update :   10/06/2021
    Updater:   Karine Sanguinet
    Purpose/Change: Add Edge server support, check config for CVE 1730, change parameter Outputpath to path, change the gc retrieval
    New script version : Script Version 1.0.1
    Last Update :   10/07/2021
    Last Updater:   Karine Sanguinet
    Purpose/Change: Add CloudEXO dump configuration
    New script version : Script Version 1.0.2
    Last Update :   06/08/2022
    Last Updater:   Karine Sanguinet
    Purpose/Change: Add tab Exchange version for SU and CU
    New script version : Script Version 1.0.4
    Last Update :   09/11/2022
    Last Updater:   Karine Sanguinet
    Purpose/Change: Change the script name and versioning 2.0
    New script version : Script Version 2.0

.EXAMPLE
    C:\ESC> .\ESC.ps1
.EXAMPLE
    C:\ESC> .\ESC.ps1 -path C:\ESC\Output 
.EXAMPLE
    C:\ESC> .\ESC.ps1 -path C:\ESC\Output -Inputcsvpath C:\ESC -DumpConfig $fase
.EXAMPLE
    C:\ESC> .\ESC.ps1 -path C:\ESC\Output -Quickmode $true
.EXAMPLE
    C:\ESC> .\ESC.ps1 -path C:\ESC\Output -EPS2010 $true
.EXAMPLE
    C:\ESC> .\ESC.ps1 -path C:\ESC\Output -EDGE $true
.EXAMPLE
    C:\ESC> .\ESC.ps1 -path C:\ESC\Output -CloudEXO $true
.EXAMPLE
    C:\ESC> .\ESC.ps1 -EPS2010 $true
.EXAMPLE
    C:\ESC> .\ESC.ps1 -EDGE $true
.EXAMPLE
    C:\ESC> .\ESC.ps1 -CloudEXO $true
#>


Param (
    [Parameter(Mandatory=$false,HelpMessage="Specify the path where the collected file will be created")]
    $path=$Null,
    [Parameter(Mandatory=$false,HelpMessage="Specify the path where the input CSV are store")]
    $Inputcsvpath=$Null,
    [Parameter(Mandatory=$false,HelpMessage="Specify if configuration settings will be retrieve")]
    $DumpConfig=$true,
    [Parameter(Mandatory=$false,HelpMessage="Specify if the script will pass cmdlet that need to connect to servers")]
    $Quickmode=$false,
    [Parameter(Mandatory=$false,HelpMessage="Specify if a PowerhShell session is connected to an Exchange 2010")]
    $EPS2010=$false,
    [Parameter(Mandatory=$false,HelpMessage="Specify if the server is an EDGE server")]
    $EDGE=$false,
    [Parameter(Mandatory=$false,HelpMessage="Specify if you want to dump Cloud EXO config")]
    $CLOUDEXO=$false
)

#Function to retrieve AD information
Function GetADInfo
{
    #Check if the Active Directory module is install if not remote session to a DC

    #Retrieve AD info
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    #$gc= $forest.NamingRoleOwner.name
    #$gc=(Get-ADServerSettings).DefaultGlobalCatalog
    $config = ([ADSI]"LDAP://RootDSE").configurationNamingContext.Value
	$gc=($forest).rootdomain.name

    #for each of the domains get the netbios name and locate the closest DC
    $forest.Domains | ForEach-Object `
    {
        $domain_names = $_.name
        
        $domain_names | ForEach-Object {
            $domain_name = $_ 
            $domain_context = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$domain_name)
            $domain_dc_fqdn = ([System.DirectoryServices.ActiveDirectory.DomainController]::findOne($domain_context)).Name

            #Only the config partition has the netbios name of the domain
            $config_search = New-Object -TypeName System.DirectoryServices.DirectorySearcher("LDAP://CN=Partitions,$config","(&(dnsRoot=$domain_name)(systemFlags=3))","nETBIOSName",1)
            $result = $config_search.FindOne()
            
            #$domain_netbios = $($config_search.FindOne().Properties.netbiosname)
            $script:ht_domains += @{
                $($result.Properties.netbiosname) = @{
                    DCFQDN = $domain_dc_fqdn
                    DomainFQDN = $domain_name
                    #JustAdd
                    DomainDN = $($result.Properties.ncname)
                }
            }
        }
    }
    $forestDN =($forest.Schema| ForEach-Object {$_ -replace ("CN=Schema,CN=Configuration,","")})
    $SIDRoot=(New-Object Security.Principal.Securityidentifier(([ADSI]"LDAP://$($forest.name)").objectSid[0],0)).Value
    Return $forest, $forestDN, $gc, $SIDRoot
}

#Function to retrive a list of servers that respond to ping. Allow to avoid later to test non reachable servers
Function GetListSrvOK
{
    Param(
        $server
     )
    #Test WSMAn and not a simple ping
    $F_res=Test-Connection -ComputerName $server -count 3 -Quiet
    return $F_res
}

#Retrieve the Number of ExchangeServer per version and build the list of SRVUp
Function GetExchver
{
    Param(
        $EPS2010,
        $EDGE
     )
    if ($edge -eq $false)
    {
    $servers= get-exchangeserver | ? { $_.ServerRole -notlike "*edge*"}
    $exch2010=0
    $exch2013=0
    $exch2016=0
    $exch2019=0

    #Check and Count theservers for each version
    $ListSRVUp=@()
    $ListSRVunreach=@()
    foreach ($srv in $servers)
    {
        $srvstatus=GetListsrvOK -Server $srv.fqdn
        if ($srvstatus)
        {
            $ListSRVUp+=$srv.FQDN
			$ListNameSRVUp+=$srv.name
        }
        Else
        {
            $ListNameSRVunreach+=$srv.name
			$ListSRVunreach+=$srv.FQDN
        }
        If ($srv.AdminDisplayVersion -like "*14.*")
        {
            $exch2010=$exch2010+1
        }
        elseif ($srv.AdminDisplayVersion -like "*15.0*")
        {
            $exch2013=$exch2013+1
        }
        elseif ($srv.AdminDisplayVersion -like "*15.1*")
        {
            $exch2016=$exch2016+1
        }
        elseif ($srv.AdminDisplayVersion -like "*15.2*")
        {
            $exch2019=$exch2019+1
        }
    }
    Write-Host "Edge servers are not check. To check an Edge server, launch the script on Edge with the setting -edge '$true'" -ForegroundColor Green
    }
    else
    {
         $ListSRVUp= (get-exchangeserver | ? { $_.ServerRole -like "*edge*"}).name
    }
    #Check if the parameter EPS2010 has set to true when launching the script or there is no Exchange server other than Exchange 2010. Some tasks will be adapt depending of powershell version
    If ($exch2013+$exch2016+$exch2019 -eq 0  -or $EPS2010 -eq $true  )
    {
        $EPS2010 = $true
    }
    Write-Host "List of current servers that respond to ping : " $ListNameSRVUp -ForegroundColor Cyan
    Write-Host "List of current servers that do not respond to ping : " $ListNameSRVunreach -ForegroundColor magenta
    
    return $ListSRVUp, $ListNameSRVUp, $EPS2010
}

#Check and correct the -path value by removing \ at the end if necessary  and set the value $pathInputCSV
Function Getpath
{
    Param(
        $Outputpath,
        $Inputcsvpath
    )

    #Check if param path is empty if Yes use current location
    If ($Outputpath -eq $null)
    {
        
        $Outputpath ="$((get-location).tostring())\output"
        Write-Host "Path paramater is not set. Collection use $Outputpath" -ForegroundColor Green

    }
    If (!(Test-Path -PathType Container $Outputpath))
    {
        Write-Host "Path $Outputpath not exist, creation started" -ForegroundColor Yellow
        New-Item -ItemType Directory -Path $Outputpath | Out-Null
    }

    #If Check if a specific path has been enter for Input CSV, needed ifparam Path is different from script location
    if ($Inputcsvpath -eq $Null)
    {
	    $Inputcsvpath =(get-location).tostring()
    }
	$Inputcsvpath=$Inputcsvpath.TrimEnd("\")
    $Outputpath=$Outputpath.TrimEnd("\")

    return $Outputpath, $Inputcsvpath
}

#Function to construct the output file which depend on the section currently processing
Function GetOutputFile
{
    Param(
        $path, 
        $Section
     )
    $F_ESC_outputfile = $path + "\ESC_"+$Section+".txt"
    return $F_ESC_outputfile
}

#From the collected data create the txt output for each section. Depending of the section some adjustments has to be done for the file creation
Function GetAllData
{
    Param(
        $AllData=@(),
		$OutputFile,
        $paraminfos=@(),
        $srvin=$Null
     )

    $output_ESC=@()
    [string]$output_ESC_temp = ""

    foreach ( $infos in $AllData)
    {
        foreach ( $info in $infos)
        {
        [array]$output_ESC = $null
        [string]$output_ESC_temp = $null
            if ($srvin -ne $null)
            {
                $output_ESC_temp +=$srvin + "`t"
            }
            #Create output file send to the Function by spliting data and add it to the output file
                foreach ( $paraminfo in $paraminfos)
                {
                    if($paraminfo -notlike "*SrvName*")
                    {
                        #Add the output variable
                        $output_ESC_temp +=[string]$info.$paraminfo + "`t"
                    }
                }
        #Add theOoutput to section file
        $output_ESC=$output_ESC_Temp
        $output_ESC | out-file $OutputFile -append
        }
    }
}

#Retrieve details user or group information like PasswordLastSet and construct the object with all information
Function GetDetails
{
    Param(
        $TargetObject,
        $Level,
        $ParentgroupI
    )

    $MyObject = new-Object PSCustomObject
    $MyObject | Add-Member -MemberType NoteProperty -Name "Parentgroup" -Value $ParentgroupI
    $MyObject | Add-Member -MemberType NoteProperty -Name "Level" -Value $Level
    $MyObject | Add-Member -MemberType NoteProperty -Name "ObjectClass" -Value $TargetObject.objectClass
    $MyObject | Add-Member -MemberType NoteProperty -Name "MemberPath" -Value $TargetObject.Name
    if ($TargetObject.objectClass -like "User")
    {
        $DN=[string]$TargetObject
        
        if ($script:GUserArray.keys -notcontains $DN)
        {
            $User = Get-ADUser $TargetObject.SAMAccountName -server ($DN.Substring($dn.IndexOf("DC=")) -replace ",DC=","." -replace "DC=") -Properties LastLogonDate, PasswordLastSet, Enabled, homeMDB | SELECT SamAccountName,Name,GivenName,Enabled,homemdb,LastLogonDate,PasswordLastSet,DistinguishedName
            If ($User.homeMDB -ne $Null)
            {
                $HasMbx = "True"
            }
            Else
            {
                $HasMbx = "False"
            }
            $script:GUserArray += @{
                $User.DistinguishedName = @{
                    UDN = $User.DistinguishedName
                    USamAccountName = $User.SamAccountName
                    ULastLogonDate = $User.LastLogonDate
                    UPasswordLastSet = $User.PasswordLastSet
                    UEnabled = $User.Enabled
                    UHasMbx=$HasMbx
                    UNetbiosDom = ($script:ht_domains.GetEnumerator() | ?{$_.value.DomainDN -like $DN.Substring($dn.IndexOf("DC="))}).key
                    ULogonNetb = ($script:ht_domains.GetEnumerator() | ?{$_.value.DomainDN -like $DN.Substring($dn.IndexOf("DC="))}).key+"\"+$TargetObject.SAMAccountName
                }
            }
        }
        $MyObject | Add-Member -MemberType NoteProperty -Name "DN" -Value $script:GUserArray[$DN].UDN
        $MyObject | Add-Member -MemberType NoteProperty -Name "LastLogonDate" -Value $script:GUserArray[$DN].ULastLogonDate
        $MyObject | Add-Member -MemberType NoteProperty -Name "PasswordLastSet" -Value $script:GUserArray[$DN].UPasswordLastSet
        $MyObject | Add-Member -MemberType NoteProperty -Name "Enabled" -Value $script:GUserArray[$DN].UEnabled
        $MyObject | Add-Member -MemberType NoteProperty -Name "HasMbx" -Value $script:GUserArray[$DN].UHasMbx
        # Has to be NULL
        $MyObject | Add-Member -MemberType NoteProperty -Name "Members" -Value $null
    }
    elseif ($TargetObject.objectClass -like "Group")
    {
        $MyObject | Add-Member -MemberType NoteProperty -Name "Members" -Value $null
        $MyObject | Add-Member -MemberType NoteProperty -Name "DN" -Value $TargetObject.DistinguishedName

        # Has to be NULL
        $MyObject | Add-Member -MemberType NoteProperty -Name "LastLogon" -Value $null
        $MyObject | Add-Member -MemberType NoteProperty -Name "LastPwdSet" -Value $null
        $MyObject | Add-Member -MemberType NoteProperty -Name "Disabled" -Value $null
        $MyObject | Add-Member -MemberType NoteProperty -Name "HasMbx" -Value $null
    }
    else
    {
        # Has to be NULL
        $MyObject | Add-Member -MemberType NoteProperty -Name "DN" -Value $TargetObject.DistinguishedName
        $MyObject | Add-Member -MemberType NoteProperty -Name "LastLogon" -Value $null
        $MyObject | Add-Member -MemberType NoteProperty -Name "LastPwdSet" -Value $null
        $MyObject | Add-Member -MemberType NoteProperty -Name "Disabled" -Value $null
        $MyObject | Add-Member -MemberType NoteProperty -Name "HasMbx" -Value $null
        $MyObject | Add-Member -MemberType NoteProperty -Name "Members" -Value $null
    }
    return $MyObject
}

#Retrieve group member
Function GetMember
{
    Param (
        $TargetObject,
        $dnsrvobj
    )
    $list = Get-ADGroupMember $TargetObject.SamAccountName -server $dnsrvobj
    return $List
}

#Create the MemberPath value
Function GenerateMembersDetail
{
    Param (
        $ResultTable,
        $Name
    )

    foreach ($Result in $ResultTable)
    {
        $Result.MemberPath = $Name + "\" + $Result.MemberPath
    }
    return $ResultTable
}

#Call Function to retrieve group member and user spceific information and Function to create the MemberPath
Function GetInfo
{
    Param (
        $TargetObject,
        $Level = $null,
        $parentgroup
    )

    if ($level -ne $null)
    {
        $Level++
        #$begin = $false
    }
    else
    {
        $level = 0
        #$Begin = $true
    }
    $InfoTable = @()

    #Call Function to create member path parameter
    $InfoResult = GetDetails -TargetObject $TargetObject -Level $Level -Parentgroup $parentgroup
    $InfoTable += $InfoResult
    if ($TargetObject.ObjectClass -like "Group")
    {
        #Call Function to retrieve group content
        $dnsrv= (($TargetObject.DistinguishedName).Substring(($TargetObject.DistinguishedName).IndexOf("DC=")) -replace ",DC=","." -replace "DC=")
        $list = GetMember -TargetObject $TargetObject -dnsrvobj $dnsrv
        $InfoResult.Members = $list
        foreach ($member in $list)
        {
            $ResultTable = GetInfo -TargetObject $member -Level $Level -Parentgroup $parentgroup
            $ResultTable = GenerateMembersDetail -ResultTable $ResultTable -Name $TargetObject.Name
            $InfoTable += $ResultTable
        }
    }
    return $InfoTable
}

#Retrieve group member, retrieve information for local user, call Function GetInfo and GetAllData
Function GetGroupInfo
{
    Param (
        $TheObject,
        $section,
        $paramObj,
        $OutputFile,
        $srv
    )
    $AllMbrssrv=@()
    $TotGrpc=0
    #Retrieve the content of nested group
    foreach ($entry in $TheObject)
    {
        if($entry.split(";")[0] -like "*Win32_UserAccount*" -and $entry.split(";")[1] -like "$srv\*"  )
        {
            #For Local User in the Local Administrators group
            $TheObject2 = new-Object PSCustomObject
            $TheObject2 | Add-Member -MemberType NoteProperty -Name "parentgroup" -Value $null
            $TheObject2 | Add-Member -MemberType NoteProperty -Name "Level" -Value 0
            $TheObject2 | Add-Member -MemberType NoteProperty -Name "ObjectClass" -Value "Local User"
            $TheObject2 | Add-Member -MemberType NoteProperty -Name "MemberPath" -Value ($entry.split(";"))[1].split("\")[1]
            $TheObject2 | Add-Member -MemberType NoteProperty -Name "DN" -Value $null
            $TheObject2 | Add-Member -MemberType NoteProperty -Name "Members" -Value $null
            $TheObject2 | Add-Member -MemberType NoteProperty -Name "LastLogonDate" -Value $null
            $TheObject2 | Add-Member -MemberType NoteProperty -Name "PasswordLastSet" -Value $null
            $TheObject2 | Add-Member -MemberType NoteProperty -Name "Disabled" -Value $null
            $TheObject2 | Add-Member -MemberType NoteProperty -Name "HasMbx" -Value $null
        }
        elseif($entry.split(";")[0] -like "*Win32_UserAccount*")
        {
            $DomUser=$entry.split(";")[1]
            
            if ($ht_domains.Keys -contains $DomUser.Split("\")[0])
            {
                if ($script:GUserArray.keys -notcontains (Get-ADUser $DomUser.Split("\")[1] -Server $script:ht_domains[ $DomUser.Split("\")[0] ].DCFQDN).DistinguishedName)
                #if  ($script:GUserArray.keys -notcontains ($script:GUserArray.GetEnumerator() | ?{$_.value.ULogonNetb -like $entry.split(";")[1]}).key)
                {
                    $User=Get-ADUser $DomUser.Split("\")[1] -Server $script:ht_domains[ $DomUser.Split("\")[0] ].DCFQDN -Properties LastLogonDate, PasswordLastSet, Enabled, homeMDB | SELECT SamAccountName,Name,GivenName,Enabled,homemdb,astLogonDate, PasswordLastSet,DistinguishedName
                    $DN=$User.DistinguishedName
                    If ($User.homeMDB -ne $Null)
                    {
                        $HasMbx = "True"
                    }
                    Else
                    {
                        $HasMbx = "False"
                    }
                    $script:GUserArray += @{
                        $User.DistinguishedName = @{
                            UDN = $User.DistinguishedName
                            USamAccountName = $User.SamAccountName
                            ULastLogonDate = $User.LastLogonDate
                            UPasswordLastSet = $User.PasswordLastSet
                            UEnabled = $User.Enabled
                            UHasMbx=$HasMbx
                            UNetbiosDom = $DomUser.Split("\")[0]
                            ULogonNetb = $entry.split(";")[1]
                        }
                    }
                }
                $TheObject2 = new-Object PSCustomObject
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "parentgroup" -Value $null
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "Level" -Value 0
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "ObjectClass" -Value "User"
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "MemberPath" -Value ($entry.split(";"))[1]
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "Members" -Value $null
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "LastLogonDate" -Value $script:GUserArray[$DN].ULastLogonDate
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "PasswordLastSet" -Value $script:GUserArray[$DN].UPasswordLastSet
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "Enabled" -Value $script:GUserArray[$DN].UEnabled
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "HasMbx" -Value $script:GUserArray[$DN].UHasMbx
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "DN" -Value $script:GUserArray[$DN].UDN
            }
            else
            {
                #User from another Forest, Information can't be retrieve
                $TheObject2 = new-Object PSCustomObject
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "parentgroup" -Value $null
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "Level" -Value 0
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "ObjectClass" -Value "Trusted Forest User"
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "MemberPath" -Value ($entry.split(";"))[1].split("\")[1]
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "DN" -Value $null
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "Members" -Value $null
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "LastLogonDate" -Value "N/A"
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "PasswordLastSet" -Value "N/A"
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "Disabled" -Value "N/A"
                $TheObject2 | Add-Member -MemberType NoteProperty -Name "HasMbx" -Value "N/A"
            }
		}
        Else
        {
            #Retrieve the group content on the target domain
            if($entry.split(";")[0] -like "*Win32_Group*")
            {
                #Group from Local Admin Group
                $dn=(Get-ADDomain ($entry.split(";"))[1].split("\")[0]).DistinguishedName
                $entry=($entry.split(";"))[1].split("\")[1]
            }
            else
            {
                #Group from OU Exchange Security groups
                $DN=($entry.Substring($entry.IndexOf("DC=")))
                $entry= ($entry.split(","))[0].replace("CN=","")
			}
            $DNobj=($DN.Substring($dn.IndexOf("DC=")) -replace ",DC=","." -replace "DC=")
            $GroupObject = Get-ADGroup -filter 'Name -eq $entry' -server $DNobj
            $TheObject2=GetInfo -TargetObject $GroupObject -parentgroup $entry
            
            $ResGrp=Get-ADGroupMember -Recursive $GroupObject.SamAccountName -server $DNobj
            $grpcount= ($ResGrp| measure).count
            #User for Groucontent Count and LocalAdmin count
            if ($srv -ne $null)
                {
                $output_ESC_temp +=$srv + "`t"
                }
            If ($GroupObject.SamAccountName -notlike "Exchange Trusted Subsystem*")
            {
                Foreach ($RUser in $ResGrp)
                {
                    If ($AllMbrssrv -notcontains $RUser.DistinguishedName)
                    {
                        $TotGrpc++
                        $AllMbrssrv+=$RUser.DistinguishedName
                    }
                }
            }
            $output_ESC_temp += $entry + "`t"+ $grpcount
            $grpcount=0
		}
        #User for Groucontent Count and LocalAdmin count
        $output_ESC=$output_ESC_Temp
        $output_ESC_temp=$null
        $filename = $section+"Count"
        $output_ESC_File2 = GetOutputFile -path $outputpath -Section $filename
        $output_ESC | out-file $output_ESC_File2 -append

        #Call the Function to create Output file for the section
        GetAllData -AllData $TheObject2 -OutputFile $OutputFile -paraminfos $paramObj -srvin $srv
	}
    $TheObject=$NULL
    return $TotGrpc
}

#Retrieve service Status
Function GetServiceStatus
{
    Param(
        $SvcToCheck,
        $SrvTocheck
     )

   $SvcToCheck = "*"+$SvcToCheck+"*"

   $servicestate = (Get-Service -name $SvcToCheck -computername $SrvTocheck).Status
   $servicestatecount=$servicestate.count
   return $servicestate, $servicestatecount
}

Function GetPOPIMAP
{
    Param(
		$OutputFile,
        $section,
        $Cmdlettoexecute,
        $ListSrvUp,
        $paramObj=@()
        )

        $TheObject=@()
        $PIConfig=@()

        foreach( $CASsrv in (Get-ClientAccessService)) #All servers need to be proceed for retrieving they POP/IMAP configuration
            {
                $PIConfig = Invoke-Expression $Cmdlettoexecute
                if($ListSrvUp -like "*$CASsrv*"  -and $Quickmode -ne $true)
                {
                    #If Srv is reachable the check service status
                    $SVCStatus = GetServiceStatus -SvcToCheck $section -SrvTocheck $CASsrv
                    $allstatus=@()
                    $allstatus = $SVCStatus[0]
                    $allstatus =$allstatus -split(" ")
                    $allstatus1=$allstatus[0]
                    #If Exchange 2010 only one service Add N/A for the service status for the Backendservice
                    if ($SVCStatus[1] -eq 1)
                    {
                        $allstatus2="N/A"
                    }
                    Else
                    {
                        $allstatus2=$allstatus[1]
                    }

                }
                Else
                {
                    #If the server is not reachable
                    $allstatus1="Unreachable"
                    $allstatus2="Unreachable"
                }
                    $PIObject = [PSCustomObject]@{
                        Server = $PIConfig.Server
                        servicestate1 = $allstatus1
                        servicestate2 = $allstatus2
                        LoginType= $PIConfig.LoginType
                        UnencryptedOrTLSBindings= $PIConfig.UnencryptedOrTLSBindings
                        SSLBindings = $PIConfig.SSLBindings
                        ProtocolLogEnabled= $PIConfig.ProtocolLogEnabled
                        WhenCreated= $PIConfig.WhenCreated
                        WhenChanged= $PIConfig.WhenChanged
                }
                $TheObject+=$PIObject
            }
            #Call the Function to create Output file for the section
            GetAllData -AllData $TheObject -OutputFile $OutputFile -paraminfos $paramObj
}

Function GetScheduledTask
{
    Param(
		$OutputFile,
        $path,
        $Cmdlettoexecute,
        $server,
        $paramObj=@()
        )
    $TheObject=@()
    #Retrieve the list of tasks, inject it in a txt and import the txt in csv with a header in an array
    $result = @((Invoke-Expression $Cmdlettoexecute))
    $result | set-content $path\tempST.txt
    $Theobject =import-csv $path\tempST.txt -delimiter "," -header @("Server","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run","Start In","Comment","Scheduled Task State","Idle Time","Power Management","Run As User","Delete Task If Not Rescheduled","Stop Task If Runs X Hours and X Mins","Schedule","Schedule Type","Start Time","Start Date","End Date","Days","Months","Repeat: Every","Repeat: Until: Time","Repeat: Until: Duration","Repeat: Stop If Still Running")

    #Call the Function to create Output file for the section
    GetAllData -AllData $TheObject -OutputFile $OutputFile -paraminfos $paramObj
    Remove-Item $path\tempST.txt
}

Function GetTLS
{
    Param(
		$OutputFile,
        $server,
        $paramObj=@()
        )
        #Construct the location where the information is stored in the registry for TLS
        $RegistryHive = 'LocalMachine'
        $RegistryKeyPath = $('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client','SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server','SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client','SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server','SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client','SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server','SOFTWARE\Microsoft\.NETFramework\v2.0.50727','SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727','SOFTWARE\Microsoft\.NETFramework\v4.0.30319','SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319')
        $RegistryRoot= "[{0}]::{1}" -f 'Microsoft.Win32.RegistryHive', $RegistryHive
        $RegistryHive = Invoke-Expression $RegistryRoot -ErrorAction Stop
        foreach ($regpath in $RegistryKeyPath)  #For each server retrieve the TLS value for regpath
        {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegistryHive, $server)
            $key = $reg.OpenSubKey($regpath, $true)
            if($key -ne $Null)
            {
                $TheObject = $key.GetValueNames()
                if ($TheObject -contains 'Enabled')
                {
                    #Create an object with the registry value for the TLS Key in SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\...
                    $TheObject = [PSCustomObject]@{
                        RegistryLocation = $key.Name
                        DisabledByDefault = $key.GetValue('DisabledByDefault')
                        Enabled = $key.GetValue('Enabled')
                    }
                    #Call the Function to create Output file for the section
                    GetAllData -AllData $TheObject -OutputFile $OutputFile -paraminfos $paramObj -srvin $server
                }
                elseif( $TheObject -contains 'SystemDefaultTlsVersions' )
                {
                    #Create an object with the registry value for the TLS Key in SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v...
                    $TheObject = [PSCustomObject]@{
                    RegistryLocation = $key.Name
                    SystemDefaultTlsVersions = $key.GetValue('SystemDefaultTlsVersions')
                    }
                    #Call the Function to create Output file for the section
                    GetAllData -AllData $TheObject -OutputFile $OutputFile -paraminfos $paramObj -srvin $server
                }
                $key.close()
            }
        }
}

Function GetSoftware
{
    Param(
		$OutputFile,
        $server,
        $paramObj=@()
    )
    #Construct the location where the information is stored in the registry
    $RegistryHive = 'LocalMachine'
    $RegistryKeyPath = $('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    $RegistryRoot= "[{0}]::{1}" -f 'Microsoft.Win32.RegistryHive', $RegistryHive
    $RegistryHive = Invoke-Expression $RegistryRoot -ErrorAction Stop
    foreach ($regpath in $RegistryKeyPath)  #For each server retreive list of installed software
    {
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegistryHive, $server)
        $key = $reg.OpenSubKey($regpath, $true)
        foreach ($subkey in $key.GetSubKeyNames())
        {
            $Childsubkey = $key.OpenSubKey($subkey)
            $TheObject = $Childsubkey.GetValueNames()
            if ($TheObject -contains 'DisplayName')
            {
                #Create an object with the registry value for the software
                $TheObject = [PSCustomObject]@{
                    DisplayName = $Childsubkey.GetValue('DisplayName')
                    DisplayVersion = $Childsubkey.GetValue('DisplayVersion')
                    Publisher = $Childsubkey.GetValue('Publisher')
                }
                GetAllData -AllData $TheObject -OutputFile $OutputFile -paraminfos $paramObj -srvin $server
            }
            $Childsubkey.close()
        }
        $key.close()
    }
}

Function GetLocalAdmin
{
    Param(
		$OutputFile,
        $section,
        $server,
        $outputpath,
        $Cmdlettoexecute,
        $paramObj=@()
    )
	$server=$server.split(".")[0]
	$TheObject = @((Invoke-Expression $Cmdlettoexecute))
    $TheObject = @($TheObject.split(" ",1))
   #Call Function to retrieve and construct group content
   $res= GetGroupInfo -TheObject $TheObject -srv $Server -section $section -paramObj $paramObj -OutputFile $OutputFile
   $output_ESC_Res = $Server+ "`t"+ "Total Unique Domains Members excluding ETS group" + "`t"+ $res
   $filename = $section+"Count"
   $output_ESC_File2 = GetOutputFile -path $outputpath -Section $filename
   $output_ESC_Res | out-file $output_ESC_File2 -append

}

function test-cmdletExch
{
    try
    {
        Get-command "get-mailbox" -ErrorAction stop | Out-Null
        return $true
    }
    catch {
        return $false
        }
}
function connect-onprem
{
    #on vérifie que les cmdlet exchange sont chargées sinon on se connecte via le remoteexchange.ps1
    try {
            if (test-cmdletExch)
            {
                Write-host "Exchange Cmdlet already loaded !" -ForegroundColor Green
            }
            else
            {
                Write-host "Loading Exchange CmdLet..."
                ."$env:ExchangeInstallPath\Bin\RemoteExchange.ps1"
                Connect-ExchangeServer -auto
            }
    }
    catch
    {
        Write-host "Failed to load EXCH CmdLet and remote session" -ForegroundColor Red
        return
    }
}


#End of Function - Start of Main

#Start of Main section
#Call Function to check and set paths to Run Transcript
$ResFnct = Getpath -Outputpath $path -Inputcsvpath $inputcsvpath
$outputpath = $ResFnct[0]
$inputcsvpath = $ResFnct[1]

$date = get-date -Format "ddMMyyyy-HHmmss"
Start-Transcript -Path "$outputpath\ESC-transcript-$date.txt"
connect-onprem 
#Warning to diplay. Depending on the customer state, restrictions and Network some tests won't work and error will be displayed
Write-Host "If some servers timeout or can't be reached, errors will be displayed for those servers. You can ignored them" -ForegroundColor Green
$script:ht_domains = @{}
$script:GUserArray=@{}


#Call Function to retrieve AD information
If ($edge -eq $false -and $CloudEXO -eq $false)
{
Set-ADServerSettings -ViewEntireForest $true
$ResFnct= GetADInfo
$forest = $ResFnct[0]
$forestDN = $ResFnct[1]
$gc=$ResFnct[2]
$SIDRoot=$ResFnct[3]
}
#Call Function to retrive the list of reachable servers if only Exchange 2010 servers exist
If ($CloudEXO -eq $false)
{
$ResFnct = GetExchver -EPS2010 $EPS2010 -EDGE $edge
$ListSrvUp = $ResFnct[0]
$ListNameSRVUp = $ResFnct[1]
$ListSrvUp=$ListSrvUp | Sort-Object name
$EPS2010 = $ResFnct[1]
}


#Import info from the input CSV file
If ($DumpConfig)
{
    $AllDataimport = import-csv $inputcsvpath"\InputESCConfig.csv" 
    $AllDataimport += import-csv $inputcsvpath"\InputESC.csv"   
    

}
else {
    $AllDataimport = import-csv $inputcsvpath"\InputESC.csv"   
}
If ($EDGE)
{
    $AllDataimport = import-csv $inputcsvpath"\InputESCEDGE.csv"   
}
If ($CloudEXO)
{
    $AllDataimport = import-csv $inputcsvpath"\InputESCCloud.csv"   
}

#Remove all txt files from previous execution
Remove-Item $outputpath'\ESC_*.txt'

$paramObj=@()
$TheObject=@()
$result = @()
$countdataimport = $AllDataImport.Count
$advance=1

#StartMain Script part
foreach ($DataImport in $AllDataImport)
{
    Write-Host "Step $advance/$countdataimport - $($DataImport.Section) in progress" -ForegroundColor Green
    $advance++
    #Retreive for the imported file the section to run, the Powershell command to execute and the parameters to retrieve
    $output_ESC_File = GetOutputFile -path $outputpath -Section $DataImport.section
    $paramObj = @($DataImport.paramObj) -split ","
    
    #Import CmdLet to execute
    #For some checks if Exchange PowerShell 2010 is used, some PowerShell commands run is a little bit different, then import the PSCmdL2 value
    If (($DataImport.section -eq 'MailboxDatabaseReceiveAs' -or $DataImport.section -eq 'MailboxDatabaseSendAs') -and $EPS2010 -eq $true)   
    {
        $DataImport.PSCmdL= $DataImport.PSCmdL2
    }
    #Cmdlet execution and call function to create result file
    $Cmdlettoexcute = $DataImport.PSCmdL

    If ($Quickmode -ne $true -and $DataImport.PerSrv -eq 1 ) # for all sections which need an iteration per server
    {
        $theobject=$NULL
        foreach ($Server in $ListSRVUp)
        {
         
            if( $DataImport.section -like "*LocalAdmin*")
            {
                GetLocalAdmin -OutputFile $output_ESC_File -section $DataImport.section -paramObj $paramObj -server $server -Cmdlettoexecute $Cmdlettoexcute -outputpath $outputpath
            }
            #The Software section cmdlet can't be part of the Input CSV, all the code is in the mail section
            elseif ($DataImport.section -like "*SOFTWARE*")
            {
                GetSoftware -OutputFile $output_ESC_File -paramObj $paramObj -server $server
            }
            elseif ($DataImport.section -like "*TLS*") #The TLS section cmdlet can't be part of the Input CSV, all the code is in the mail section
            {
                GetTLS -OutputFile $output_ESC_File -paramObj $paramObj -server $server
            }
            elseif ($DataImport.section -like "*ScheduledTask*") #For each server, retrieve the list of scheduled tasks using schtasks.exe (Get-ScheduledTask not supported in E2010)
            {
                GetScheduledTask -OutputFile $output_ESC_File -paramObj $paramObj -server $server -path $outputpath -Cmdlettoexecute $Cmdlettoexcute
            }
            else
            {
                $TheObject = Invoke-Expression $Cmdlettoexcute
                #Call the Function to create Output file for the section
                GetAllData -AllData $TheObject -OutputFile $output_ESC_File -paraminfos $paramObj -srvin $server
            }
        }
    }
    elseif ($DataImport.section -like "*ExchGroup*" -or $DataImport.section -like "*ADRootGrp*")
    {
            $TheObject = Invoke-Expression $Cmdlettoexcute
            #Call Function to retrieve and construct group content
            $TheObject= GetGroupInfo -TheObject $TheObject -section $DataImport.section -paramObj $paramObj -OutputFile $output_ESC_File
	}
    elseif  ($DataImport.section -like "*POP*" -or $DataImport.section -like "*IMAP*")
    {
        GetPOPIMAP -OutputFile $output_ESC_File -section $DataImport.section -paramObj $paramObj -Cmdlettoexecute $Cmdlettoexcute -ListSrvUp $ListSrvUp
    }
    elseif ($DataImport.PerSrv -eq 0)
    {
        $TheObject = Invoke-Expression $Cmdlettoexcute
        #Call the Function to create Output file for the section
        GetAllData -AllData $TheObject -OutputFile $output_ESC_File -paraminfos $paramObj
    }
}

Stop-Transcript