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
Released : 04/01/2021
Develop by ksangui@microsoft.com
Thanks for those who helped me !
Especially Nicolas Lepagnez and Lucas Zinck

The method to export data to Excel was inspired from the script Exchange Data Collector (ExDC) from
https://github.com/stemy-msft/exchange-data-collector
stemy-MS
#>

<#
.SYNOPSIS
    This script convert in an Excel data collected by the script Get-ExchangeSecurityCollect.ps1
.DESCRIPTION
    This script use the CSV file InputESC.csv to construct a sheet by section
.PARAMETER Path
    Specify the folder where the txt file have been stored. The format could be d:\ESC\output or d:\ESC\Output\. If not specify, the script will use the current folder to retrieve txt file and store the Excel file
.PARAMETER DumpConfig
    Set this setting to $True if you want to create excel file with Exchange configuration settings
.PARAMETER EDGE
Set this setting to $True if the script is launched on an edge server
.PARAMETER CLOUDEXO
Set this setting to $True if the script is launched on an edge server
.NOTES
    Version:        1.0
    Author:         Karine Sanguinet
    Creation Date:  20/03/2021
    Update :   03/25/2021
    Updater:   Lucas Zink
	Update :   10/06/2021
    Updater:   Karine Sanguinet
    Purpose/Change: Add Edge server support, check config for CVE 1730
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
	Last Update :   2023/04/05
    Last Updater:   Karine Sanguinet
    Purpose/Change: Change the name generation for the Excel file, allow to customize with the CX name
    New script version : Script Version 2.1
  
.EXAMPLE
    C:\ESC> .\New-ExchangeSecurityInfoReport.ps1
.EXAMPLE
	C:\ESC> .\New-ExchangeSecurityInfoReport.ps1 -Path C:\ESC\Output
.EXAMPLE
    C:\ESC> .\New-ExchangeSecurityInfoReport.ps1 -Path C:\ESC\Output  -DumpConfig $true
.EXAMPLE
    C:\ESC> .\New-ExchangeSecurityInfoReport.ps1 -EDGE $true
.EXAMPLE
    C:\ESC> .\New-ExchangeSecurityInfoReport.ps1 -Path C:\ESC\Output  -EDGE $true
.EXAMPLE
    C:\ESC> .\New-ExchangeSecurityInfoReport.ps1 -CloudEXO $true
.EXAMPLE
    C:\ESC> .\New-ExchangeSecurityInfoReport.ps1 -Path C:\ESC\Output  -CloudEXO $true
#>

param(

    [Parameter(Mandatory=$false,HelpMessage="Specify the path where the collected file will be created")]
	$path=$Null, # specify the path for the storage of the collect
	[Parameter(Mandatory=$false,HelpMessage="Specify if configuration settings will be retrieve")]
    $DumpConfig=$true, #set to $true to add Exchange configuration settings
	[Parameter(Mandatory=$false,HelpMessage="Specify if the server is an EDGE server")]
    $edge=$false, #set to $true for EDGE server check
	[Parameter(Mandatory=$false,HelpMessage="Specify if you want to dump Cloud EXO config")]
	$CXName=$Null, #set to $true for EDGE server check
	[Parameter(Mandatory=$false,HelpMessage="If you want to customize the Excel file name with the Customer name")]
    $CLOUDEXO=$false

)

function Getpath 
{     
    Param(
        $path 
       )
 
    #Check if param path is empty if Yes use current location
    If ($path -eq $null)
    {
        $path = "$((get-location).tostring())\output"
    }
	$pathInputCSV =(get-location).tostring()
	$pathInputCSV=$pathInputCSV.TrimEnd("\")
    $path=$path.TrimEnd("\")
    return $path, $pathInputCSV
}

function getinfosheet
{     
    Param(
		$AllDataImport=@(),
		$path 
	   )
foreach ($alldata in $AllDataImport)
{
		Write-Host "---- Creating Tab "$AllData.Section -ForegroundColor Green
		$Worksheet = $Excel_ESC_workbook.worksheets.item($intSheetCount)
		$Worksheet.name = $AllData.section
		$row = 1
		# Header creation for the sheet
		$allheader=($AllData.paramObj) -split","
		$header = @()
		foreach ( $headerInfo in $allheader)
		{ 			
			$header +=  $headerInfo
		}
		#$header +=$AllData.Comment
		$a = [int][char]'a' -1
		if ($header.GetLength(0) -gt 26) 
		{
			$EndCellColumn = [char]([int][math]::Floor($header.GetLength(0)/26) + $a) + [char](($header.GetLength(0)%26) + $a)
		} 
		else 
		{
			$EndCellColumn = [char]($header.GetLength(0) + $a)
		}
		$Header_range = $Worksheet.Range("A1","$EndCellColumn$row")
		$Header_range.value2 = $header
		$Header_range.cells.interior.ColorIndex = 37
		$Header_range.cells.font.colorindex = 0
		$Header_range.cells.font.bold = $true
		$row++
		$intSheetCount++	
		$ColumnCount = $header.Count
		$DataFile = @()
		$EndCellRow = 1

		# Fill the sheet with the data form the txt file
		$output_location=$path + "\ESC_"+$AllData.section+".txt"
		if ((Test-Path $output_location) -eq $true)
		{	
			$DataFile += [System.IO.File]::ReadAllLines($output_location) 
			$RowCount = $DataFile.Count
			$RowCount+=2
			$ArrayRow = 0
			$DataArray = New-Object 'object[,]' $RowCount,$ColumnCount
			Foreach ($DataRow in $DataFile)
			{
				$DataField = $DataRow.Split("`t")
				for ($ArrayColumn=0;$ArrayColumn -le $ColumnCount-1;$ArrayColumn++)
				{
					$DataArray[$ArrayRow,$ArrayColumn] = $DataField[$ArrayColumn]
				}
				$ArrayRow++
				
			}

			$EndCellRow = ($RowCount+1)
			$Data_range = $Worksheet.Range("a2","$EndCellColumn$EndCellRow")
			$Data_range.Value2 = $DataArray
		}
}
}

#Call Function to check and set paths
$ResFnct = Getpath -path $Path
$path = $ResFnct[0]
$pathInputCSV = $ResFnct[1]
$AllDataimport=@()
#Import info from the input CSV file
If ($DumpConfig)
{
    $AllDataimport = import-csv $pathInputCSV"\InputESC.csv"   
    $AllDataimport += import-csv $pathInputCSV"\InputESCConfig.csv"   
}
else {
    $AllDataimport = import-csv $pathInputCSV"\InputESC.csv"   
}
If ($EDGE)
{
    $AllDataimport = import-csv $pathInputCSV"\InputESCEDGE.csv"   
}
If ($CloudEXO)
{
    $AllDataimport = import-csv $pathInputCSV"\InputESCCloud.csv"   
}
#$AllDataimport = import-csv $pathInputCSV"\InputESC.csv"

[int]$nbsheet=($AllDataimport).count
#Prepare Excel File
#$RunLocation = $Path+ "\ESC_"+$(Get-Date -uFormat %m/%d/%Y_%R| foreach {$_ -replace ":", "." -replace"/","-"})
if ($CXname -eq $Null)
{
$RunLocation = $Path+"\"+ $(Get-Date -uFormat %Y/%m/%d-%R| foreach {$_ -replace ":", "." -replace"/","-"})+"_ESC"
}
Else
{
	$RunLocation = $Path+"\"+ $(Get-Date -uFormat %Y/%m/%d-%R| foreach {$_ -replace ":", "." -replace"/","-"})+"_"+$CXName
}


#Write-Host "---- Starting to create com object for Excel"
$Excel_ESC = New-Object -ComObject excel.application
#Write-Host "---- Hiding Excel"
$Excel_ESC.visible = $false
#Write-Host "---- Setting ShowStartupDialog to false" 
$Excel_ESC.ShowStartupDialog = $false 
#Write-Host "---- Setting DefaultFilePath"
$Excel_ESC.DefaultFilePath = $RunLocation
#Write-Host "---- Setting SheetsInNewWorkbook" 
$Excel_ESC.SheetsInNewWorkbook = $nbsheet
#Write-Host "---- Checking Excel version"
if ($Excel_ESC.version -ge 12)
{
	$Excel_ESC.DefaultSaveFormat = 51
	$excel_Extension = ".xlsx"
}
else
{
	$Excel_ESC.DefaultSaveFormat = 56
	$excel_Extension = ".xls"
}
#Write-Host "---- Excel version " $Excel_ESC.version " and DefaultSaveFormat " $Excel_extension

# Create new Excel workbook
#Write-Host "---- Adding workbook"
$Excel_ESC_workbook = $Excel_ESC.workbooks.add()
#Write-Host "---- Setting output file"
$ESC_XLS = $RunLocation+ $excel_Extension

#Write-Host "---- Setting workbook properties"
$Excel_ESC_workbook.author = "CE-ESC"
$Excel_ESC_workbook.title = "Exchange Security Information"
$Excel_ESC_workbook.comments = "Exchange Security Information"
$intSheetCount = 1

#Create each sheet from output file
getinfosheet -AllDataImport $AllDataImport -path $path

#########
# Autofit columns
#Write-Host "---- Starting Autofit  "	
$Excel_ESCWorksheetCount = $Excel_ESC_workbook.worksheets.count
$AutofitSheetCount = 1
while ($AutofitSheetCount -le $Excel_ESCWorksheetCount)
{
	$ActiveWorksheet = $Excel_ESC_workbook.worksheets.item($AutofitSheetCount)
	$objRange = $ActiveWorksheet.usedrange
    	[Void]	$objRange.entirecolumn.autofit()
        [Void]	$objRange.AutoFilter()
	$AutofitSheetCount++
}
$Excel_ESC_workbook.saveas($ESC_XLS)
Write-Host "---- Spreadsheet saved" -ForegroundColor Green
$Excel_ESC.workbooks.close()
Write-Host "---- Workbook closed" -ForegroundColor Green
$Excel_ESC.quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Excel_ESC)
Remove-Variable Excel_ESC
