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
stemy-MS (thanks !)
#>

param
(
[Parameter(mandatory=$true,position=0)]
[string]$SRV = ""
)

$uri = "http://" + $SRV + "/powershell?serializationlevel=full"
Import-PsSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$SRV/powershell?serializationlevel=full")