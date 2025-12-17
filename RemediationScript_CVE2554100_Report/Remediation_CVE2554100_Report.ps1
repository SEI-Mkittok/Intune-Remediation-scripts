param(
[switch]$GridView,		
[switch]$CSV
)

# Prompt credentials
Connect-MgGraph

# With a secret
# $tenantID = ""
# $clientId = ""
# $Secret = ""
# $myAccessToken = Get-MsalToken -ClientId $clientID -TenantId $tenantID -ClientSecret $Secret
# Connect-MgGraph -TenantId $tenantID -ClientSecretCredential $ClientSecretCredential

# With a certificate
# $Script:tenantID = ""
# $Script:clientId = ""	
# $Script:Thumbprint = ""
# Connect-MgGraph -Certificate $ClientCertificate -TenantId $TenantId -ClientId $ClientId  | out-null		
	
$Remediations_URL = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts"
$Get_Scripts = (Invoke-MgGraphRequest -Uri $Remediations_URL  -Method GET).value	
$CVE_Check_Array = @()
ForEach($Script in $Get_Scripts)
{
	$Script_Name = $Script.displayName
	$Script_Id = $Script.id

	$Script_info = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$Script_Id"
	$Get_Script_info = (Invoke-MgGraphRequest -Uri $Script_info  -Method GET)	

	$Detection = $Get_Script_info.detectionScriptContent
	$Remediation = $Get_Script_info.remediationScriptContent
	
	$Detection_Decoded = [Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($Detection))
	$Remediation_Decoded = [Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($Remediation))
	
	$Detection_check = $Detection_Decoded | Select-String "Invoke-WebRequest" | Where-Object {$_.Line -notmatch "-UseBasicParsing"}
	If($Detection_check -ne $null)
	{
		$Issue = "Yes"
		$Issue_with_detection = "Yes"
	}Else{
		$Issue = "No"		
		$Issue_with_detection = "No"
	}	

	$Remediation_Check = $Remediation_Decoded | Select-String "Invoke-WebRequest" | Where-Object {$_.Line -notmatch "-UseBasicParsing"}		
	If($Remediation_Check -ne $null)
	{
		$Issue = "Yes"		
		$Issue_with_remediation = "Yes"
	}Else{
		$Issue = "No"				
		$Issue_with_remediation = "No"
	}		
	
	$Obj = [PSCustomObject]@{
		Name     = $Script_Name
		ID     = $Script_Id
		Issue     = $Issue		
		"Issue in detection" = $Issue_with_detection
		"Issue in remediation" = $Issue_with_remediation		
	}
	
	$CVE_Check_Array += $Obj
}	

If($GridView){$CVE_Check_Array | Out-GridView}
If($CSV){$CVE_Check_Array | Export-Csv -Path "$env:temp\CVE-2025-54100_Script_Report.csv" -NoTypeInformation -Encoding UTF8;invoke-item $env:temp}

