
<#PSScriptInfo

.VERSION 1.31

.GUID 134de175-8fd8-4938-9812-053ba39eed83

.AUTHOR banhao@gmail.com

.COMPANYNAME

.COPYRIGHT

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES


.PRIVATEDATA

#> 

<# 

.DESCRIPTION 
CSRtoCER.ps1 is used to view the information from a CSR file and generate the certificate based on the CSR file. This PowerShell will grab the information such as "Subject", "Key Length", "SANs", "Template" from the CSR file. If the SANs is not empty in the CSR file, the script will use the CSR file’s setting. If there's no SANs in CSR file, script will use “CN” as the SANs. The script will also list the Template that used in the CSR file, If there's no Template in the CSR file, script will list all the available Certificate Templates from your AD, when you pick up one, script will list the CA Server which has the Template you picked up. 

  Version:        1.31
  Creation Date:  <02/25/2021>
  Purpose/Change: Fix the bug that when the CSR file contains SANs can't generate SANs in Certificate correctly.

  Version:        1.30
  Creation Date:  <01/29/2020>
  Purpose/Change: Add the feature that can manually input SANS. If the SANs not contain CN the script will auto add it.

  Version:        1.20
  Creation Date:  <10/08/2019>
  Purpose/Change: Fix the CertUtil version compare issue


Before you run the script Install the PSPKI module in your PowerShell running environment. 

https://www.powershellgallery.com/packages/PSPKI/3.4.1.0 

<Install-Module -Name PSPKI>

#> 


<#
.SYNOPSIS
  <>

.DESCRIPTION
  <>

.PARAMETER <Parameter_Name>
  <>

.INPUTS
  <>

.OUTPUTS
  <>

.NOTES
  <>

.EXAMPLE
  This PowerShell passed the test in PowerShell version 5.1
  PS H:\>host  
	Check the PowerShell version.
  
  PS H:\>CSRtoCER.ps1 csrfilename
	Output the Certificate Template and the other information which is in the CSR file. 
	
  PS H:\>CSRtoCER.ps1 csrfilename -cert
	Generate the Certificate by using the CSR file.

#>

cls
#-------------------------------------------------------------------------------------------------------------------------------------------------------
#variables
$CSRfile = $Args[0]
$ENV = $Args[1]

Import-Module PSPKI

if ( Test-Path -Path TemplatePropCommonName.csv ) { Clear-Content TemplatePropCommonName.csv }else{ New-Item -Name TemplatePropCommonName.csv -ItemType File } 
if ( Test-Path -Path TemplateOID.csv ) { Clear-Content TemplateOID.csv }else{ New-Item -Name TemplateOID.csv -ItemType File }
if ( Test-Path -Path TemplateMenu.csv) { Clear-Content TemplateMenu.csv }else{ New-Item -Name TemplateMenu.csv -ItemType File }
if ( Test-Path -Path CAServers.csv ) { Clear-Content CAServers.csv }else{ New-Item -Name CAServers.csv -ItemType File }

if ( ([string]::IsNullOrEmpty($CSRfile))  ){
  Write-Output "Sorry, missing the CSR file! Please input the CSR file name and try again."
  Write-Output "---USAGE: CSRtoCER.ps1 csrfilename [-cert]---"
}else {
  if ( Test-Path -Path $CSRfile ) {
		$CSRfileOID = certutil.exe -dump .\$CSRfile | findstr "Template=" |  %{ $_.Split('=')[1]; }
		$CSRfileSubject = ((certutil.exe -dump .\$CSRfile) | select-string '^\s{4}[A-Z]{1,2}=[0-9a-zA-Z*]' -AllMatches) | foreach{ $_.ToString().Trim() }
		$CSRfileCN = (certutil.exe -dump .\$CSRfile) | findstr "CN" | %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
		$CSRfileSAN = certutil.exe -dump .\$CSRfile | findstr "DNS" |  %{ $_.Split('=')[1]; } | sort -u
		$CSRfileKeyLength = (certutil.exe -dump .\$CSRfile | findstr "Public\ Key\ Length:" |  %{ $_.Split(':')[1]; }).Trim()
		$DistinguishedNameLength = (((get-addomain | findstr "DistinguishedName" |  foreach{ $_.ToString() } | %{ $_.Split(':')[1]; }).Trim()).Split(',')).count
		$ForestLength = (((get-addomain | findstr "^Forest" |  foreach{ $_.ToString() } | %{ $_.Split(':')[1]; }).Trim()).Split('.')).count
		$Delta = $DistinguishedNameLength-$ForestLength
		$ForestDC = ((get-addomain | findstr "DistinguishedName" |  foreach{ $_.ToString() } | %{ $_.Split(':')[1]; }).Trim()).Split(',')[$Delta..$($DistinguishedNameLength-1)] -join ","
		$CertutilVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("c:\windows\system32\certutil.exe").FileVersion | %{ $_.Split('(')[0]; } | foreach{ $_.ToString().Trim() }
		
		Write-Output "CSR file $CSRfile Subject = "$CSRfileSubject
		Write-Output ""
		Write-Output "CSR file $CSRfile Key Length = $($CSRfileKeyLength)"
		Write-Output ""
		Write-Output "CSR file $CSRfile SANs = "$CSRfileSAN
		Write-Output ""
		
		#-------------------------------------------------------------------------------------------------------------------------------------------------------
		#Generate all the Certificate Templates Name List from every CA Server export into TemplatePropCommonName.csv.
		#certutil.exe -Template | findstr "TemplatePropCommonName" | %{ $_.Split('=')[1]; } |  %{$_.Substring(1)} > .\TemplatePropCommonName.csv
		if ( [version]$CertutilVersion -ge [version]"10.0.16299.15" ){ certutil.exe | findstr "Config" | %{ $_.Split(':')[1]; } | foreach{ $_.ToString().Trim() } > CAServers.csv }
		else{ certutil.exe | findstr "Config" | %{ $_.Split('`')[1]; } | %{$_.Substring(0, $_.length - 1) } > CAServers.csv }
		
		foreach($line in Get-Content .\CAServers.csv) {
			$CA = certutil.exe -config $line -CATemplates | findstr "Auto-Enroll" | %{ $_.Split(':')[0]; }
			$COUNT = $CA.count
			for (($i = 0); $i -lt $COUNT; $i++){
				write-output "$($line),$($CA[$i])" >> .\TemplatePropCommonName.csv
			}
		}

		#-------------------------------------------------------------------------------------------------------------------------------------------------------
		#Generate all the Certificate Templates OID List export into Template-OID.csv
		foreach($line in Get-Content .\TemplatePropCommonName.csv) {
			$TemplateName = $line | %{ $_.Split(',')[1]; }
			$Parameter = "CN="+$TemplateName+",CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,"+$ForestDC
			$TemplateOID = Get-ADObject $Parameter -Properties msPKI-Cert-Template-OID | findstr "msPKI-Cert-Template-OID" | %{ $_.Split(':')[1]; } | %{$_.Substring(1)} 
			write-output "$($TemplateName)=$($TemplateOID)" >> TemplateOID.csv
		}
		
		#-------------------------------------------------------------------------------------------------------------------------------------------------------
		#Find out which Certificate Template is used in the CSR file and which CA Server has the Template and generate the CA Server List menu
		if ( $CSRfileOID ){
			$CSRTemplateOID = Select-String -Path .\TemplateOID.csv -Pattern $CSRfileOID | foreach{ $_.ToString() } | %{ $_.Split(':')[3]; } | select-object -First 1
			$CSRTemplateName = Select-String -Path .\TemplateOID.csv -Pattern $CSRfileOID | foreach{ $_.ToString() } | %{ $_.Split(':')[3]; } | %{ $_.Split('=')[0]; } | select-object -First 1
			if ( ([string]::IsNullOrEmpty($CSRTemplateName)) ){
				write-host "This Certificate Template doesn't exist in the CA Servers! Need to re-generate the CSR file or check the Domain Forest!"
				exit 
			}else {
				Write-Output "CSR file $($CSRfile) uses Certificate Template:"
				Write-output $CSRTemplateOID
				Write-Output ""
				$i = 1
				$menu = @{}
				write-output "------------------------------------------------------------------------------------------------------"
				write-output "Following CA Servers have this Certificate Template:"
				foreach($line in Get-Content .\CAServers.csv) {
					$result = certutil.exe -config $line -CATemplates | findstr $CSRTemplateName":"
					if ( $result ){
						Write-Host "$i. $line"
						$menu.Add($i, ($line))
						$i++
					}
				}
			}
		}else { 
			write-output "------------------------------------------------------------------------------------------------------"
			Write-Output "CSR file $($CSRfile) doesn't use the Certificate Template. Please choose one Template from the following list:" 
			get-content -Path .\TemplateOID.csv | %{ $_.Split('=')[0]; } | Sort-Object | Get-Unique > TemplateMenu.csv
			$i = 1
			$menu = @{}
			foreach($line in Get-Content .\TemplateMenu.csv) {
				Write-Host "$i. $line"
				$menu.Add($i, ($line))
				$i++
			}
			[int]$ans = Read-Host "Please select the CA server to gnenerate the Certificate [ 1 - $($i-1) ]"
			$selection = $menu.Item($ans)
			if ( ([string]::IsNullOrEmpty($selection)) ){
				write-output "------------------------------------------------------------------------------------------------------"
				Write-Output "Selection Wrong, Please correct it and try again."
			}else { $CSRTemplateName = $selection }
						
			write-output "------------------------------------------------------------------------------------------------------"
			write-output "Following CA Servers have this Certificate Template:"
			$i = 1
			$menu = @{}
			foreach($line in Get-Content .\CAServers.csv) {
				$result = certutil.exe -config $line -CATemplates | findstr ^$CSRTemplateName":"
				if ( $result ){
					Write-Host "$i. $line"
					$menu.Add($i, ($line))
					$i++
				}
			}
		}
		
		# ------------------------------------------------------------------------------------------------------------------------------------------------------
		#Generate the Certificate.
		if ( $ENV -eq "-cert" ){
			[int]$ans = Read-Host "Please select the CA server to gnenerate the Certificate [ 1 - $($i-1) ]"
			$selection = $menu.Item($ans)
			if ( ([string]::IsNullOrEmpty($selection)) ){
				write-output "------------------------------------------------------------------------------------------------------"
				Write-Output "Selection Wrong, Please correct it and try again."
			}else{
				if ( ([string]::IsNullOrEmpty($CSRfileSAN)) ){
					if ( $CSRfileCN -match "\*") { $CERFILENAME = $CSRfileCN -replace "\*", "wildcard" } else{ $CERFILENAME = $CSRfileCN }
					[string[]] $SANArray = @()
					$SANArray = Read-Host "Please input the SANs [ Example: 192.168.0.1,www.example.com,test.example.com ] (Use comma "," as Delimiter)"
					$SANArray = $SANArray.Split(',').Split(' ')
					if ( ([string]::IsNullOrEmpty($SANArray)) ){
						$CSRfileSAN = $CSRfileCN
						$RequestIdOutPut = certreq -f -q -Submit -Attrib "CertificateTemplate:$CSRTemplateName\nSAN:dns=$CSRfileSAN" -config $selection .\$CSRfile "$($CERFILENAME).cer"
					} else{ 
						if ( $SANArray.contains($CSRfileCN) ){
							$CSRfileSAN = "SAN:dns="+$SANArray[0]
							for ($i=1;$i -lt $SANArray.length;$i++){ $CSRfileSAN = $CSRfileSAN+"&dns="+$SANArray[$i] }
						}else{
							$CSRfileSAN = "SAN:dns="+$CSRfileCN
							for ($i=0;$i -lt $SANArray.length;$i++){ $CSRfileSAN = $CSRfileSAN+"&dns="+$SANArray[$i] }
							}
						$RequestIdOutPut = certreq -f -q -Submit -Attrib "CertificateTemplate:$CSRTemplateName\n$CSRfileSAN" -config $selection .\$CSRfile "$($CERFILENAME).cer"	
						}
					$RequestId = $RequestIdOutPut[0] | %{ $_.Split(':')[1]; } | foreach{ $_.ToString().Trim() }
					$CAServer = $selection | %{ $_.Split('\')[0]; } | foreach{ $_.ToString().Trim() }
					write-output "This Request Id is $($RequestId)"
					if ( Test-Path -Path "$($CERFILENAME).cer" ) { write-Output "Certificate $($CERFILENAME).cer generate successfully!" }else{ Get-PendingRequest -CA $CAServer -RequestID $RequestId | Approve-CertificateRequest 
						$CertPath = Get-Location
						Get-IssuedRequest -CA $CAServer -RequestId $RequestId | Receive-Certificate -Path "$CertPath"
						Rename-Item -Path "RequestID_$RequestId.cer" -NewName "$CERFILENAME.cer"
						}
				}else{ if ( $CSRfileCN -match "\*") { $CERFILENAME = $CSRfileCN -replace "\*", "wildcard" } else{ $CERFILENAME = $CSRfileCN }
					   if ( !$($CSRfileSAN.contains($CSRfileCN)) ) { 
						$SANArray = @($CSRfileSAN)
						$CSRfileSAN = "SAN:dns="+$CSRfileCN
						for ($i=0;$i -lt $SANArray.length;$i++){ $CSRfileSAN = $CSRfileSAN+"&dns="+$SANArray[$i] }
						$RequestIdOutPut = certreq -f -q -Submit -Attrib "CertificateTemplate:$CSRTemplateName\n$CSRfileSAN" -config $selection .\$CSRfile "$($CERFILENAME).cer"
					   }else { $RequestIdOutPut = certreq -f -q -Submit -Attrib "CertificateTemplate:$CSRTemplateName" -config $selection .\$CSRfile "$($CERFILENAME).cer" }
					   $RequestId = $RequestIdOutPut[0] | %{ $_.Split(':')[1]; } | foreach{ $_.ToString().Trim() }
					   $CAServer = $selection | %{ $_.Split('\')[0]; } | foreach{ $_.ToString().Trim() }
					   write-output "This Request Id is $($RequestId)"
					   if ( Test-Path -Path "$($CERFILENAME).cer" ) { write-Output "Certificate $($CERFILENAME).cer generate successfully!" }else{ Get-PendingRequest -CA $CAServer -RequestID $RequestId | Approve-CertificateRequest 
						$CertPath = Get-Location
						Get-IssuedRequest -CA $CAServer -RequestId $RequestId | Receive-Certificate -Path "$CertPath"
						Rename-Item -Path "RequestID_$RequestId.cer" -NewName "$CERFILENAME.cer"
					   }
					}
			}
		}else{
			write-output "------------------------------------------------------------------------------------------------------"
			Write-Output "If need generate the Certificate, please use the Verbs <-cert>"
			Write-Output "---USAGE: CSRtoCER.ps1 csrfilename [-cert]---"
		}
	}else {
		Write-Output "Sorry, $($CSRfile) doesn't exist. Please correct it and try again."
		Write-Output "---USAGE: CSRtoCER.ps1 csrfilename [-cert]---"
	}
}

