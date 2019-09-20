
<#PSScriptInfo

.VERSION 1.11

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
  Before start running the script, need to install module PSPKI.
  https://www.powershellgallery.com/packages/PSPKI/3.4.1.0
  
  Install-Module -Name PSPKI
  
  Version:        1.11
  Author:         <HAO BAN/banhao@gmail.com>
  Creation Date:  <06/17/2019>
  Purpose/Change: Fix the bug that running on Windows 10 that CertUtil version is 10.0.16299.15
  
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
		if ( $CertutilVersion -eq "10.0.16299.15" ){ certutil.exe | findstr "Config" | %{ $_.Split(':')[1]; } | foreach{ $_.ToString().Trim() } > CAServers.csv }
		else{ certutil.exe | findstr "Config" | %{ $_.Split('`')[1]; } |  %{$_.Substring(0, $_.length - 1) } > CAServers.csv }
		
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
					$CSRfileSAN = $CSRfileCN
					if ( $CSRfileCN -match "\*") { $CERFILENAME = $CSRfileCN -replace "\*", "wildcard" } else{ $CERFILENAME = $CSRfileCN }
					$RequestIdOutPut = certreq -f -q -Submit -Attrib "CertificateTemplate:$CSRTemplateName\nSAN:dns=$CSRfileSAN" -config $selection .\$CSRfile "$($CERFILENAME).cer"
					$RequestId = $RequestIdOutPut[0] | %{ $_.Split(':')[1]; } | foreach{ $_.ToString().Trim() }
					$CAServer = $selection | %{ $_.Split('\')[0]; } | foreach{ $_.ToString().Trim() }
					write-output "This Request Id is $($RequestId)"
					if ( Test-Path -Path "$($CERFILENAME).cer" ) { write-Output "Certificate $($CERFILENAME).cer generate successfully!" }else{ Get-PendingRequest -CA $CAServer -RequestID $RequestId | Approve-CertificateRequest 
					$CertPath = Get-Location
					Get-IssuedRequest -CA $CAServer -RequestId $RequestId | Receive-Certificate -Path "$CertPath"
					Rename-Item -Path "RequestID_$RequestId.cer" -NewName "$CERFILENAME.cer"
					}
				}else{ if ( $CSRfileCN -match "\*") { $CERFILENAME = $CSRfileCN -replace "\*", "wildcard" } else{ $CERFILENAME = $CSRfileCN }
					   $RequestIdOutPut = certreq -f -q -Submit -Attrib "CertificateTemplate:$CSRTemplateName" -config $selection .\$CSRfile "$($CERFILENAME).cer"
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

# SIG # Begin signature block
# MIIM8AYJKoZIhvcNAQcCoIIM4TCCDN0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUhzogd4jZc+0dPCmP9X42GfX4
# UgWgggolMIIEjjCCA3agAwIBAgIKJQbcrwAAAAAABjANBgkqhkiG9w0BAQUFADAe
# MRwwGgYDVQQDExNlSGVhbHRoU2FzayBSb290IENBMB4XDTExMDkyMDAxMjExMloX
# DTIxMDkyMDAxMzExMlowgYQxEjAQBgoJkiaJk/IsZAEZFgJjYTESMBAGCgmSJomT
# 8ixkARkWAnNrMRMwEQYKCZImiZPyLGQBGRYDaGluMRYwFAYKCZImiZPyLGQBGRYG
# aGVhbHRoMS0wKwYDVQQDEyRlSGVhbHRoU2FzayBQcm9kdWN0aW9uIElzc3Vpbmcg
# Q0EgMDEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCh+xnNg6Mg8XeR
# 2vkBj9pwV2mtvp7J71XcmttcLYS7K1UnZavSHjg2bXixI7UqmoOTBCS8vJ2ST0xx
# qF77fjiiOzXh3BNUxTgb84PgLUguvBhK/kE3X+2hU6TbAlHe1Yr3pbNfAHeZBPe5
# YrYaN1Y0Y1WOi9pzlZCjEibdWPXFAteiNsNG/qT8LfNsWRd9Mtadr7IiVHFp1IMB
# if1HZ0vil6qMGTJJae1iXWlHl8di8rHxEznoYlyGXuwX5eyFA53ULEFsFY+Hh7Pl
# GftGBx+N1MEznqJsXpdIixTaingvm8YbrcxDPqE+DarpBtw549Y2YlcD7O1W3HQf
# Kn1W185tAgMBAAGjggFlMIIBYTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQW
# BBQ8pSVhoHD9x0F1FFNa7qG2KSeHzjALBgNVHQ8EBAMCAYYwEAYJKwYBBAGCNxUB
# BAMCAQAwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwHwYDVR0jBBgwFoAUUXvc
# rFCEgP3rkd8XfSHi2JkFUS4wSwYDVR0fBEQwQjBAoD6gPIY6aHR0cDovL29jc3Au
# ZWhlYWx0aHNhc2suY2EvY3JsL2VIZWFsdGhTYXNrJTIwUm9vdCUyMENBLmNybDCB
# gwYIKwYBBQUHAQEEdzB1MEYGCCsGAQUFBzAChjpodHRwOi8vb2NzcC5laGVhbHRo
# c2Fzay5jYS9jcmwvZUhlYWx0aFNhc2slMjBSb290JTIwQ0EuY3J0MCsGCCsGAQUF
# BzABhh9odHRwOi8vb2NzcC5laGVhbHRoc2Fzay5jYS9vY3NwMA0GCSqGSIb3DQEB
# BQUAA4IBAQAnZFm3yOBTXVxFkeBXDhLu9NjocMlrd4w9FTLO8dt80MYvUx9KEH/D
# cUtmiowLq6tlLQWBkOR2NztAXqD/ORTdzb2pbwmVZ8/iSOT7v5XhdabND8ZWGSaD
# ILPEfJxKC08DImHZ5hKa9BdQa/Nz/BdhmOj+PVI3bq4nn+crlMYEbTRl0i1A2ihU
# bdzfODlQKpcmDRmyN0yMOW3HK5l8KaLFmSOstcF9x0bF8NqCAXLOcOwU4/z39uHh
# hrMAC9y1pXUO+ZLjTW2NuoE8SyJNV8HSTDz6Wy/WbKx+3MDiwUJj5+YtPGNSMvRa
# 7kWZtCJ/krixaOMaX3O2x9w97Ev4ACcRMIIFjzCCBHegAwIBAgIKFxFKUQAAAAAo
# ZDANBgkqhkiG9w0BAQsFADCBhDESMBAGCgmSJomT8ixkARkWAmNhMRIwEAYKCZIm
# iZPyLGQBGRYCc2sxEzARBgoJkiaJk/IsZAEZFgNoaW4xFjAUBgoJkiaJk/IsZAEZ
# FgZoZWFsdGgxLTArBgNVBAMTJGVIZWFsdGhTYXNrIFByb2R1Y3Rpb24gSXNzdWlu
# ZyBDQSAwMTAeFw0xOTA5MTIxNDUyNDNaFw0yMDA5MTExNDUyNDNaMIGeMRIwEAYK
# CZImiZPyLGQBGRYCY2ExEjAQBgoJkiaJk/IsZAEZFgJzazETMBEGCgmSJomT8ixk
# ARkWA2hpbjEWMBQGCgmSJomT8ixkARkWBmhlYWx0aDEWMBQGA1UECxMNVXNlciBB
# Y2NvdW50czENMAsGA1UECxMESElTQzEOMAwGA1UECxMFVXNlcnMxEDAOBgNVBAMT
# B0hhbyBCYW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDoFwf0t8Bq
# F17V8YFLCrfjB8/sOP+YZrJ4NcggDkhL9c7YaX9qhsCLy6MQnTqsoO70GDkc3gws
# xoe0MX9h0fxMOhs/1iBvyMaGFHzjqLSe5oiAMOZulccjNdd7b7Ci9noz1U26HLRl
# aVlk8aP7Pcssq5csBN15r3iH2agYXXF+viMydDjwIynwBwk9VZCt1MEDAXbm0MGy
# Jv5FxlSP/N12Hu9M1yHAAl7EMaTt6Z9CXNm1X60iT9wmjT0CKDp4+ZeRGudfxCtS
# cLt3l6ew/cTq6abkis9pqOFQYGnp+Up6Q95PRShyRAnXfWdqOurINk1fhnbAPLIh
# k+UjRy+GXd+VAgMBAAGjggHlMIIB4TATBgNVHSUEDDAKBggrBgEFBQcDAzAbBgkr
# BgEEAYI3FQoEDjAMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBTyDPc4Q7q7QqIxq2KY
# JLGM2Uo5ADAfBgNVHSMEGDAWgBQ8pSVhoHD9x0F1FFNa7qG2KSeHzjBgBgNVHR8E
# WTBXMFWgU6BRhk9odHRwOi8vb2NzcC5laGVhbHRoc2Fzay5jYS9jcmwvZUhlYWx0
# aFNhc2slMjBQcm9kdWN0aW9uJTIwSXNzdWluZyUyMENBJTIwMDEuY3JsMIGaBggr
# BgEFBQcBAQSBjTCBijBbBggrBgEFBQcwAoZPaHR0cDovL29jc3AuZWhlYWx0aHNh
# c2suY2EvY3JsL2VIZWFsdGhTYXNrJTIwUHJvZHVjdGlvbiUyMElzc3VpbmclMjBD
# QSUyMDAxLmNydDArBggrBgEFBQcwAYYfaHR0cDovL29jc3AuZWhlYWx0aHNhc2su
# Y2Evb2NzcDALBgNVHQ8EBAMCB4AwPgYJKwYBBAGCNxUHBDEwLwYnKwYBBAGCNxUI
# h5jnTYHOwHWG1ZcphZuNTYeIjCSBLIKGuReDiuZ5AgFkAgEFMCEGA1UdEQQaMBiC
# Fmhhby5iYW5AZWhlYWx0aHNhc2suY2EwDQYJKoZIhvcNAQELBQADggEBAACMAxq4
# jENNxUMVmqIf9IWl+7yJbZbQ71GzJPL43A+DBv3OGJAyGrUctBZpMdZKxAcy/2U3
# IjUEgy4fMvgh9wWPY91ifIztVjF0Hk8k9KqX64a1XDbXO4iSN5O6WIicQ4L/fNTJ
# VKZmQNpUAagq/bZz7Nlcti5SvnEy74aSWLKh5WDWZ366Z065QhMpZB1sBE3/hML6
# I+YJpYGRRSJlHmPZCv6PFKovnqjyVMpZ6hIglHtQANrKcvDx8mayUq2+nsSuwj7s
# UJN3VjLGlrnXDK40USXlOOr0TSWP3XanuZ1CVuhuasRvQDtfQQjTrSD8UVqpvGjq
# /uaLXXQFF1huRroxggI1MIICMQIBATCBkzCBhDESMBAGCgmSJomT8ixkARkWAmNh
# MRIwEAYKCZImiZPyLGQBGRYCc2sxEzARBgoJkiaJk/IsZAEZFgNoaW4xFjAUBgoJ
# kiaJk/IsZAEZFgZoZWFsdGgxLTArBgNVBAMTJGVIZWFsdGhTYXNrIFByb2R1Y3Rp
# b24gSXNzdWluZyBDQSAwMQIKFxFKUQAAAAAoZDAJBgUrDgMCGgUAoHgwGAYKKwYB
# BAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAc
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUsiT3
# PZgOUykn0K5ux3DAwEJ/568wDQYJKoZIhvcNAQEBBQAEggEAUPyTH9N9695u1GCL
# fllsMTNV1OJ3IA4sBltjtfw7BtwcbzGRJmFeTJKDd8E01cp7kVZttJG4Qp3xdIty
# RKLW39Ie2eHCtwHOUNnqYSCrhc0yubnkV5eNLjr1+SXJapidb+d1Z94s/lS1eORs
# e+Pew9smfioNZbBCj6zWhAjnkbWKnTYV1VIjBDgZLp3kppVlTNasvwkiziIeTeYw
# t/rH16epGqQJM8RokhDVx7A6UO+23Z+87KofrUq94c3eZ427vwLdoIjgh674FLN+
# 2QgZ2fqJPcPEMHbUqaZhAdsweRD+PwRUi7OKmRX3qyDB6aXgXQNIuquyJRX1TzM9
# YSxTRA==
# SIG # End signature block
