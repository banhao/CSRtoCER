# CSRtoCER
[![Minimum Supported PowerShell Version](https://img.shields.io/badge/PowerShell-5.1+-purple.svg)](https://github.com/PowerShell/PowerShell) ![Cross Platform](https://img.shields.io/badge/platform-windows-lightgrey)
[![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/CSRtoCER)](https://www.powershellgallery.com/packages/CSRtoCER) [![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/CSRtoCER)](https://www.powershellgallery.com/packages/CSRtoCER)

“CSRtoCER.ps1” is used to view the information from a CSR file and generate the certificate based on the CSR file.
This PowerShell will grab the information such as "Subject", "Key Length", "SANs", "Template" from the CSR file.
If the SANs is not empty in the CSR file, the script will use the CSR file’s setting. If there's no SANs in CSR file, script will use “CN” as the SANs.
The script will also list the Template that used in the CSR file, If there's no Template in the CSR file, script will list all the available Certificate Templates from your AD, when you pick up one, script will list the CA Server which has the Template you picked up.

Before you run the script Install the PSPKI module in your PowerShell running environment. https://www.powershellgallery.com/packages/PSPKI/3.5


You also can find this script in powershellgallery.com https://www.powershellgallery.com/packages/CSRtoCER/
