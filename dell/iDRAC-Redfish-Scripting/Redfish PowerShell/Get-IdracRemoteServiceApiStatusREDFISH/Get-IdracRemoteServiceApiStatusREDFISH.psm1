<#
_author_ = Texas Roemer <Texas_Roemer@Dell.com>
_version_ = 4.0

Copyright (c) 2020, Dell, Inc.

This software is licensed to you under the GNU General Public License,
version 2 (GPLv2). There is NO WARRANTY for this software, express or
implied, including the implied warranties of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
along with this software; if not, see
http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#>




<#
.Synopsis
   Cmdlet used to get iDRAC remote services status.
.DESCRIPTION
   Cmdlet using Redfish API with OEM extension to get iDRAC remote service status. The output will return LC (Lifecycle controller) status, RT (real time monitoring) status, server status (examples, in POST or in in BIOS boot manager) and overall status. 
   - idrac_ip: Pass in iDRAC IP address
   - idrac_username: Pass in iDRAC username
   - idrac_password: Pass in iDRAC username password
   - x_auth_token: Pass in iDRAC X-Auth token session to execute cmdlet instead of username / password (recommended).
.EXAMPLE
   .\Get-IdracRemoteServiceApiStatusREDFISH -idrac_ip 192.168.0.120 -username root -password calvin 
   This example will return remote services status for the iDRAC. 
   .\Get-IdracRemoteServiceApiStatusREDFISH -idrac_ip 192.168.0.120 
   This example will first prompt to enter username/password using Get-Credential, then return remote services status for the iDRAC. 
   .EXAMPLE
   .\Get-IdracRemoteServiceApiStatusREDFISH -idrac_ip 192.168.0.120 -x_auth_token 163490d51b708f8dc24ca853ef2fc6e7 
   This example will return remote services status for the iDRAC using X-auth token session.
#>

function Get-IdracRemoteServiceApiStatusREDFISH {






param(
    [Parameter(Mandatory=$False)]
    [string]$idrac_ip,
    [Parameter(Mandatory=$False)]
    [string]$idrac_username,
    [Parameter(Mandatory=$False)]
    [string]$idrac_password,
    [Parameter(Mandatory=$False)]
    [string]$x_auth_token
    )

# Function to ignore SSL certs

function Ignore-SSLCertificates
{
    $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
    $Compiler = $Provider.CreateCompiler()
    $Params = New-Object System.CodeDom.Compiler.CompilerParameters
    $Params.GenerateExecutable = $false
    $Params.GenerateInMemory = $true
    $Params.IncludeDebugInformation = $false
    $Params.ReferencedAssemblies.Add("System.DLL") > $null
    $TASource=@'
        namespace Local.ToolkitExtensions.Net.CertificatePolicy
        {
            public class TrustAll : System.Net.ICertificatePolicy
            {
                public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                {
                    return true;
                }
            }
        }
'@ 
    $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
    $TAAssembly=$TAResults.CompiledAssembly
    $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
    [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
}

$global:get_powershell_version = $null

function get_powershell_version 
{
$get_host_info = Get-Host
$major_number = $get_host_info.Version.Major
$global:get_powershell_version = $major_number
}

get_powershell_version


[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12
if ($idrac_username -and $idrac_password)
{
$user = $idrac_username
$pass= $idrac_password
$secpasswd = ConvertTo-SecureString $pass -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($user, $secpasswd)
}
elseif ($x_auth_token)
{
}
else
{
$get_creds = Get-Credential
$credential = New-Object System.Management.Automation.PSCredential($get_creds.UserName, $get_creds.Password)
}

$uri = "https://$idrac_ip/redfish/v1/Systems/System.Embedded.1/Storage"

if ($x_auth_token)
{
 try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept" = "application/json"; "X-Auth-Token" = $x_auth_token}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"; "X-Auth-Token" = $x_auth_token}
    }
    }
    catch
    {
    Write-Host
    $RespErr
    return
    }
}

else
{
    try
    {
    if ($global:get_powershell_version -gt 5)
    {
    $result = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    else
    {
    Ignore-SSLCertificates
    $result = Invoke-WebRequest -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept"="application/json"}
    }
    }
    catch
    {
    Write-Host
    $RespErr
    return
    }
}

 if ($result.StatusCode -ne 200)
	    {
        Write-Host "`n- WARNING, iDRAC version detected does not support this feature using Redfish API"
	    return
	    }
        elseif ($result.StatusCode -eq 401)
        {
        Write-Host "`n- WARNING, invalid iDRAC username or password detected, status code 401 returned."
        return
        }
	    else
	    {
	    }




$JsonBody = @{} | ConvertTo-Json -Compress
$uri = "https://$idrac_ip/redfish/v1/Dell/Managers/iDRAC.Embedded.1/DellLCService/Actions/DellLCService.GetRemoteServicesAPIStatus"

if ($x_auth_token)
{
try
{
    if ($global:get_powershell_version -gt 5)
    {
    
    $post_result = Invoke-WebRequest -UseBasicParsing -SkipHeaderValidation -SkipCertificateCheck -Uri $uri -Body $JsonBody -Method Post -ContentType 'application/json' -Headers @{"Accept" = "application/json"; "X-Auth-Token" = $x_auth_token} -ErrorVariable RespErr
    }
    else
    {
    Ignore-SSLCertificates
    $post_result = Invoke-WebRequest -UseBasicParsing -Uri $uri -Method Post -ContentType 'application/json' -Headers @{"Accept" = "application/json"; "X-Auth-Token" = $x_auth_token} -Body $JsonBody -ErrorVariable RespErr
    }
}
catch
{
Write-Host
$RespErr
return
} 
}


else
{
try
{
    if ($global:get_powershell_version -gt 5)
    {
    
    $post_result = Invoke-WebRequest -UseBasicParsing -SkipHeaderValidation -SkipCertificateCheck -Uri $uri -Credential $credential -Body $JsonBody -Method Post -ContentType 'application/json' -Headers @{"Accept"="application/json"} -ErrorVariable RespErr
    }
    else
    {
    Ignore-SSLCertificates
    $post_result = Invoke-WebRequest -UseBasicParsing -Uri $uri -Credential $credential -Method Post -ContentType 'application/json' -Headers @{"Accept"="application/json"} -Body $JsonBody -ErrorVariable RespErr
    }
}
catch
{
Write-Host
$RespErr
return
} 
}


if ($post_result.StatusCode -eq 200 -or $post_result.StatusCode -eq 200)
{
#Write-Host "- PASS, POST command passed to get iDRAC remote service API status"
}
else
{
[String]::Format("- FAIL, POST command failed to get iDRAC remote service API status, statuscode {0} returned. Detail error message: {1}",$post_result.StatusCode, $post_result)
return
}

$get_post_result = $post_result.Content | ConvertFrom-Json
$lc_status = $get_post_result.LCStatus
$rt_status = $get_post_result.RTStatus
$server_status = $get_post_result.ServerStatus
$status = $get_post_result.Status
Write-Host "`n- Get Remote Service API Status results for iDRAC $idrac_ip -`n"
Write-Host "LCStatus: $lc_status"
Write-Host "RTStatus: $rt_status"
Write-Host "ServerStatus: $server_status"
Write-Host "Status: $status"
Write-Host

}


