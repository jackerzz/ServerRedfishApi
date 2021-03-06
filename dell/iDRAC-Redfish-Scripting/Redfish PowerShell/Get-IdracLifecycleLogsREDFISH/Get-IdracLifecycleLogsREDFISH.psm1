<#
_author_ = Texas Roemer <Texas_Roemer@Dell.com>
_version_ = 8.0

Copyright (c) 2017, Dell, Inc.

This software is licensed to you under the GNU General Public License,
version 2 (GPLv2). There is NO WARRANTY for this software, express or
implied, including the implied warranties of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
along with this software; if not, see
http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#>




<#
.Synopsis
   Cmdlet used to get complete iDRAC lifecycle logs 
.DESCRIPTION
   Cmdlet using Redfish API with OEM extension to get complete iDRAC Lifecycle logs, echo to the screen. NOTE: Recommended to redirect output to a file due to large amount of data returned.
   - idrac_ip: Pass in iDRAC IP address
   - idrac_username: Pass in iDRAC username
   - idrac_password: Pass in iDRAC username password
   - x_auth_token: Pass in iDRAC X-Auth token session to execute cmdlet instead of username / password (recommended).
.EXAMPLE
   .\Get-IdracLifecycleLogsREDFISH -idrac_ip 192.168.0.120 -username root -password calvin 
   This example will get complete iDRAC Lifecycle Logs, echo output to the screen.
.EXAMPLE
   .\Get-IdracLifecycleLogsREDFISH -idrac_ip 192.168.0.120  
   This example will first prompt to enter username/password using Get-Credential, then execute getting LC logs. 
.EXAMPLE
   .\Get-IdracLifecycleLogsREDFISH -idrac_ip 192.168.0.120 -x_auth_token 163490d51b708f8dc24ca853ef2fc6e7 
   This example will get complete iDRAC Lifecycle Logs using X-auth token session.
.EXAMPLE
   .\Get-IdracLifecycleLogsREDFISH -idrac_ip 192.168.0.120 -username root -password calvin >  R640_iDRAC_LC_logs.txt
   This example will get complete iDRAC Lifecycle Logs and redirect output to a file.
#>

function Get-IdracLifecycleLogsREDFISH {




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

$uri = "https://$idrac_ip/redfish/v1/Systems/System.Embedded.1"

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
    $RespErr
    return
    }
}


Write-Host -ForegroundColor Yellow "`n- INFO, getting Lifecycle Logs for iDRAC $idrac_ip. This cmdlet may take a few minutes to complete depending on log file size`n"
Start-Sleep 10
$next_link_value = 0

while ($true)
{


$skip_uri ="?"+"$"+"skip="+$next_link_value

$uri = "https://$idrac_ip/redfish/v1/Managers/iDRAC.Embedded.1/Logs/Lclog$skip_uri"

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
    if ([string]$RespErr.Contains("Unable to complete the operation because the value"))
    {
    Write-Host -ForegroundColor Yellow "`n- INFO, cmdlet execution complete. Note: If needed, execute cmdlet again and redirect output to a file."
    break
    }
    else
    {
    Write-Host
    $RespErr
    return
    }
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
    if ([string]$RespErr.Contains("Unable to complete the operation because the value"))
    {
    Write-Host -ForegroundColor Yellow "`n- INFO, cmdlet execution complete. Note: If needed, execute cmdlet again and redirect output to a file."
    break
    }
    else
    {
    Write-Host
    $RespErr
    return
    }
    }

}

if ($result.StatusCode -eq 200)
{
}
else
{
    [String]::Format("- FAIL, statuscode {0} returned",$result.StatusCode)
    return
}
$get_content=$result.Content | ConvertFrom-Json
if ($get_content.Members.Count -eq 0)
{
Write-Host -ForegroundColor Yellow "`n- INFO, cmdlet execution complete. Note: If needed, execute cmdlet again and redirect output to a file."
break
}
else
{
$get_content.Members
$next_link_value = $next_link_value+50
}
}

}


