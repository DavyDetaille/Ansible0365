#!powershell

#Requires -Module Ansible.ModuleUtils.Legacy

$ErrorActionPreference = "Stop"

$result = @{
    changed = $false
    failed = $false
}

$params = Parse-Args $args -supports_check_mode $true
$check_mode = Get-AnsibleParam -obj $params -name "_ansible_check_mode" -default $false

# # Module control parameters
$admin_username                               = Get-AnsibleParam -obj $params -name "admin_username" -type "str" -failifempty $true
$admin_password                               = Get-AnsibleParam -obj $params -name "admin_password" -type "str" -failifempty $true

$AllowClickThrough                            = Get-AnsibleParam -obj $params -name "AllowClickThrough" -type "bool"
$AllowSafeDocsOpen                            = Get-AnsibleParam -obj $params -name "AllowSafeDocsOpen" -type "bool"
$BlockUrls                                    = Get-AnsibleParam -obj $params -name "BlockUrls" -type "list"
$EnableATPForSPOTeamsODB                      = Get-AnsibleParam -obj $params -name "EnableATPForSPOTeamsODB" -type "bool"
$EnableSafeDocs                               = Get-AnsibleParam -obj $params -name "EnableSafeDocs" -type "bool"
$EnableSafeLinksForO365Clients                = Get-AnsibleParam -obj $params -name "EnableSafeLinksForO365Clients" -type "bool"
$Ensure                                       = Get-AnsibleParam -obj $params -name "Ensure" -type "str" -validateset "Present" -default "Present"
$Identity                                     = Get-AnsibleParam -obj $params -name "Identity" -type "str"
$IsSingleInstance                             = Get-AnsibleParam -obj $params -name "IsSingleInstance" -type "str" -validateset "Yes" -failifempty $true
$TrackClicks                                  = Get-AnsibleParam -obj $params -name "TrackClicks" -type "bool"

$ApplicationId                                = Get-AnsibleParam -obj $params -name "ApplicationId" -type "str"
$TenantId                                     = Get-AnsibleParam -obj $params -name "TenantId" -type "str"
$CertificateThumbprint                        = Get-AnsibleParam -obj $params -name "CertificateThumbprint" -type "str"
$CertificatePassword                          = Get-AnsibleParam -obj $params -name "CertificatePassword" -type "str"
$CertificatePath                              = Get-AnsibleParam -obj $params -name "CertificatePath" -type "str"

if(($null -ne $CertificatePassword) -and ("" -ne $CertificatePassword)){
    $CertificatePassword                = New-Object System.Management.Automation.PSCredential -ArgumentList ("none",$(ConvertTo-SecureString $CertificatePassword -AsPlainText -Force))
}else{
    $CertificatePassword = $null
}


$inputData = @{
    status = $status
    admin_username                    = $admin_username
    #admin_password                    = $admin_password

    AllowClickThrough                 = $AllowClickThrough
    AllowSafeDocsOpen                 = $AllowSafeDocsOpen
    BlockUrls                         = $BlockUrls
    EnableATPForSPOTeamsODB           = $EnableATPForSPOTeamsODB
    EnableSafeDocs                    = $EnableSafeDocs
    EnableSafeLinksForO365Clients     = $EnableSafeLinksForO365Clients
    Ensure                            = $Ensure
    Identity                          = $Identity
    IsSingleInstance                  = $IsSingleInstance
    TrackClicks                       = $TrackClicks

    ApplicationId                     = $ApplicationId
    TenantId                          = $TenantId
    CertificateThumbprint             = $CertificateThumbprint
    CertificatePassword               = $CertificatePassword
    CertificatePath                   = $CertificatePath
}

$result.invocation = @{
    module_args = $inputData
}

function M365TenantConfig{
    $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($admin_username,$(ConvertTo-SecureString "$admin_password" -AsPlainText -Force))

    $config = @{
        AllNodes = @(
            @{
                NodeName                    = "localhost"
                PSDscAllowPlainTextPassword = $true;
                PSDscAllowDomainUser        = $true;
                ServerNumber = "0"
    
            }
        )
        NonNodeData = @(
        )
    }

    Configuration M365TenantConfig{
        param(
            #[Parameter(Mandatory = $true)]
            [Parameter()]
            [System.Management.Automation.PSCredential]
            $Credential
        )
        $Credscredential = $Credential
        $OrganizationName = $Credential.UserName.Split('@')[1]
        Import-DscResource -ModuleName 'Microsoft365DSC'

        Node localhost{
            EXOAtpPolicyForO365 'data'{
                Credential                        = $Credscredential;
                AllowClickThrough                 = $AllowClickThrough
                AllowSafeDocsOpen                 = $AllowSafeDocsOpen
                BlockUrls                         = $BlockUrls
                EnableATPForSPOTeamsODB           = $EnableATPForSPOTeamsODB
                EnableSafeDocs                    = $EnableSafeDocs
                EnableSafeLinksForO365Clients     = $EnableSafeLinksForO365Clients
                Ensure                            = $Ensure
                Identity                          = $Identity
                IsSingleInstance                  = $IsSingleInstance
                TrackClicks                       = $TrackClicks

                ApplicationId                     = $ApplicationId
                TenantId                          = $TenantId
                CertificateThumbprint             = $CertificateThumbprint
                CertificatePassword               = $CertificatePassword
                CertificatePath                   = $CertificatePath
            }
        }
    }
    $noData = M365TenantConfig -ConfigurationData $config -Credential $Credential
}

function FormatText($data){
    $data = $data -replace "`r",""
    $data = $data -replace "= `n","= "
    $data = $data -replace "; `n","; "
    $data = $data -replace " `n"," "
    $data =  $data.Split("`n")
    return $data
}

Function TargetNewData($data){
    $output = @{}
    for ($i = 0; $i -lt $data.Count; $i++){
        if($null -ne (Select-String -Pattern "Target Values:" -inputObject $data[$i])){
            $Index = ($data[$i].IndexOf("Target Values:")) + 14
            $Length = ($data[$i].Length) - $Index
            $myData = $($data[$i].Substring( $Index , $Length ) ).Split(";")
            for($j =0; $j -lt $myData.Count; $j++){
                if(("" -ne $myData[$j]) -and (" " -ne $myData[$j])){
                    $temp = $myData[$j].Split("=")
                    $temp[0] = $temp[0].Substring(1)
                    if("***" -eq $temp[1]){
                        $temp[1] = $null
                    }
                    if("" -eq $temp[1]){
                        $temp[1] = $null
                    }
                    if ("`$null" -eq $temp[1]){
                        $temp[1] = $null
                    }
                    if ($null -eq $temp[1]){
                        $temp[1] = $null
                    }
                    if ("()" -eq $temp[1]){
                        $temp[1] = @($null)
                    }
                    if ("(" -eq $temp[1][0]){
                        $Index = 1
                        $Length = ($temp[1].Length) - 2
                        $temp[1] = @($temp[1].Substring( $Index , $Length ).Split(","))
                    }
                    $temp[1] = $temp[1] -replace ' ',''
                    $temp[0] = $temp[0] -replace ' ',''
                    $output.add($temp[0],$temp[1])
                }
            }
        }
        if($output.Count -gt 1){
            return $output
        }
    }
}

Function TargetData($data){
    $output = @{}
    for ($i = 0; $i -lt $data.Count; $i++){
        if($null -ne (Select-String -Pattern "Get-TargetResource Result:" -inputObject $data[$i])){
            $Index = ($data[$i].IndexOf("Get-TargetResource Result:")) + 26
            $Length = ($data[$i].Length) - $Index
            $myData = $($data[$i].Substring( $Index , $Length ) ).Split(";")
            for($j =0; $j -lt $myData.Count; $j++){
                if(("" -ne $myData[$j]) -and (" " -ne $myData[$j])){
                    $temp = $myData[$j].Split("=")
                    $temp[0] = $temp[0].Substring(1)
                    if("***" -eq $temp[1]){
                        $temp[1] = $null
                    }
                    if("" -eq $temp[1]){
                        $temp[1] = $null
                    }
                    if ("`$null" -eq $temp[1]){
                        $temp[1] = $null
                    }
                    if ($null -eq $temp[1]){
                        $temp[1] = $null
                    }
                    if ("()" -eq $temp[1]){
                        $temp[1] = @($null)
                    }
                    if ("(" -eq $temp[1][0]){
                        $Index = 1
                        $Length = ($temp[1].Length) - 2
                        $temp[1] = @($temp[1].Substring( $Index , $Length ).Split(","))
                    }
                    $temp[1] = $temp[1] -replace ' ',''
                    $temp[0] = $temp[0] -replace ' ',''
                    $output.add($temp[0],$temp[1])
                }
            }
        }
        if($output.Count -gt 1){
            return $output
        }
    }
}

Function compareData($data){
    $keyList = @(
        "TrackClicks",
        "TenantId",
        "CertificatePath",
        "IsSingleInstance",
        "EnableSafeLinksForO365Clients",
        "EnableATPForSPOTeamsODB",
        "BlockUrls",
        "CertificatePassword",
        "Ensure",
        "Identity",
        "CertificateThumbprint",
        "ApplicationId",
        "EnableSafeDocs",
        "AllowSafeDocsOpen"
        )
    $output = @{}

    for($i = 0; $i -lt $keyList.Count; $i++){
        if(("SignInFrequencyValue" -eq $keyList[$i]) -and ("" -eq $data[0][$keyList[$i]])){
            $data[0][$keyList[$i]] = 0
        }
        if( ($null -ne $data[1][$keyList[$i]]) -and ("" -ne $data[1][$keyList[$i]]) ){
            if($data[0][$keyList[$i]] -ne $data[1][$keyList[$i]]){
                $output.add($keyList[$i], "Data change : '$($data[0][$keyList[$i]])' -> '$($data[1][$keyList[$i]])'")
            }
        }
    }
    return $output
}

function Actions($data){
    $oldData = TargetData($data)
    $newData = TargetNewData($data)
    try{
        $changes = compareData($oldData, $newData)
    }catch {
    }


    # if($newData["Ensure"] -eq "Absent"){
    #     $result.msg = "This anti phish policy is revoved or don't exist"
    # }else{
    #     $result.msg = "This anti phish policy is created or alredy exist"
    # }

    $result.stdout_lines = @{
        oldData = $oldData;
        newData = $newData;
        changes = $changes;
    }

    if(($oldData.Count -eq 0) -and ($newData["Ensure"] -eq "Present")){
        $result.changed = $true
    }

    if($changes.Count -ne 0){
        $result.changed = $true
    }
}

try{
    M365TenantConfig -ErrorAction Stop
    $output = Start-DscConfiguration M365TenantConfig -Force -wait -verbose 4>&1 -ErrorAction Stop
    Actions(FormatText($output))
}catch{
    Fail-Json -obj $result -message ( $error[0] | out-string )
}

$result.warning = "Turn on Safe Documents for Office clients; files will also be sent to Microsoft Cloud for deep analyses. (Only available with Microsoft 365 E5 or Microsoft 365 E5 Security license.)"

Exit-Json $result