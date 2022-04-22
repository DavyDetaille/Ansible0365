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
$admin_username       = Get-AnsibleParam -obj $params -name "admin_username" -type "str" -failifempty $true
$admin_password       = Get-AnsibleParam -obj $params -name "admin_password" -type "str" -failifempty $true

$DisplayName                   = Get-AnsibleParam -obj $params -name "DisplayName" -type "str"
$MailNickname                  = Get-AnsibleParam -obj $params -name "MailNickname" -type "str"
$Description                   = Get-AnsibleParam -obj $params -name "Description" -type "str"
$Id                            = Get-AnsibleParam -obj $params -name "Id" -type "str"
$GroupTypes                    = Get-AnsibleParam -obj $params -name "GroupTypes" -type "list"
$MembershipRule                = Get-AnsibleParam -obj $params -name "MembershipRule" -type "str"
$MembershipRuleProcessingState = Get-AnsibleParam -obj $params -name "MembershipRuleProcessingState" -type "str" -validateset "On", "Paused"
$SecurityEnabled               = Get-AnsibleParam -obj $params -name "SecurityEnabled" -type "bool"
$MailEnabled                   = Get-AnsibleParam -obj $params -name "MailEnabled" -type "bool"
$IsAssignableToRole            = Get-AnsibleParam -obj $params -name "IsAssignableToRole" -type "bool"
$Visibility                    = Get-AnsibleParam -obj $params -name "Visibility" -type "str" -validateset "Public", "Private", "HiddenMembership"
$Ensure                        = Get-AnsibleParam -obj $params -name "Ensure" -type "str" -validateset "Present", "Absent" -failifempty $true
$ApplicationId                 = Get-AnsibleParam -obj $params -name "ApplicationId" -type "str"
$TenantId                      = Get-AnsibleParam -obj $params -name "TenantId" -type "str"
$ApplicationSecret             = Get-AnsibleParam -obj $params -name "ApplicationSecret" -type "str"
$CertificateThumbprint         = Get-AnsibleParam -obj $params -name "CertificateThumbprint" -type "str"

if(($null -ne $CertificatePassword) -and ("" -ne $CertificatePassword)){
    $CertificatePassword = New-Object System.Management.Automation.PSCredential -ArgumentList ("none",$(ConvertTo-SecureString $CertificatePassword -AsPlainText -Force))
}else{
    $CertificatePassword = $null
}

$inputData = @{
    admin_username                    = $admin_username
    #admin_password                    = $admin_password
 
    DisplayName                   = $DisplayName
    MailNickname                  = $MailNickname
    Description                   = $Description
    Id                            = $Id
    GroupTypes                    = $GroupTypes
    MembershipRule                = $MembershipRule
    MembershipRuleProcessingState = $MembershipRuleProcessingState
    SecurityEnabled               = $SecurityEnabled
    MailEnabled                   = $MailEnabled
    IsAssignableToRole            = $IsAssignableToRole
    Visibility                    = $Visibility
    Ensure                        = $Ensure
    ApplicationId                 = $ApplicationId
    TenantId                      = $TenantId
    ApplicationSecret             = $ApplicationSecret
    CertificateThumbprint         = $CertificateThumbprint
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
            AADGroup 'data'{
                DisplayName                   = $DisplayName
                MailNickname                  = $MailNickname
                Description                   = $Description
                Id                            = $Id
                GroupTypes                    = $GroupTypes
                MembershipRule                = $MembershipRule
                MembershipRuleProcessingState = $MembershipRuleProcessingState
                SecurityEnabled               = $SecurityEnabled
                MailEnabled                   = $MailEnabled
                IsAssignableToRole            = $IsAssignableToRole
                Visibility                    = $Visibility
                Ensure                        = $Ensure
                Credential                    = $Credential
                ApplicationId                 = $ApplicationId
                TenantId                      = $TenantId
                ApplicationSecret             = $ApplicationSecret
                CertificateThumbprint         = $CertificateThumbprint
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
            $Index = ($data[$i].IndexOf("Current Values:")) + 15
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
        "DisplayName",
        "MailNickname",
        "Description",
        "Id",
        "GroupTypes",
        "MembershipRule",
        "MembershipRuleProcessingState",
        "SecurityEnabled",
        "MailEnabled",
        "IsAssignableToRole",
        "Visibility",
        "Ensure",
        "ApplicationId",
        "TenantId",
        "ApplicationSecret",
        "CertificateThumbprint"
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

    $oldData.Domains
    $newData.Domains

    try{
        $changes = compareData($oldData, $newData)
    }catch {
    }


    # if($newData["Ensure"] -eq "Absent"){
    #     $result.msg = "This group is revoved or don't exist"
    # }else{
    #     $result.msg = "This group is created or alredy exist"
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

Exit-Json $result