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
$admin_username                                = Get-AnsibleParam -obj $params -name "admin_username" -type "str" -failifempty $true
$admin_password                                = Get-AnsibleParam -obj $params -name "admin_password" -type "str" -failifempty $true

$AdminDisplayName                              = Get-AnsibleParam -obj $params -name "AdminDisplayName" -type "str"
$AuthenticationFailAction                      = Get-AnsibleParam -obj $params -name "AuthenticationFailAction" -type "str" -validateset "MoveToJmf", "Quarantine" # "MoveToJmf";
$Enabled                                       = Get-AnsibleParam -obj $params -name "Enabled" -type "bool" # $True;
$EnableFirstContactSafetyTips                  = Get-AnsibleParam -obj $params -name "EnableFirstContactSafetyTips" -type "bool" # $True;
$EnableMailboxIntelligence                     = Get-AnsibleParam -obj $params -name "EnableMailboxIntelligence" -type "bool" # $True;
$EnableMailboxIntelligenceProtection           = Get-AnsibleParam -obj $params -name "EnableMailboxIntelligenceProtection" -type "bool" # $False;
$EnableOrganizationDomainsProtection           = Get-AnsibleParam -obj $params -name "EnableOrganizationDomainsProtection" -type "bool" # $False;
$EnableSimilarDomainsSafetyTips                = Get-AnsibleParam -obj $params -name "EnableSimilarDomainsSafetyTips" -type "bool" # $False;
$EnableSimilarUsersSafetyTips                  = Get-AnsibleParam -obj $params -name "EnableSimilarUsersSafetyTips" -type "bool" # $False;
$EnableSpoofIntelligence                       = Get-AnsibleParam -obj $params -name "EnableSpoofIntelligence" -type "bool" # $True;
$EnableTargetedDomainsProtection               = Get-AnsibleParam -obj $params -name "EnableTargetedDomainsProtection" -type "bool" # $False;
$EnableTargetedUserProtection                  = Get-AnsibleParam -obj $params -name "EnableTargetedUserProtection" -type "bool" # $True;
$EnableUnauthenticatedSender                   = Get-AnsibleParam -obj $params -name "EnableUnauthenticatedSender" -type "bool" # $True;
$EnableUnusualCharactersSafetyTips             = Get-AnsibleParam -obj $params -name "EnableUnusualCharactersSafetyTips" -type "bool" # $False;
$EnableViaTag                                  = Get-AnsibleParam -obj $params -name "EnableViaTag" -type "bool" # $True;
$Ensure                                        = Get-AnsibleParam -obj $params -name "Ensure" -type "str" -validateset "Present", "Absent" -failifempty $true
$ExcludedDomains                               = Get-AnsibleParam -obj $params -name "ExcludedDomains" -type "list"
$ExcludedSenders                               = Get-AnsibleParam -obj $params -name "ExcludedSenders" -type "list"
$Identity                                      = Get-AnsibleParam -obj $params -name "Identity" -type "str" -failifempty $true # "MON TEST";
$ImpersonationProtectionState                  = Get-AnsibleParam -obj $params -name "ImpersonationProtectionState" -type "str" # "Manual";
$MailboxIntelligenceProtectionAction           = Get-AnsibleParam -obj $params -name "MailboxIntelligenceProtectionAction" -type "str" # "NoAction";
$MailboxIntelligenceProtectionActionRecipients = Get-AnsibleParam -obj $params -name "MailboxIntelligenceProtectionActionRecipients" -type "list"
$MakeDefault                                   = Get-AnsibleParam -obj $params -name "MakeDefault" -type "bool" # $False;
$PhishThresholdLevel                           = Get-AnsibleParam -obj $params -name "PhishThresholdLevel" -type "int" -validateset 1, 2, 3, 4
$TargetedDomainActionRecipients                = Get-AnsibleParam -obj $params -name "TargetedDomainActionRecipients" -type "list"
$TargetedDomainsToProtect                      = Get-AnsibleParam -obj $params -name "TargetedDomainsToProtect" -type "list"
$TargetedUserActionRecipients                  = Get-AnsibleParam -obj $params -name "TargetedUserActionRecipients" -type "list"
$TargetedUserProtectionAction                  = Get-AnsibleParam -obj $params -name "TargetedUserProtectionAction" -type "str" -validateset "BccMessage", "Delete", "MoveToJmf", "NoAction", "Quarantine", "Redirect"
$TargetedUsersToProtect                        = Get-AnsibleParam -obj $params -name "TargetedUsersToProtect" -type "list"


$inputData = @{
    status = $status
    admin_username                    = $admin_username
    #admin_password                    = $admin_password

    AdminDisplayName                              = $AdminDisplayName
    AuthenticationFailAction                      = $AuthenticationFailAction
    Enabled                                       = $Enabled
    EnableFirstContactSafetyTips                  = $EnableFirstContactSafetyTips
    EnableMailboxIntelligence                     = $EnableMailboxIntelligence
    EnableMailboxIntelligenceProtection           = $EnableMailboxIntelligenceProtection
    EnableOrganizationDomainsProtection           = $EnableOrganizationDomainsProtection
    EnableSimilarDomainsSafetyTips                = $EnableSimilarDomainsSafetyTips
    EnableSimilarUsersSafetyTips                  = $EnableSimilarUsersSafetyTips
    EnableSpoofIntelligence                       = $EnableSpoofIntelligence
    EnableTargetedDomainsProtection               = $EnableTargetedDomainsProtection
    EnableTargetedUserProtection                  = $EnableTargetedUserProtection
    EnableUnauthenticatedSender                   = $EnableUnauthenticatedSender
    EnableUnusualCharactersSafetyTips             = $EnableUnusualCharactersSafetyTips
    EnableViaTag                                  = $EnableViaTag
    Ensure                                        = $Ensure
    ExcludedDomains                               = $ExcludedDomains
    ExcludedSenders                               = $ExcludedSenders
    Identity                                      = $Identity
    ImpersonationProtectionState                  = $ImpersonationProtectionState
    MailboxIntelligenceProtectionAction           = $MailboxIntelligenceProtectionAction
    MailboxIntelligenceProtectionActionRecipients = $MailboxIntelligenceProtectionActionRecipients
    MakeDefault                                   = $MakeDefault
    PhishThresholdLevel                           = $PhishThresholdLevel
    TargetedDomainActionRecipients                = $TargetedDomainActionRecipients
    TargetedDomainsToProtect                      = $TargetedDomainsToProtect
    TargetedUserActionRecipients                  = $TargetedUserActionRecipients
    TargetedUserProtectionAction                  = $TargetedUserProtectionAction
    TargetedUsersToProtect                        = $TargetedUsersToProtect
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

        Node localhost {
            EXOAntiPhishPolicy "MON TEST"{
                Credential                                    = $Credential
                AdminDisplayName                              = $AdminDisplayName
                AuthenticationFailAction                      = $AuthenticationFailAction
                Enabled                                       = $Enabled
                EnableFirstContactSafetyTips                  = $EnableFirstContactSafetyTips
                EnableMailboxIntelligence                     = $EnableMailboxIntelligence
                EnableMailboxIntelligenceProtection           = $EnableMailboxIntelligenceProtection
                EnableOrganizationDomainsProtection           = $EnableOrganizationDomainsProtection
                EnableSimilarDomainsSafetyTips                = $EnableSimilarDomainsSafetyTips
                EnableSimilarUsersSafetyTips                  = $EnableSimilarUsersSafetyTips
                EnableSpoofIntelligence                       = $EnableSpoofIntelligence
                EnableTargetedDomainsProtection               = $EnableTargetedDomainsProtection
                EnableTargetedUserProtection                  = $EnableTargetedUserProtection
                EnableUnauthenticatedSender                   = $EnableUnauthenticatedSender
                EnableUnusualCharactersSafetyTips             = $EnableUnusualCharactersSafetyTips
                EnableViaTag                                  = $EnableViaTag
                Ensure                                        = $Ensure
                ExcludedDomains                               = $ExcludedDomains
                ExcludedSenders                               = $ExcludedSenders
                Identity                                      = $Identity
                ImpersonationProtectionState                  = $ImpersonationProtectionState
                MailboxIntelligenceProtectionAction           = $MailboxIntelligenceProtectionAction
                MailboxIntelligenceProtectionActionRecipients = $MailboxIntelligenceProtectionActionRecipients
                MakeDefault                                   = $MakeDefault
                PhishThresholdLevel                           = $PhishThresholdLevel
                TargetedDomainActionRecipients                = $TargetedDomainActionRecipients
                TargetedDomainsToProtect                      = $TargetedDomainsToProtect
                TargetedUserActionRecipients                  = $TargetedUserActionRecipients
                TargetedUserProtectionAction                  = $TargetedUserProtectionAction
                TargetedUsersToProtect                        = $TargetedUsersToProtect
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
        "TenantId",
        "CertificatePath",
        "AdminDisplayName",
        "BodyCanonicalization",
        "CertificatePassword",
        "Ensure",
        "Identity",
        "Credential",
        "KeySize",
        "CertificateThumbprint",
        "HeaderCanonicalization",
        "ApplicationId",
        "Enabled"
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


    if($newData["Ensure"] -eq "Absent"){
        $result.msg = "This anti phish policy is revoved or don't exist"
    }else{
        $result.msg = "This anti phish policy is created or alredy exist"
    }

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

    # $data = FormatText($output)
    # # $data
    # TargetNewData($data)
    # echo "---"
    # TargetData($data)

}catch{
    Fail-Json -obj $result -message ( $error[0] | out-string )
}

Exit-Json $result