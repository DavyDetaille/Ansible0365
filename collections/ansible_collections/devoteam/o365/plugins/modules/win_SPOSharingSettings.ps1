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
$admin_username               = Get-AnsibleParam -obj $params -name "admin_username" -type "str" -failifempty $true
$admin_password               = Get-AnsibleParam -obj $params -name "admin_password" -type "str" -failifempty $true

$BccExternalSharingInvitations              = Get-AnsibleParam -obj $params -name "BccExternalSharingInvitations" -type "bool"
$DefaultLinkPermission                      = Get-AnsibleParam -obj $params -name "DefaultLinkPermission" -type "str"
$DefaultSharingLinkType                     = Get-AnsibleParam -obj $params -name "DefaultSharingLinkType" -type "str"
$EnableGuestSignInAcceleration              = Get-AnsibleParam -obj $params -name "EnableGuestSignInAcceleration" -type "bool"
$FileAnonymousLinkType                      = Get-AnsibleParam -obj $params -name "FileAnonymousLinkType" -type "str"
$FolderAnonymousLinkType                    = Get-AnsibleParam -obj $params -name "FolderAnonymousLinkType" -type "str"
$IsSingleInstance                           = Get-AnsibleParam -obj $params -name "IsSingleInstance" -type "str" -validateset "Yes" -failifempty $true
$NotifyOwnersWhenItemsReshared              = Get-AnsibleParam -obj $params -name "NotifyOwnersWhenItemsReshared" -type "bool"
$PreventExternalUsersFromResharing          = Get-AnsibleParam -obj $params -name "PreventExternalUsersFromResharing" -type "bool"
$ProvisionSharedWithEveryoneFolder          = Get-AnsibleParam -obj $params -name "ProvisionSharedWithEveryoneFolder" -type "bool"
$RequireAcceptingAccountMatchInvitedAccount = Get-AnsibleParam -obj $params -name "RequireAcceptingAccountMatchInvitedAccount" -type "bool"
$SharingCapability                          = Get-AnsibleParam -obj $params -name "SharingCapability" -type "str" -validateset "ExistingExternalUserSharingOnly", "ExternalUserAndGuestSharing", "Disabled", "ExternalUserSharingOnly"
$SharingDomainRestrictionMode               = Get-AnsibleParam -obj $params -name "SharingDomainRestrictionMode" -type "str"
$ShowAllUsersClaim                          = Get-AnsibleParam -obj $params -name "ShowAllUsersClaim" -type "bool"
$ShowEveryoneClaim                          = Get-AnsibleParam -obj $params -name "ShowEveryoneClaim" -type "bool"
$ShowEveryoneExceptExternalUsersClaim       = Get-AnsibleParam -obj $params -name "ShowEveryoneExceptExternalUsersClaim" -type "bool"
$ShowPeoplePickerSuggestionsForGuestUsers   = Get-AnsibleParam -obj $params -name "ShowPeoplePickerSuggestionsForGuestUsers" -type "bool"

$BccExternalSharingInvitationsList          = Get-AnsibleParam -obj $params -name "BccExternalSharingInvitationsList" -type "str"
$RequireAnonymousLinksExpireInDays          = Get-AnsibleParam -obj $params -name "RequireAnonymousLinksExpireInDays" -type "int"
$SharingAllowedDomainList                   = Get-AnsibleParam -obj $params -name "SharingAllowedDomainList" -type "list"
$SharingBlockedDomainList                   = Get-AnsibleParam -obj $params -name "SharingBlockedDomainList" -type "list"
$ApplicationId                              = Get-AnsibleParam -obj $params -name "ApplicationId" -type "str"
$ApplicationSecret                          = Get-AnsibleParam -obj $params -name "ApplicationSecret" -type "str"
$TenantId                                   = Get-AnsibleParam -obj $params -name "TenantId" -type "str"
$CertificatePassword                        = Get-AnsibleParam -obj $params -name "CertificatePassword" -type "str"
$CertificatePath                            = Get-AnsibleParam -obj $params -name "CertificatePath" -type "str"
$CertificateThumbprint                      = Get-AnsibleParam -obj $params -name "CertificateThumbprint" -type "str"


if(($null -ne $CertificatePassword) -and ("" -ne $CertificatePassword)){
    $CertificatePassword                = New-Object System.Management.Automation.PSCredential -ArgumentList ("none",$(ConvertTo-SecureString $CertificatePassword -AsPlainText -Force))
}else{
    $CertificatePassword = $null
}

$inputData = @{
    admin_username                    = $admin_username
    #admin_password                    = $admin_password
 
    BccExternalSharingInvitations              = $BccExternalSharingInvitations
    DefaultLinkPermission                      = $DefaultLinkPermission
    DefaultSharingLinkType                     = $DefaultSharingLinkType
    EnableGuestSignInAcceleration              = $EnableGuestSignInAcceleration
    FileAnonymousLinkType                      = $FileAnonymousLinkType
    FolderAnonymousLinkType                    = $FolderAnonymousLinkType
    IsSingleInstance                           = $IsSingleInstance
    NotifyOwnersWhenItemsReshared              = $NotifyOwnersWhenItemsReshared
    PreventExternalUsersFromResharing          = $PreventExternalUsersFromResharing
    ProvisionSharedWithEveryoneFolder          = $ProvisionSharedWithEveryoneFolder
    RequireAcceptingAccountMatchInvitedAccount = $RequireAcceptingAccountMatchInvitedAccount
    SharingCapability                          = $SharingCapability
    SharingDomainRestrictionMode               = $SharingDomainRestrictionMode
    ShowAllUsersClaim                          = $ShowAllUsersClaim
    ShowEveryoneClaim                          = $ShowEveryoneClaim
    ShowEveryoneExceptExternalUsersClaim       = $ShowEveryoneExceptExternalUsersClaim
    ShowPeoplePickerSuggestionsForGuestUsers   = $ShowPeoplePickerSuggestionsForGuestUsers

    BccExternalSharingInvitationsList          = $BccExternalSharingInvitationsList
    RequireAnonymousLinksExpireInDays          = $RequireAnonymousLinksExpireInDays
    SharingAllowedDomainList                   = $SharingAllowedDomainList
    SharingBlockedDomainList                   = $SharingBlockedDomainList
    ApplicationId                              = $ApplicationId
    ApplicationSecret                          = $ApplicationSecret
    TenantId                                   = $TenantId
    CertificatePassword                        = $CertificatePassword
    CertificatePath                            = $CertificatePath
    CertificateThumbprint                      = $CertificateThumbprint
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

        if($null -eq $RequireAnonymousLinksExpireInDays){
            Node localhost{
                SPOSharingSettings "data"{
                    Credential                                 = $Credscredential;
    
                    BccExternalSharingInvitations              = $BccExternalSharingInvitations
                    DefaultLinkPermission                      = $DefaultLinkPermission
                    DefaultSharingLinkType                     = $DefaultSharingLinkType
                    EnableGuestSignInAcceleration              = $EnableGuestSignInAcceleration
                    FileAnonymousLinkType                      = $FileAnonymousLinkType
                    FolderAnonymousLinkType                    = $FolderAnonymousLinkType
                    IsSingleInstance                           = $IsSingleInstance
                    NotifyOwnersWhenItemsReshared              = $NotifyOwnersWhenItemsReshared
                    PreventExternalUsersFromResharing          = $PreventExternalUsersFromResharing
                    ProvisionSharedWithEveryoneFolder          = $ProvisionSharedWithEveryoneFolder
                    RequireAcceptingAccountMatchInvitedAccount = $RequireAcceptingAccountMatchInvitedAccount
                    SharingCapability                          = $SharingCapability
                    SharingDomainRestrictionMode               = $SharingDomainRestrictionMode
                    ShowAllUsersClaim                          = $ShowAllUsersClaim
                    ShowEveryoneClaim                          = $ShowEveryoneClaim
                    ShowEveryoneExceptExternalUsersClaim       = $ShowEveryoneExceptExternalUsersClaim
                    ShowPeoplePickerSuggestionsForGuestUsers   = $ShowPeoplePickerSuggestionsForGuestUsers
    
                    BccExternalSharingInvitationsList          = $BccExternalSharingInvitationsList
                    # RequireAnonymousLinksExpireInDays          = $RequireAnonymousLinksExpireInDays
                    SharingAllowedDomainList                   = $SharingAllowedDomainList
                    SharingBlockedDomainList                   = $SharingBlockedDomainList
                    ApplicationId                              = $ApplicationId
                    ApplicationSecret                          = $ApplicationSecret
                    TenantId                                   = $TenantId
                    CertificatePassword                        = $CertificatePassword
                    CertificatePath                            = $CertificatePath
                    CertificateThumbprint                      = $CertificateThumbprint
                }
            }
        }else{
            Node localhost{
                SPOSharingSettings "data"{
                    Credential                                 = $Credscredential;
    
                    BccExternalSharingInvitations              = $BccExternalSharingInvitations
                    DefaultLinkPermission                      = $DefaultLinkPermission
                    DefaultSharingLinkType                     = $DefaultSharingLinkType
                    EnableGuestSignInAcceleration              = $EnableGuestSignInAcceleration
                    FileAnonymousLinkType                      = $FileAnonymousLinkType
                    FolderAnonymousLinkType                    = $FolderAnonymousLinkType
                    IsSingleInstance                           = $IsSingleInstance
                    NotifyOwnersWhenItemsReshared              = $NotifyOwnersWhenItemsReshared
                    PreventExternalUsersFromResharing          = $PreventExternalUsersFromResharing
                    ProvisionSharedWithEveryoneFolder          = $ProvisionSharedWithEveryoneFolder
                    RequireAcceptingAccountMatchInvitedAccount = $RequireAcceptingAccountMatchInvitedAccount
                    SharingCapability                          = $SharingCapability
                    SharingDomainRestrictionMode               = $SharingDomainRestrictionMode
                    ShowAllUsersClaim                          = $ShowAllUsersClaim
                    ShowEveryoneClaim                          = $ShowEveryoneClaim
                    ShowEveryoneExceptExternalUsersClaim       = $ShowEveryoneExceptExternalUsersClaim
                    ShowPeoplePickerSuggestionsForGuestUsers   = $ShowPeoplePickerSuggestionsForGuestUsers
    
                    BccExternalSharingInvitationsList          = $BccExternalSharingInvitationsList
                    RequireAnonymousLinksExpireInDays          = $RequireAnonymousLinksExpireInDays
                    SharingAllowedDomainList                   = $SharingAllowedDomainList
                    SharingBlockedDomainList                   = $SharingBlockedDomainList
                    ApplicationId                              = $ApplicationId
                    ApplicationSecret                          = $ApplicationSecret
                    TenantId                                   = $TenantId
                    CertificatePassword                        = $CertificatePassword
                    CertificatePath                            = $CertificatePath
                    CertificateThumbprint                      = $CertificateThumbprint
                }
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
        if($null -ne (Select-String -Pattern "Current Values:" -inputObject $data[$i])){
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
        "IsSingleInstance",
        "SharingCapability",
        "ShowEveryoneClaim",
        "ShowAllUsersClaim",
        "ShowEveryoneExceptExternalUsersClaim",
        "ProvisionSharedWithEveryoneFolder",
        "EnableGuestSignInAcceleration",
        "BccExternalSharingInvitations",
        "BccExternalSharingInvitationsList",
        "RequireAnonymousLinksExpireInDays",
        "SharingAllowedDomainList",
        "SharingBlockedDomainList",
        "SharingDomainRestrictionMode",
        "DefaultSharingLinkType",
        "PreventExternalUsersFromResharing",
        "ShowPeoplePickerSuggestionsForGuestUsers",
        "FileAnonymousLinkType",
        "FolderAnonymousLinkType",
        "NotifyOwnersWhenItemsReshared",
        "DefaultLinkPermission",
        "ApplicationId",
        "ApplicationSecret",
        "TenantId",
        "CertificatePassword",
        "CertificatePath",
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
    #     $result.msg = "This safe links policy is revoved or don't exist"
    # }else{
    #     $result.msg = "This safe links policy is created or alredy exist"
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