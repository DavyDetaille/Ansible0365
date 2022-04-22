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

$Url                                         = Get-AnsibleParam -obj $params -name "Url" -type "str"
$Title                                       = Get-AnsibleParam -obj $params -name "Title" -type "str"
$Owner                                       = Get-AnsibleParam -obj $params -name "Owner" -type "str"
$TimeZoneId                                  = Get-AnsibleParam -obj $params -name "TimeZoneId" -type "int"
$Template                                    = Get-AnsibleParam -obj $params -name "Template" -type "str"
$HubUrl                                      = Get-AnsibleParam -obj $params -name "HubUrl" -type "str"
$DisableFlows                                = Get-AnsibleParam -obj $params -name "DisableFlows" -type "bool"
$SharingCapability                           = Get-AnsibleParam -obj $params -name "SharingCapability" -type "str" -validateset "Disabled", "ExistingExternalUserSharingOnly", "ExternalUserSharingOnly", "ExternalUserAndGuestSharing"
$StorageMaximumLevel                         = Get-AnsibleParam -obj $params -name "StorageMaximumLevel" -type "int"
$StorageWarningLevel                         = Get-AnsibleParam -obj $params -name "StorageWarningLevel" -type "int"
$AllowSelfServiceUpgrade                     = Get-AnsibleParam -obj $params -name "AllowSelfServiceUpgrade" -type "boll"
$CommentsOnSitePagesDisabled                 = Get-AnsibleParam -obj $params -name "CommentsOnSitePagesDisabled" -type "boll"
$DefaultLinkPermission                       = Get-AnsibleParam -obj $params -name "DefaultLinkPermission" -type "str" -validateset "None", "View", "Edit"
$DefaultSharingLinkType                      = Get-AnsibleParam -obj $params -name "DefaultSharingLinkType" -type "str" -validateset "None", "AnonymousAccess", "Internal", "Direct"
$DisableAppViews                             = Get-AnsibleParam -obj $params -name "DisableAppViews" -type "str" -validateset "Unknown", "Disabled", "NotDisabled"
$DisableCompanyWideSharingLinks              = Get-AnsibleParam -obj $params -name "DisableCompanyWideSharingLinks" -type "str" -validateset "Unknown", "Disabled", "NotDisabled"
$LocaleId                                    = Get-AnsibleParam -obj $params -name "LocaleId" -type "int"
$DenyAddAndCustomizePages                    = Get-AnsibleParam -obj $params -name "DenyAddAndCustomizePages" -type "bool"
#$RestrictedToRegion                          = Get-AnsibleParam -obj $params -name "RestrictedToRegion" -type "str" -validateset "NoRestriction", "BlockMoveOnly", "BlockFull", "Unknown", ""
$SharingAllowedDomainList                    = Get-AnsibleParam -obj $params -name "SharingAllowedDomainList" -type "str"
$SharingBlockedDomainList                    = Get-AnsibleParam -obj $params -name "SharingBlockedDomainList" -type "str"
#$SharingDomainRestrictionMode                = Get-AnsibleParam -obj $params -name "SharingDomainRestrictionMode" -type "str" -validateset "None", "AllowList", "BlockList"
$ShowPeoplePickerSuggestionsForGuestUsers    = Get-AnsibleParam -obj $params -name "ShowPeoplePickerSuggestionsForGuestUsers" -type "bool"
$AnonymousLinkExpirationInDays               = Get-AnsibleParam -obj $params -name "AnonymousLinkExpirationInDays" -type "int"
$SocialBarOnSitePagesDisabled                = Get-AnsibleParam -obj $params -name "SocialBarOnSitePagesDisabled" -type "bool"
$OverrideTenantAnonymousLinkExpirationPolicy = Get-AnsibleParam -obj $params -name "OverrideTenantAnonymousLinkExpirationPolicy" -type "bool"
$Ensure                                      = Get-AnsibleParam -obj $params -name "Ensure" -type "str" validateset "Present", "Absent"
$ApplicationId                               = Get-AnsibleParam -obj $params -name "ApplicationId" -type "str"
$ApplicationSecret                           = Get-AnsibleParam -obj $params -name "ApplicationSecret" -type "str"
$TenantId                                    = Get-AnsibleParam -obj $params -name "TenantId" -type "str"
$CertificatePassword                         = Get-AnsibleParam -obj $params -name "CertificatePassword" -type "str"
$CertificatePath                             = Get-AnsibleParam -obj $params -name "CertificatePath" -type "str"
$CertificateThumbprint                       = Get-AnsibleParam -obj $params -name "CertificateThumbprint" -type "str"


if(($null -ne $CertificatePassword) -and ("" -ne $CertificatePassword)){
    $CertificatePassword                = New-Object System.Management.Automation.PSCredential -ArgumentList ("none",$(ConvertTo-SecureString $CertificatePassword -AsPlainText -Force))
}else{
    $CertificatePassword = $null
}

$inputData = @{
    admin_username                    = $admin_username
    #admin_password                    = $admin_password

    Url                                         = $Url
    Title                                       = $Title
    Owner                                       = $Owner
    TimeZoneId                                  = $TimeZoneId
    Template                                    = $Template
    HubUrl                                      = $HubUrl
    DisableFlows                                = $DisableFlows
    SharingCapability                           = $SharingCapability
    StorageMaximumLevel                         = $StorageMaximumLevel
    StorageWarningLevel                         = $StorageWarningLevel
    AllowSelfServiceUpgrade                     = $AllowSelfServiceUpgrade
    CommentsOnSitePagesDisabled                 = $CommentsOnSitePagesDisabled
    DefaultLinkPermission                       = $DefaultLinkPermission
    DefaultSharingLinkType                      = $DefaultSharingLinkType
    DisableAppViews                             = $DisableAppViews
    DisableCompanyWideSharingLinks              = $DisableCompanyWideSharingLinks
    LocaleId                                    = $LocaleId
    DenyAddAndCustomizePages                    = $DenyAddAndCustomizePages
    RestrictedToRegion                          = $RestrictedToRegion
    SharingAllowedDomainList                    = $SharingAllowedDomainList
    SharingBlockedDomainList                    = $SharingBlockedDomainList
    SharingDomainRestrictionMode                = $SharingDomainRestrictionMode
    ShowPeoplePickerSuggestionsForGuestUsers    = $ShowPeoplePickerSuggestionsForGuestUsers
    AnonymousLinkExpirationInDays               = $AnonymousLinkExpirationInDays
    SocialBarOnSitePagesDisabled                = $SocialBarOnSitePagesDisabled
    OverrideTenantAnonymousLinkExpirationPolicy = $OverrideTenantAnonymousLinkExpirationPolicy
    Ensure                                      = $Ensure
    ApplicationId                               = $ApplicationId
    ApplicationSecret                           = $ApplicationSecret
    TenantId                                    = $TenantId
    CertificatePassword                         = $CertificatePassword
    CertificatePath                             = $CertificatePath
    CertificateThumbprint                       = $CertificateThumbprint
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
            SPOSite 'data'{
                Credential                                  = $Credential

                Url                                         = $Url
                Title                                       = $Title
                Owner                                       = $Owner
                TimeZoneId                                  = $TimeZoneId
                Template                                    = $Template
                HubUrl                                      = $HubUrl
                DisableFlows                                = $DisableFlows
                SharingCapability                           = $SharingCapability
                StorageMaximumLevel                         = $StorageMaximumLevel
                StorageWarningLevel                         = $StorageWarningLevel
                AllowSelfServiceUpgrade                     = $AllowSelfServiceUpgrade
                CommentsOnSitePagesDisabled                 = $CommentsOnSitePagesDisabled
                DefaultLinkPermission                       = $DefaultLinkPermission
                DefaultSharingLinkType                      = $DefaultSharingLinkType
                DisableAppViews                             = $DisableAppViews
                DisableCompanyWideSharingLinks              = $DisableCompanyWideSharingLinks
                LocaleId                                    = $LocaleId
                DenyAddAndCustomizePages                    = $DenyAddAndCustomizePages
                #RestrictedToRegion                          = $RestrictedToRegion
                SharingAllowedDomainList                    = $SharingAllowedDomainList
                SharingBlockedDomainList                    = $SharingBlockedDomainList
                #SharingDomainRestrictionMode                = $SharingDomainRestrictionMode
                ShowPeoplePickerSuggestionsForGuestUsers    = $ShowPeoplePickerSuggestionsForGuestUsers
                AnonymousLinkExpirationInDays               = $AnonymousLinkExpirationInDays
                SocialBarOnSitePagesDisabled                = $SocialBarOnSitePagesDisabled
                OverrideTenantAnonymousLinkExpirationPolicy = $OverrideTenantAnonymousLinkExpirationPolicy
                Ensure                                      = $Ensure
                ApplicationId                               = $ApplicationId
                ApplicationSecret                           = $ApplicationSecret
                TenantId                                    = $TenantId
                CertificatePassword                         = $CertificatePassword
                CertificatePath                             = $CertificatePath
                CertificateThumbprint                       = $CertificateThumbprint
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
        "Url",
        "Title",
        "Owner",
        "TimeZoneId",
        "Template",
        "HubUrl",
        "DisableFlows",
        "SharingCapability",
        "StorageMaximumLevel",
        "StorageWarningLevel",
        "AllowSelfServiceUpgrade",
        "CommentsOnSitePagesDisabled",
        "DefaultLinkPermission",
        "DefaultSharingLinkType",
        "DisableAppViews",
        "DisableCompanyWideSharingLinks",
        "LocaleId",
        "DenyAddAndCustomizePages",
        "RestrictedToRegion",
        "SharingAllowedDomainList",
        "SharingBlockedDomainList",
        "SharingDomainRestrictionMode",
        "ShowPeoplePickerSuggestionsForGuestUsers",
        "AnonymousLinkExpirationInDays",
        "SocialBarOnSitePagesDisabled",
        "OverrideTenantAnonymousLinkExpirationPolicy",
        "Ensure",
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


    if($newData["Ensure"] -eq "Absent"){
        $result.msg = "This site is revoved or don't exist"
    }else{
        $result.msg = "This site is created or alredy exist"
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
}catch{
    Fail-Json -obj $result -message ( $error[0] | out-string )
}

Exit-Json $result