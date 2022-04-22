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
$admin_username                    = Get-AnsibleParam -obj $params -name "admin_username" -type "str" -failifempty $true
$admin_password                    = Get-AnsibleParam -obj $params -name "admin_password" -type "str" -failifempty $true

$ActionForUnknownFileAndMIMETypes                     = Get-AnsibleParam -obj $params -name "ActionForUnknownFileAndMIMETypes" -type "str" -validateset "Allow", "ForceSave", "Block"
$ActiveSyncIntegrationEnabled                         = Get-AnsibleParam -obj $params -name "ActiveSyncIntegrationEnabled" -type "bool"
$AdditionalStorageProvidersAvailable                  = Get-AnsibleParam -obj $params -name "AdditionalStorageProvidersAvailable" -type "bool"
$AllAddressListsEnabled                               = Get-AnsibleParam -obj $params -name "AllAddressListsEnabled" -type "bool"
$AllowCopyContactsToDeviceAddressBook                 = Get-AnsibleParam -obj $params -name "AllowCopyContactsToDeviceAddressBook" -type "bool"
$AllowedFileTypes                                     = Get-AnsibleParam -obj $params -name "AllowedFileTypes" -type "list"
$AllowedMimeTypes                                     = Get-AnsibleParam -obj $params -name "AllowedMimeTypes" -type "list"
$BlockedFileTypes                                     = Get-AnsibleParam -obj $params -name "BlockedFileTypes" -type "list"
$BlockedMimeTypes                                     = Get-AnsibleParam -obj $params -name "BlockedMimeTypes" -type "list"
$ClassicAttachmentsEnabled                            = Get-AnsibleParam -obj $params -name "ClassicAttachmentsEnabled" -type "bool"
$ConditionalAccessPolicy                              = Get-AnsibleParam -obj $params -name "ConditionalAccessPolicy" -type "str" -validateset "Off", "ReadOnly", "ReadOnlyPlusAttachmentsBlocked"
$DefaultTheme                                         = Get-AnsibleParam -obj $params -name "DefaultTheme" -type "str"
$DirectFileAccessOnPrivateComputersEnabled            = Get-AnsibleParam -obj $params -name "DirectFileAccessOnPrivateComputersEnabled" -type "bool"
$DirectFileAccessOnPublicComputersEnabled             = Get-AnsibleParam -obj $params -name "DirectFileAccessOnPublicComputersEnabled" -type "bool"
$DisplayPhotosEnabled                                 = Get-AnsibleParam -obj $params -name "DisplayPhotosEnabled" -type "bool"
$Ensure                                               = Get-AnsibleParam -obj $params -name "Ensure" -type "str" -validateset "Present", "Absent"
$ExplicitLogonEnabled                                 = Get-AnsibleParam -obj $params -name "ExplicitLogonEnabled" -type "bool"
$ExternalImageProxyEnabled                            = Get-AnsibleParam -obj $params -name "ExternalImageProxyEnabled" -type "bool"
$ForceSaveAttachmentFilteringEnabled                  = Get-AnsibleParam -obj $params -name "ForceSaveAttachmentFilteringEnabled" -type "bool"
$ForceSaveFileTypes                                   = Get-AnsibleParam -obj $params -name "ForceSaveFileTypes" -type "list"
$ForceSaveMimeTypes                                   = Get-AnsibleParam -obj $params -name "ForceSaveMimeTypes" -type "list"
$ForceWacViewingFirstOnPrivateComputers               = Get-AnsibleParam -obj $params -name "ForceWacViewingFirstOnPrivateComputers" -type "bool"
$ForceWacViewingFirstOnPublicComputers                = Get-AnsibleParam -obj $params -name "ForceWacViewingFirstOnPublicComputers" -type "bool"
$FreCardsEnabled                                      = Get-AnsibleParam -obj $params -name "FreCardsEnabled" -type "bool"
$GlobalAddressListEnabled                             = Get-AnsibleParam -obj $params -name "GlobalAddressListEnabled" -type "bool"
$GroupCreationEnabled                                 = Get-AnsibleParam -obj $params -name "GroupCreationEnabled" -type "bool"
$InstantMessagingEnabled                              = Get-AnsibleParam -obj $params -name "InstantMessagingEnabled" -type "bool"
$InstantMessagingType                                 = Get-AnsibleParam -obj $params -name "InstantMessagingType" -type "str" -validateset "None", "Ocs"
$InterestingCalendarsEnabled                          = Get-AnsibleParam -obj $params -name "InterestingCalendarsEnabled" -type "bool"
$IRMEnabled                                           = Get-AnsibleParam -obj $params -name "IRMEnabled" -type "bool"
$IsDefault                                            = Get-AnsibleParam -obj $params -name "IsDefault" -type "bool"
$JournalEnabled                                       = Get-AnsibleParam -obj $params -name "JournalEnabled" -type "bool"
$LocalEventsEnabled                                   = Get-AnsibleParam -obj $params -name "LocalEventsEnabled" -type "bool"
$LogonAndErrorLanguage                                = Get-AnsibleParam -obj $params -name "LogonAndErrorLanguage" -type "int"
$Name                                                 = Get-AnsibleParam -obj $params -name "Name" -type "str"
$NotesEnabled                                         = Get-AnsibleParam -obj $params -name "NotesEnabled" -type "bool"
$NpsSurveysEnabled                                    = Get-AnsibleParam -obj $params -name "NpsSurveysEnabled" -type "bool"
$OnSendAddinsEnabled                                  = Get-AnsibleParam -obj $params -name "OnSendAddinsEnabled" -type "bool"
$OrganizationEnabled                                  = Get-AnsibleParam -obj $params -name "OrganizationEnabled" -type "bool"
$OutboundCharset                                      = Get-AnsibleParam -obj $params -name "OutboundCharset" -type "str" -validateset "AutoDetect", "AlwaysUTF8", "UserLanguageChoice"
$OutlookBetaToggleEnabled                             = Get-AnsibleParam -obj $params -name "OutlookBetaToggleEnabled" -type "bool"
$OWALightEnabled                                      = Get-AnsibleParam -obj $params -name "OWALightEnabled" -type "bool"
$PersonalAccountCalendarsEnabled                      = Get-AnsibleParam -obj $params -name "PersonalAccountCalendarsEnabled" -type "bool"
$PhoneticSupportEnabled                               = Get-AnsibleParam -obj $params -name "PhoneticSupportEnabled" -type "bool"
$PlacesEnabled                                        = Get-AnsibleParam -obj $params -name "PlacesEnabled" -type "bool"
$PremiumClientEnabled                                 = Get-AnsibleParam -obj $params -name "PremiumClientEnabled" -type "bool"
$PrintWithoutDownloadEnabled                          = Get-AnsibleParam -obj $params -name "PrintWithoutDownloadEnabled" -type "bool"
$PublicFoldersEnabled                                 = Get-AnsibleParam -obj $params -name "PublicFoldersEnabled" -type "bool"
$RecoverDeletedItemsEnabled                           = Get-AnsibleParam -obj $params -name "RecoverDeletedItemsEnabled" -type "bool"
$ReferenceAttachmentsEnabled                          = Get-AnsibleParam -obj $params -name "ReferenceAttachmentsEnabled" -type "bool"
$RemindersAndNotificationsEnabled                     = Get-AnsibleParam -obj $params -name "RemindersAndNotificationsEnabled" -type "bool"
$ReportJunkEmailEnabled                               = Get-AnsibleParam -obj $params -name "ReportJunkEmailEnabled" -type "bool"
$RulesEnabled                                         = Get-AnsibleParam -obj $params -name "RulesEnabled" -type "bool"
$SatisfactionEnabled                                  = Get-AnsibleParam -obj $params -name "SatisfactionEnabled" -type "bool"
$SaveAttachmentsToCloudEnabled                        = Get-AnsibleParam -obj $params -name "SaveAttachmentsToCloudEnabled" -type "bool"
$SearchFoldersEnabled                                 = Get-AnsibleParam -obj $params -name "SearchFoldersEnabled" -type "bool"
$SetPhotoEnabled                                      = Get-AnsibleParam -obj $params -name "SetPhotoEnabled" -type "bool"
$SetPhotoURL                                          = Get-AnsibleParam -obj $params -name "SetPhotoURL" -type "str"
$SignaturesEnabled                                    = Get-AnsibleParam -obj $params -name "SignaturesEnabled" -type "bool"
$SkipCreateUnifiedGroupCustomSharepointClassification = Get-AnsibleParam -obj $params -name "SkipCreateUnifiedGroupCustomSharepointClassification" -type "bool"
$TeamSnapCalendarsEnabled                             = Get-AnsibleParam -obj $params -name "TeamSnapCalendarsEnabled" -type "bool"
$TextMessagingEnabled                                 = Get-AnsibleParam -obj $params -name "TextMessagingEnabled" -type "bool"
$ThemeSelectionEnabled                                = Get-AnsibleParam -obj $params -name "ThemeSelectionEnabled" -type "bool"
$UMIntegrationEnabled                                 = Get-AnsibleParam -obj $params -name "UMIntegrationEnabled" -type "bool"
$UseGB18030                                           = Get-AnsibleParam -obj $params -name "UseGB18030" -type "bool"
$UseISO885915                                         = Get-AnsibleParam -obj $params -name "UseISO885915" -type "bool"
$UserVoiceEnabled                                     = Get-AnsibleParam -obj $params -name "UserVoiceEnabled" -type "bool"
$WacEditingEnabled                                    = Get-AnsibleParam -obj $params -name "WacEditingEnabled" -type "bool"
$WacExternalServicesEnabled                           = Get-AnsibleParam -obj $params -name "WacExternalServicesEnabled" -type "bool"
$WacOMEXEnabled                                       = Get-AnsibleParam -obj $params -name "WacOMEXEnabled" -type "bool"
$WacViewingOnPrivateComputersEnabled                  = Get-AnsibleParam -obj $params -name "WacViewingOnPrivateComputersEnabled" -type "bool"
$WacViewingOnPublicComputersEnabled                   = Get-AnsibleParam -obj $params -name "WacViewingOnPublicComputersEnabled" -type "bool"
$WeatherEnabled                                       = Get-AnsibleParam -obj $params -name "WeatherEnabled" -type "bool"
$WebPartsFrameOptionsType                             = Get-AnsibleParam -obj $params -name "WebPartsFrameOptionsType" -type "str" -validateset "None", "SameOrigin", "Deny"

$DisableFacebook                                      = Get-AnsibleParam -obj $params -name "DisableFacebook" -type "bool"
$ExternalSPMySiteHostURL                              = Get-AnsibleParam -obj $params -name "ExternalSPMySiteHostURL" -type "str"
$InternalSPMySiteHostURL                              = Get-AnsibleParam -obj $params -name "InternalSPMySiteHostURL" -type "str"
$ApplicationId                                        = Get-AnsibleParam -obj $params -name "ApplicationId" -type "str"
$TenantId                                             = Get-AnsibleParam -obj $params -name "TenantId" -type "str"
$CertificateThumbprint                                = Get-AnsibleParam -obj $params -name "CertificateThumbprint" -type "str"
$CertificatePassword                                  = Get-AnsibleParam -obj $params -name "CertificatePassword" -type "str"
$CertificatePath                                      = Get-AnsibleParam -obj $params -name "CertificatePath" -type "str"


if(($null -ne $CertificatePassword) -and ("" -ne $CertificatePassword)){
    $CertificatePassword                = New-Object System.Management.Automation.PSCredential -ArgumentList ("none",$(ConvertTo-SecureString $CertificatePassword -AsPlainText -Force))
}else{
    $CertificatePassword = $null
}

$inputData = @{
    admin_username                    = $admin_username
    #admin_password                    = $admin_password

    Name                                                 = $Name
    ActionForUnknownFileAndMIMETypes                     = $ActionForUnknownFileAndMIMETypes
    ActiveSyncIntegrationEnabled                         = $ActiveSyncIntegrationEnabled
    AdditionalStorageProvidersAvailable                  = $AdditionalStorageProvidersAvailable
    AllAddressListsEnabled                               = $AllAddressListsEnabled
    AllowCopyContactsToDeviceAddressBook                 = $AllowCopyContactsToDeviceAddressBook
    AllowedFileTypes                                     = $AllowedFileTypes
    AllowedMimeTypes                                     = $AllowedMimeTypes
    BlockedFileTypes                                     = $BlockedFileTypes
    BlockedMimeTypes                                     = $BlockedMimeTypes
    ClassicAttachmentsEnabled                            = $ClassicAttachmentsEnabled
    ConditionalAccessPolicy                              = $ConditionalAccessPolicy
    DefaultTheme                                         = $DefaultTheme
    DirectFileAccessOnPrivateComputersEnabled            = $DirectFileAccessOnPrivateComputersEnabled
    DirectFileAccessOnPublicComputersEnabled             = $DirectFileAccessOnPublicComputersEnabled
    DisableFacebook                                      = $DisableFacebook
    DisplayPhotosEnabled                                 = $DisplayPhotosEnabled
    ExplicitLogonEnabled                                 = $ExplicitLogonEnabled
    ExternalImageProxyEnabled                            = $ExternalImageProxyEnabled
    ExternalSPMySiteHostURL                              = $ExternalSPMySiteHostURL
    ForceSaveAttachmentFilteringEnabled                  = $ForceSaveAttachmentFilteringEnabled
    ForceSaveFileTypes                                   = $ForceSaveFileTypes
    ForceSaveMimeTypes                                   = $ForceSaveMimeTypes
    ForceWacViewingFirstOnPrivateComputers               = $ForceWacViewingFirstOnPrivateComputers
    ForceWacViewingFirstOnPublicComputers                = $ForceWacViewingFirstOnPublicComputers
    FreCardsEnabled                                      = $FreCardsEnabled
    GlobalAddressListEnabled                             = $GlobalAddressListEnabled
    GroupCreationEnabled                                 = $GroupCreationEnabled
    InstantMessagingEnabled                              = $InstantMessagingEnabled
    InstantMessagingType                                 = $InstantMessagingType
    InterestingCalendarsEnabled                          = $InterestingCalendarsEnabled
    InternalSPMySiteHostURL                              = $InternalSPMySiteHostURL
    IRMEnabled                                           = $IRMEnabled
    IsDefault                                            = $IsDefault
    JournalEnabled                                       = $JournalEnabled
    LocalEventsEnabled                                   = $LocalEventsEnabled
    LogonAndErrorLanguage                                = $LogonAndErrorLanguage
    NotesEnabled                                         = $NotesEnabled
    NpsSurveysEnabled                                    = $NpsSurveysEnabled
    OrganizationEnabled                                  = $OrganizationEnabled
    OnSendAddinsEnabled                                  = $OnSendAddinsEnabled
    OutboundCharset                                      = $OutboundCharset
    OutlookBetaToggleEnabled                             = $OutlookBetaToggleEnabled
    OWALightEnabled                                      = $OWALightEnabled
    PersonalAccountCalendarsEnabled                      = $PersonalAccountCalendarsEnabled
    PhoneticSupportEnabled                               = $PhoneticSupportEnabled
    PlacesEnabled                                        = $PlacesEnabled
    PremiumClientEnabled                                 = $PremiumClientEnabled
    PrintWithoutDownloadEnabled                          = $PrintWithoutDownloadEnabled
    PublicFoldersEnabled                                 = $PublicFoldersEnabled
    RecoverDeletedItemsEnabled                           = $RecoverDeletedItemsEnabled
    ReferenceAttachmentsEnabled                          = $ReferenceAttachmentsEnabled
    RemindersAndNotificationsEnabled                     = $RemindersAndNotificationsEnabled
    ReportJunkEmailEnabled                               = $ReportJunkEmailEnabled
    RulesEnabled                                         = $RulesEnabled
    SatisfactionEnabled                                  = $SatisfactionEnabled
    SaveAttachmentsToCloudEnabled                        = $SaveAttachmentsToCloudEnabled
    SearchFoldersEnabled                                 = $SearchFoldersEnabled
    SetPhotoEnabled                                      = $SetPhotoEnabled
    SetPhotoURL                                          = $SetPhotoURL
    SignaturesEnabled                                    = $SignaturesEnabled
    SkipCreateUnifiedGroupCustomSharepointClassification = $SkipCreateUnifiedGroupCustomSharepointClassification
    TeamSnapCalendarsEnabled                             = $TeamSnapCalendarsEnabled
    TextMessagingEnabled                                 = $TextMessagingEnabled
    ThemeSelectionEnabled                                = $ThemeSelectionEnabled
    UMIntegrationEnabled                                 = $UMIntegrationEnabled
    UseGB18030                                           = $UseGB18030
    UseISO885915                                         = $UseISO885915
    UserVoiceEnabled                                     = $UserVoiceEnabled
    WacEditingEnabled                                    = $WacEditingEnabled
    WacExternalServicesEnabled                           = $WacExternalServicesEnabled
    WacOMEXEnabled                                       = $WacOMEXEnabled
    WacViewingOnPrivateComputersEnabled                  = $WacViewingOnPrivateComputersEnabled
    WacViewingOnPublicComputersEnabled                   = $WacViewingOnPublicComputersEnabled
    WeatherEnabled                                       = $WeatherEnabled
    WebPartsFrameOptionsType                             = $WebPartsFrameOptionsType
    Ensure                                               = $Ensure
    ApplicationId                                        = $ApplicationId
    TenantId                                             = $TenantId
    CertificateThumbprint                                = $CertificateThumbprint
    CertificatePassword                                  = $CertificatePassword
    CertificatePath                                      = $CertificatePath
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
            EXOOwaMailboxPolicy "data" {
                Credential                                           = $Credscredential;

                Name                                                 = $Name
                ActionForUnknownFileAndMIMETypes                     = $ActionForUnknownFileAndMIMETypes
                ActiveSyncIntegrationEnabled                         = $ActiveSyncIntegrationEnabled
                AdditionalStorageProvidersAvailable                  = $AdditionalStorageProvidersAvailable
                AllAddressListsEnabled                               = $AllAddressListsEnabled
                AllowCopyContactsToDeviceAddressBook                 = $AllowCopyContactsToDeviceAddressBook
                AllowedFileTypes                                     = $AllowedFileTypes
                AllowedMimeTypes                                     = $AllowedMimeTypes
                BlockedFileTypes                                     = $BlockedFileTypes
                BlockedMimeTypes                                     = $BlockedMimeTypes
                ClassicAttachmentsEnabled                            = $ClassicAttachmentsEnabled
                ConditionalAccessPolicy                              = $ConditionalAccessPolicy
                DefaultTheme                                         = $DefaultTheme
                DirectFileAccessOnPrivateComputersEnabled            = $DirectFileAccessOnPrivateComputersEnabled
                DirectFileAccessOnPublicComputersEnabled             = $DirectFileAccessOnPublicComputersEnabled
                DisableFacebook                                      = $DisableFacebook
                DisplayPhotosEnabled                                 = $DisplayPhotosEnabled
                ExplicitLogonEnabled                                 = $ExplicitLogonEnabled
                ExternalImageProxyEnabled                            = $ExternalImageProxyEnabled
                ExternalSPMySiteHostURL                              = $ExternalSPMySiteHostURL
                ForceSaveAttachmentFilteringEnabled                  = $ForceSaveAttachmentFilteringEnabled
                ForceSaveFileTypes                                   = $ForceSaveFileTypes
                ForceSaveMimeTypes                                   = $ForceSaveMimeTypes
                ForceWacViewingFirstOnPrivateComputers               = $ForceWacViewingFirstOnPrivateComputers
                ForceWacViewingFirstOnPublicComputers                = $ForceWacViewingFirstOnPublicComputers
                FreCardsEnabled                                      = $FreCardsEnabled
                GlobalAddressListEnabled                             = $GlobalAddressListEnabled
                GroupCreationEnabled                                 = $GroupCreationEnabled
                InstantMessagingEnabled                              = $InstantMessagingEnabled
                InstantMessagingType                                 = $InstantMessagingType
                InterestingCalendarsEnabled                          = $InterestingCalendarsEnabled
                InternalSPMySiteHostURL                              = $InternalSPMySiteHostURL
                IRMEnabled                                           = $IRMEnabled
                IsDefault                                            = $IsDefault
                JournalEnabled                                       = $JournalEnabled
                LocalEventsEnabled                                   = $LocalEventsEnabled
                LogonAndErrorLanguage                                = $LogonAndErrorLanguage
                NotesEnabled                                         = $NotesEnabled
                NpsSurveysEnabled                                    = $NpsSurveysEnabled
                OrganizationEnabled                                  = $OrganizationEnabled
                OnSendAddinsEnabled                                  = $OnSendAddinsEnabled
                OutboundCharset                                      = $OutboundCharset
                OutlookBetaToggleEnabled                             = $OutlookBetaToggleEnabled
                OWALightEnabled                                      = $OWALightEnabled
                PersonalAccountCalendarsEnabled                      = $PersonalAccountCalendarsEnabled
                PhoneticSupportEnabled                               = $PhoneticSupportEnabled
                PlacesEnabled                                        = $PlacesEnabled
                PremiumClientEnabled                                 = $PremiumClientEnabled
                PrintWithoutDownloadEnabled                          = $PrintWithoutDownloadEnabled
                PublicFoldersEnabled                                 = $PublicFoldersEnabled
                RecoverDeletedItemsEnabled                           = $RecoverDeletedItemsEnabled
                ReferenceAttachmentsEnabled                          = $ReferenceAttachmentsEnabled
                RemindersAndNotificationsEnabled                     = $RemindersAndNotificationsEnabled
                ReportJunkEmailEnabled                               = $ReportJunkEmailEnabled
                RulesEnabled                                         = $RulesEnabled
                SatisfactionEnabled                                  = $SatisfactionEnabled
                SaveAttachmentsToCloudEnabled                        = $SaveAttachmentsToCloudEnabled
                SearchFoldersEnabled                                 = $SearchFoldersEnabled
                SetPhotoEnabled                                      = $SetPhotoEnabled
                SetPhotoURL                                          = $SetPhotoURL
                SignaturesEnabled                                    = $SignaturesEnabled
                SkipCreateUnifiedGroupCustomSharepointClassification = $SkipCreateUnifiedGroupCustomSharepointClassification
                TeamSnapCalendarsEnabled                             = $TeamSnapCalendarsEnabled
                TextMessagingEnabled                                 = $TextMessagingEnabled
                ThemeSelectionEnabled                                = $ThemeSelectionEnabled
                UMIntegrationEnabled                                 = $UMIntegrationEnabled
                UseGB18030                                           = $UseGB18030
                UseISO885915                                         = $UseISO885915
                UserVoiceEnabled                                     = $UserVoiceEnabled
                WacEditingEnabled                                    = $WacEditingEnabled
                WacExternalServicesEnabled                           = $WacExternalServicesEnabled
                WacOMEXEnabled                                       = $WacOMEXEnabled
                WacViewingOnPrivateComputersEnabled                  = $WacViewingOnPrivateComputersEnabled
                WacViewingOnPublicComputersEnabled                   = $WacViewingOnPublicComputersEnabled
                WeatherEnabled                                       = $WeatherEnabled
                WebPartsFrameOptionsType                             = $WebPartsFrameOptionsType
                Ensure                                               = $Ensure
                ApplicationId                                        = $ApplicationId
                TenantId                                             = $TenantId
                CertificateThumbprint                                = $CertificateThumbprint
                CertificatePassword                                  = $CertificatePassword
                CertificatePath                                      = $CertificatePath
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
        "Name",
        "ActionForUnknownFileAndMIMETypes",
        "ActiveSyncIntegrationEnabled",
        "AdditionalStorageProvidersAvailable",
        "AllAddressListsEnabled",
        "AllowCopyContactsToDeviceAddressBook",
        "AllowedFileTypes",
        "AllowedMimeTypes",
        "BlockedFileTypes",
        "BlockedMimeTypes",
        "ClassicAttachmentsEnabled",
        "ConditionalAccessPolicy",
        "DefaultTheme",
        "DirectFileAccessOnPrivateComputersEnabled",
        "DirectFileAccessOnPublicComputersEnabled",
        "DisplayPhotosEnabled",
        "ExplicitLogonEnabled",
        "ExternalImageProxyEnabled",
        "ExternalSPMySiteHostURL",
        "ForceSaveAttachmentFilteringEnabled",
        "ForceSaveFileTypes",
        "ForceSaveMimeTypes",
        "ForceWacViewingFirstOnPrivateComputers",
        "ForceWacViewingFirstOnPublicComputers",
        "FreCardsEnabled",
        "GlobalAddressListEnabled",
        "GroupCreationEnabled",
        "InstantMessagingEnabled",
        "InstantMessagingType",
        "InterestingCalendarsEnabled",
        "InternalSPMySiteHostURL",
        "IRMEnabled",
        "IsDefault",
        "JournalEnabled",
        "LocalEventsEnabled",
        "LogonAndErrorLanguage",
        "NotesEnabled",
        "NpsSurveysEnabled",
        "OrganizationEnabled",
        "OnSendAddinsEnabled",
        "OutboundCharset",
        "OutlookBetaToggleEnabled",
        "OWALightEnabled",
        "PersonalAccountCalendarsEnabled",
        "PhoneticSupportEnabled",
        "PlacesEnabled",
        "PremiumClientEnabled",
        "PrintWithoutDownloadEnabled",
        "PublicFoldersEnabled",
        "RecoverDeletedItemsEnabled",
        "ReferenceAttachmentsEnabled",
        "RemindersAndNotificationsEnabled",
        "ReportJunkEmailEnabled",
        "RulesEnabled",
        "SatisfactionEnabled",
        "SaveAttachmentsToCloudEnabled",
        "SearchFoldersEnabled",
        "SetPhotoEnabled",
        "SetPhotoURL",
        "SignaturesEnabled",
        "SkipCreateUnifiedGroupCustomSharepointClassification",
        "TeamSnapCalendarsEnabled",
        "TextMessagingEnabled",
        "ThemeSelectionEnabled",
        "UMIntegrationEnabled",
        "UseGB18030",
        "UseISO885915",
        "UserVoiceEnabled",
        "WacEditingEnabled",
        "WacExternalServicesEnabled",
        "WacOMEXEnabled",
        "WacViewingOnPrivateComputersEnabled",
        "WacViewingOnPublicComputersEnabled",
        "WeatherEnabled",
        "WebPartsFrameOptionsType",
        "Ensure",
        "ApplicationId",
        "TenantId",
        "CertificateThumbprint",
        "CertificatePassword",
        "CertificatePath"
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
        $result.msg = "This OWA mailbox policy is revoved or don't exist"
    }else{
        $result.msg = "This OWA mailbox policy filter policy is revoved or don't exist"
    }

    $result.stdout_lines = @{
        oldData = $oldData;
        newData = $newData;
        changes = $changes;
    }

    # if(($oldData.Count -eq 0) -and ($newData["Ensure"] -eq "Present")){
    #     $result.changed = $true
    # }

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