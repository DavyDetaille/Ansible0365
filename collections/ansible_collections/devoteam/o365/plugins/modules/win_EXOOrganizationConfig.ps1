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

$ActivityBasedAuthenticationTimeoutEnabled                 = Get-AnsibleParam -obj $params -name "ActivityBasedAuthenticationTimeoutEnabled" -type "bool"
$ActivityBasedAuthenticationTimeoutInterval                = Get-AnsibleParam -obj $params -name "ActivityBasedAuthenticationTimeoutInterval" -type "str"
$ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled = Get-AnsibleParam -obj $params -name "ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled" -type "bool"
$AllowPlusAddressInRecipients                              = Get-AnsibleParam -obj $params -name "AllowPlusAddressInRecipients" -type "bool"
$AppsForOfficeEnabled                                      = Get-AnsibleParam -obj $params -name "AppsForOfficeEnabled" -type "bool"
$AsyncSendEnabled                                          = Get-AnsibleParam -obj $params -name "AsyncSendEnabled" -type "bool"
$AuditDisabled                                             = Get-AnsibleParam -obj $params -name "AuditDisabled" -type "bool"
$AutoExpandingArchive                                      = Get-AnsibleParam -obj $params -name "AutoExpandingArchive" -type "bool"
$BookingsEnabled                                           = Get-AnsibleParam -obj $params -name "BookingsEnabled" -type "bool"
$BookingsPaymentsEnabled                                   = Get-AnsibleParam -obj $params -name "BookingsPaymentsEnabled" -type "bool"
$BookingsSocialSharingRestricted                           = Get-AnsibleParam -obj $params -name "BookingsSocialSharingRestricted" -type "bool"
$ByteEncoderTypeFor7BitCharsets                            = Get-AnsibleParam -obj $params -name "ByteEncoderTypeFor7BitCharsets" -type "int"
$ConnectorsActionableMessagesEnabled                       = Get-AnsibleParam -obj $params -name "ConnectorsActionableMessagesEnabled" -type "bool"
$ConnectorsEnabled                                         = Get-AnsibleParam -obj $params -name "ConnectorsEnabled" -type "bool"
$ConnectorsEnabledForOutlook                               = Get-AnsibleParam -obj $params -name "ConnectorsEnabledForOutlook" -type "bool"
$ConnectorsEnabledForSharepoint                            = Get-AnsibleParam -obj $params -name "ConnectorsEnabledForSharepoint" -type "bool"
$ConnectorsEnabledForTeams                                 = Get-AnsibleParam -obj $params -name "ConnectorsEnabledForTeams" -type "bool"
$ConnectorsEnabledForYammer                                = Get-AnsibleParam -obj $params -name "ConnectorsEnabledForYammer" -type "bool"
$DefaultGroupAccessType                                    = Get-AnsibleParam -obj $params -name "DefaultGroupAccessType" -type "str" -validateset "Private", "Public"
$DefaultPublicFolderDeletedItemRetention                   = Get-AnsibleParam -obj $params -name "DefaultPublicFolderDeletedItemRetention" -type "str"
$DefaultPublicFolderIssueWarningQuota                      = Get-AnsibleParam -obj $params -name "DefaultPublicFolderIssueWarningQuota" -type "str"
$DefaultPublicFolderMaxItemSize                            = Get-AnsibleParam -obj $params -name "DefaultPublicFolderMaxItemSize" -type "str"
$DefaultPublicFolderMovedItemRetention                     = Get-AnsibleParam -obj $params -name "DefaultPublicFolderMovedItemRetention" -type "str"
$DefaultPublicFolderProhibitPostQuota                      = Get-AnsibleParam -obj $params -name "DefaultPublicFolderProhibitPostQuota" -type "str"
$DirectReportsGroupAutoCreationEnabled                     = Get-AnsibleParam -obj $params -name "DirectReportsGroupAutoCreationEnabled" -type "bool"
$DistributionGroupNameBlockedWordsList                     = Get-AnsibleParam -obj $params -name "DistributionGroupNameBlockedWordsList" -type "list"
$DistributionGroupNamingPolicy                             = Get-AnsibleParam -obj $params -name "DistributionGroupNamingPolicy" -type "str"
$ElcProcessingDisabled                                     = Get-AnsibleParam -obj $params -name "ElcProcessingDisabled" -type "bool"
$EndUserDLUpgradeFlowsDisabled                             = Get-AnsibleParam -obj $params -name "EndUserDLUpgradeFlowsDisabled" -type "bool"
$ExchangeNotificationEnabled                               = Get-AnsibleParam -obj $params -name "ExchangeNotificationEnabled" -type "bool"
$ExchangeNotificationRecipients                            = Get-AnsibleParam -obj $params -name "ExchangeNotificationRecipients" -type "list"
$IPListBlocked                                             = Get-AnsibleParam -obj $params -name "IPListBlocked" -type "list"
$IsSingleInstance                                          = Get-AnsibleParam -obj $params -name "IsSingleInstance" -type "str" -validateset "Yes" -failifempty $true
$LeanPopoutEnabled                                         = Get-AnsibleParam -obj $params -name "LeanPopoutEnabled" -type "bool"
$LinkPreviewEnabled                                        = Get-AnsibleParam -obj $params -name "LinkPreviewEnabled" -type "bool"
$MailTipsAllTipsEnabled                                    = Get-AnsibleParam -obj $params -name "MailTipsAllTipsEnabled" -type "bool"
$MailTipsExternalRecipientsTipsEnabled                     = Get-AnsibleParam -obj $params -name "MailTipsExternalRecipientsTipsEnabled" -type "bool"
$MailTipsGroupMetricsEnabled                               = Get-AnsibleParam -obj $params -name "MailTipsGroupMetricsEnabled" -type "bool"
$MailTipsLargeAudienceThreshold                            = Get-AnsibleParam -obj $params -name "MailTipsLargeAudienceThreshold" -type "int"
$MailTipsMailboxSourcedTipsEnabled                         = Get-AnsibleParam -obj $params -name "MailTipsMailboxSourcedTipsEnabled" -type "bool"
$MessageRemindersEnabled                                   = Get-AnsibleParam -obj $params -name "MessageRemindersEnabled" -type "bool"
$MobileAppEducationEnabled                                 = Get-AnsibleParam -obj $params -name "MobileAppEducationEnabled" -type "bool"
$OAuth2ClientProfileEnabled                                = Get-AnsibleParam -obj $params -name "OAuth2ClientProfileEnabled" -type "bool"
$OutlookGifPickerDisabled                                  = Get-AnsibleParam -obj $params -name "OutlookGifPickerDisabled" -type "bool"
$OutlookMobileGCCRestrictionsEnabled                       = Get-AnsibleParam -obj $params -name "OutlookMobileGCCRestrictionsEnabled" -type "bool"
$OutlookPayEnabled                                         = Get-AnsibleParam -obj $params -name "OutlookPayEnabled" -type "bool"
$PublicComputersDetectionEnabled                           = Get-AnsibleParam -obj $params -name "PublicComputersDetectionEnabled" -type "bool"
$PublicFoldersEnabled                                      = Get-AnsibleParam -obj $params -name "PublicFoldersEnabled" -type "str" -validateset "None", "Local", "Remote"
$PublicFolderShowClientControl                             = Get-AnsibleParam -obj $params -name "PublicFolderShowClientControl" -type "bool"
$ReadTrackingEnabled                                       = Get-AnsibleParam -obj $params -name "ReadTrackingEnabled" -type "bool"
$RemotePublicFolderMailboxes                               = Get-AnsibleParam -obj $params -name "RemotePublicFolderMailboxes" -type "list"
$SendFromAliasEnabled                                      = Get-AnsibleParam -obj $params -name "SendFromAliasEnabled" -type "bool"
$SmtpActionableMessagesEnabled                             = Get-AnsibleParam -obj $params -name "SmtpActionableMessagesEnabled" -type "bool"
$VisibleMeetingUpdateProperties                            = Get-AnsibleParam -obj $params -name "VisibleMeetingUpdateProperties" -type "str"
$WebPushNotificationsDisabled                              = Get-AnsibleParam -obj $params -name "WebPushNotificationsDisabled" -type "bool"
$WebSuggestedRepliesDisabled                               = Get-AnsibleParam -obj $params -name "WebSuggestedRepliesDisabled" -type "bool"

$DefaultAuthenticationPolicy                               = Get-AnsibleParam -obj $params -name "DefaultAuthenticationPolicy" -type "str"
$DefaultPublicFolderAgeLimit                               = Get-AnsibleParam -obj $params -name "DefaultPublicFolderAgeLimit" -type "str"
$DistributionGroupDefaultOU                                = Get-AnsibleParam -obj $params -name "DistributionGroupDefaultOU" -type "str"
$EwsAllowEntourage                                         = Get-AnsibleParam -obj $params -name "EwsAllowEntourage" -type "bool"
$EwsAllowList                                              = Get-AnsibleParam -obj $params -name "EwsAllowList" -type "list"
$EwsAllowMacOutlook                                        = Get-AnsibleParam -obj $params -name "EwsAllowMacOutlook" -type "bool"
$EwsAllowOutlook                                           = Get-AnsibleParam -obj $params -name "EwsAllowOutlook" -type "bool"
$EwsApplicationAccessPolicy                                = Get-AnsibleParam -obj $params -name "EwsApplicationAccessPolicy" -type "str" -validateset "EnforceAllowList", "EnforceBlockList", $null -default $null
$EwsBlockList                                              = Get-AnsibleParam -obj $params -name "EwsBlockList" -type "list"
$EwsEnabled                                                = Get-AnsibleParam -obj $params -name "EwsEnabled" -type "bool"
$FocusedInboxOn                                            = Get-AnsibleParam -obj $params -name "FocusedInboxOn" -type "bool"
$HierarchicalAddressBookRoot                               = Get-AnsibleParam -obj $params -name "HierarchicalAddressBookRoot" -type "str"
$OnlineMeetingsByDefaultEnabled                            = Get-AnsibleParam -obj $params -name "OnlineMeetingsByDefaultEnabled" -type "bool"
$SiteMailboxCreationURL                                    = Get-AnsibleParam -obj $params -name "SiteMailboxCreationURL" -type "str"
$ApplicationId                                             = Get-AnsibleParam -obj $params -name "ApplicationId" -type "str"
$TenantId                                                  = Get-AnsibleParam -obj $params -name "TenantId" -type "str"
$CertificateThumbprint                                     = Get-AnsibleParam -obj $params -name "CertificateThumbprint" -type "str"
$CertificatePassword                                       = Get-AnsibleParam -obj $params -name "CertificatePassword" -type "str"
$CertificatePath                                           = Get-AnsibleParam -obj $params -name "CertificatePath" -type "str"

if(($null -ne $EwsAllowList) -and ($null -ne $EwsBlockList)){
    Fail-Json -obj $result -message "Error on `$EwsAllowList and `$EwsBlockList, these two parameters are mutually exclusive"
}

if(($null -ne $CertificatePassword) -and ("" -ne $CertificatePassword)){
    $CertificatePassword                = New-Object System.Management.Automation.PSCredential -ArgumentList ("none",$(ConvertTo-SecureString $CertificatePassword -AsPlainText -Force))
}else{
    $CertificatePassword = $null
}

$inputData = @{
    admin_username                    = $admin_username
    #admin_password                    = $admin_password

    ActivityBasedAuthenticationTimeoutEnabled                 = $ActivityBasedAuthenticationTimeoutEnabled
    ActivityBasedAuthenticationTimeoutInterval                = $ActivityBasedAuthenticationTimeoutInterval
    ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled = $ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled
    AllowPlusAddressInRecipients                              = $AllowPlusAddressInRecipients
    AppsForOfficeEnabled                                      = $AppsForOfficeEnabled
    AsyncSendEnabled                                          = $AsyncSendEnabled
    AuditDisabled                                             = $AuditDisabled
    AutoExpandingArchive                                      = $AutoExpandingArchive
    BookingsEnabled                                           = $BookingsEnabled
    BookingsPaymentsEnabled                                   = $BookingsPaymentsEnabled
    BookingsSocialSharingRestricted                           = $BookingsSocialSharingRestricted
    ByteEncoderTypeFor7BitCharsets                            = $ByteEncoderTypeFor7BitCharsets
    ConnectorsActionableMessagesEnabled                       = $ConnectorsActionableMessagesEnabled
    ConnectorsEnabled                                         = $ConnectorsEnabled
    ConnectorsEnabledForOutlook                               = $ConnectorsEnabledForOutlook
    ConnectorsEnabledForSharepoint                            = $ConnectorsEnabledForSharepoint
    ConnectorsEnabledForTeams                                 = $ConnectorsEnabledForTeams
    ConnectorsEnabledForYammer                                = $ConnectorsEnabledForYammer
    DefaultGroupAccessType                                    = $DefaultGroupAccessType
    DefaultPublicFolderDeletedItemRetention                   = $DefaultPublicFolderDeletedItemRetention
    DefaultPublicFolderIssueWarningQuota                      = $DefaultPublicFolderIssueWarningQuota
    DefaultPublicFolderMaxItemSize                            = $DefaultPublicFolderMaxItemSize
    DefaultPublicFolderMovedItemRetention                     = $DefaultPublicFolderMovedItemRetention
    DefaultPublicFolderProhibitPostQuota                      = $DefaultPublicFolderProhibitPostQuota
    DirectReportsGroupAutoCreationEnabled                     = $DirectReportsGroupAutoCreationEnabled
    DistributionGroupNameBlockedWordsList                     = $DistributionGroupNameBlockedWordsList
    DistributionGroupNamingPolicy                             = $DistributionGroupNamingPolicy
    ElcProcessingDisabled                                     = $ElcProcessingDisabled
    EndUserDLUpgradeFlowsDisabled                             = $EndUserDLUpgradeFlowsDisabled
    ExchangeNotificationEnabled                               = $ExchangeNotificationEnabled
    ExchangeNotificationRecipients                            = $ExchangeNotificationRecipients
    IPListBlocked                                             = $IPListBlocked
    IsSingleInstance                                          = $IsSingleInstance
    LeanPopoutEnabled                                         = $LeanPopoutEnabled
    LinkPreviewEnabled                                        = $LinkPreviewEnabled
    MailTipsAllTipsEnabled                                    = $MailTipsAllTipsEnabled
    MailTipsExternalRecipientsTipsEnabled                     = $MailTipsExternalRecipientsTipsEnabled
    MailTipsGroupMetricsEnabled                               = $MailTipsGroupMetricsEnabled
    MailTipsLargeAudienceThreshold                            = $MailTipsLargeAudienceThreshold
    MailTipsMailboxSourcedTipsEnabled                         = $MailTipsMailboxSourcedTipsEnabled
    MessageRemindersEnabled                                   = $MessageRemindersEnabled
    MobileAppEducationEnabled                                 = $MobileAppEducationEnabled
    OAuth2ClientProfileEnabled                                = $OAuth2ClientProfileEnabled
    OutlookGifPickerDisabled                                  = $OutlookGifPickerDisabled
    OutlookMobileGCCRestrictionsEnabled                       = $OutlookMobileGCCRestrictionsEnabled
    OutlookPayEnabled                                         = $OutlookPayEnabled
    PublicComputersDetectionEnabled                           = $PublicComputersDetectionEnabled
    PublicFoldersEnabled                                      = $PublicFoldersEnabled
    PublicFolderShowClientControl                             = $PublicFolderShowClientControl
    ReadTrackingEnabled                                       = $ReadTrackingEnabled
    RemotePublicFolderMailboxes                               = $RemotePublicFolderMailboxes
    SendFromAliasEnabled                                      = $SendFromAliasEnabled
    SmtpActionableMessagesEnabled                             = $SmtpActionableMessagesEnabled
    VisibleMeetingUpdateProperties                            = $VisibleMeetingUpdateProperties
    WebPushNotificationsDisabled                              = $WebPushNotificationsDisabled
    WebSuggestedRepliesDisabled                               = $WebSuggestedRepliesDisabled

    DefaultAuthenticationPolicy                               = $DefaultAuthenticationPolicy
    DefaultPublicFolderAgeLimit                               = $DefaultPublicFolderAgeLimit
    DistributionGroupDefaultOU                                = $DistributionGroupDefaultOU
    EwsAllowEntourage                                         = $EwsAllowEntourage
    EwsAllowList                                              = $EwsAllowList
    EwsAllowMacOutlook                                        = $EwsAllowMacOutlook
    EwsAllowOutlook                                           = $EwsAllowOutlook
    EwsApplicationAccessPolicy                                = $EwsApplicationAccessPolicy
    EwsBlockList                                              = $EwsBlockList
    EwsEnabled                                                = $EwsEnabled
    FocusedInboxOn                                            = $FocusedInboxOn
    HierarchicalAddressBookRoot                               = $HierarchicalAddressBookRoot
    OnlineMeetingsByDefaultEnabled                            = $OnlineMeetingsByDefaultEnabled
    SiteMailboxCreationURL                                    = $SiteMailboxCreationURL
    ApplicationId                                             = $ApplicationId
    TenantId                                                  = $TenantId
    CertificateThumbprint                                     = $CertificateThumbprint
    CertificatePassword                                       = $CertificatePassword
    CertificatePath                                           = $CertificatePath
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

        if($null -eq $EwsAllowList){
            if($null -eq $EwsApplicationAccessPolicy){
                Node localhost{
                    EXOOrganizationConfig "data"{
                        Credential                                                = $Credscredential;
        
                        ActivityBasedAuthenticationTimeoutEnabled                 = $ActivityBasedAuthenticationTimeoutEnabled
                        ActivityBasedAuthenticationTimeoutInterval                = $ActivityBasedAuthenticationTimeoutInterval
                        ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled = $ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled
                        AllowPlusAddressInRecipients                              = $AllowPlusAddressInRecipients
                        AppsForOfficeEnabled                                      = $AppsForOfficeEnabled
                        AsyncSendEnabled                                          = $AsyncSendEnabled
                        AuditDisabled                                             = $AuditDisabled
                        AutoExpandingArchive                                      = $AutoExpandingArchive
                        BookingsEnabled                                           = $BookingsEnabled
                        BookingsPaymentsEnabled                                   = $BookingsPaymentsEnabled
                        BookingsSocialSharingRestricted                           = $BookingsSocialSharingRestricted
                        ByteEncoderTypeFor7BitCharsets                            = $ByteEncoderTypeFor7BitCharsets
                        ConnectorsActionableMessagesEnabled                       = $ConnectorsActionableMessagesEnabled
                        ConnectorsEnabled                                         = $ConnectorsEnabled
                        ConnectorsEnabledForOutlook                               = $ConnectorsEnabledForOutlook
                        ConnectorsEnabledForSharepoint                            = $ConnectorsEnabledForSharepoint
                        ConnectorsEnabledForTeams                                 = $ConnectorsEnabledForTeams
                        ConnectorsEnabledForYammer                                = $ConnectorsEnabledForYammer
                        DefaultGroupAccessType                                    = $DefaultGroupAccessType
                        DefaultPublicFolderDeletedItemRetention                   = $DefaultPublicFolderDeletedItemRetention
                        DefaultPublicFolderIssueWarningQuota                      = $DefaultPublicFolderIssueWarningQuota
                        DefaultPublicFolderMaxItemSize                            = $DefaultPublicFolderMaxItemSize
                        DefaultPublicFolderMovedItemRetention                     = $DefaultPublicFolderMovedItemRetention
                        DefaultPublicFolderProhibitPostQuota                      = $DefaultPublicFolderProhibitPostQuota
                        DirectReportsGroupAutoCreationEnabled                     = $DirectReportsGroupAutoCreationEnabled
                        DistributionGroupNameBlockedWordsList                     = $DistributionGroupNameBlockedWordsList
                        DistributionGroupNamingPolicy                             = $DistributionGroupNamingPolicy
                        ElcProcessingDisabled                                     = $ElcProcessingDisabled
                        EndUserDLUpgradeFlowsDisabled                             = $EndUserDLUpgradeFlowsDisabled
                        ExchangeNotificationEnabled                               = $ExchangeNotificationEnabled
                        ExchangeNotificationRecipients                            = $ExchangeNotificationRecipients
                        IPListBlocked                                             = $IPListBlocked
                        IsSingleInstance                                          = $IsSingleInstance
                        LeanPopoutEnabled                                         = $LeanPopoutEnabled
                        LinkPreviewEnabled                                        = $LinkPreviewEnabled
                        MailTipsAllTipsEnabled                                    = $MailTipsAllTipsEnabled
                        MailTipsExternalRecipientsTipsEnabled                     = $MailTipsExternalRecipientsTipsEnabled
                        MailTipsGroupMetricsEnabled                               = $MailTipsGroupMetricsEnabled
                        MailTipsLargeAudienceThreshold                            = $MailTipsLargeAudienceThreshold
                        MailTipsMailboxSourcedTipsEnabled                         = $MailTipsMailboxSourcedTipsEnabled
                        MessageRemindersEnabled                                   = $MessageRemindersEnabled
                        MobileAppEducationEnabled                                 = $MobileAppEducationEnabled
                        OAuth2ClientProfileEnabled                                = $OAuth2ClientProfileEnabled
                        OutlookGifPickerDisabled                                  = $OutlookGifPickerDisabled
                        OutlookMobileGCCRestrictionsEnabled                       = $OutlookMobileGCCRestrictionsEnabled
                        OutlookPayEnabled                                         = $OutlookPayEnabled
                        PublicComputersDetectionEnabled                           = $PublicComputersDetectionEnabled
                        PublicFoldersEnabled                                      = $PublicFoldersEnabled
                        PublicFolderShowClientControl                             = $PublicFolderShowClientControl
                        ReadTrackingEnabled                                       = $ReadTrackingEnabled
                        RemotePublicFolderMailboxes                               = $RemotePublicFolderMailboxes
                        SendFromAliasEnabled                                      = $SendFromAliasEnabled
                        SmtpActionableMessagesEnabled                             = $SmtpActionableMessagesEnabled
                        VisibleMeetingUpdateProperties                            = $VisibleMeetingUpdateProperties
                        WebPushNotificationsDisabled                              = $WebPushNotificationsDisabled
                        WebSuggestedRepliesDisabled                               = $WebSuggestedRepliesDisabled
                    
                        DefaultAuthenticationPolicy                               = $DefaultAuthenticationPolicy
                        DefaultPublicFolderAgeLimit                               = $DefaultPublicFolderAgeLimit
                        DistributionGroupDefaultOU                                = $DistributionGroupDefaultOU
                        EwsAllowEntourage                                         = $EwsAllowEntourage
                        #EwsAllowList                                              = $EwsAllowList
                        EwsAllowMacOutlook                                        = $EwsAllowMacOutlook
                        EwsAllowOutlook                                           = $EwsAllowOutlook
                        #EwsApplicationAccessPolicy                                = $EwsApplicationAccessPolicy
                        EwsBlockList                                              = $EwsBlockList
                        EwsEnabled                                                = $EwsEnabled
                        FocusedInboxOn                                            = $FocusedInboxOn
                        HierarchicalAddressBookRoot                               = $HierarchicalAddressBookRoot
                        OnlineMeetingsByDefaultEnabled                            = $OnlineMeetingsByDefaultEnabled
                        SiteMailboxCreationURL                                    = $SiteMailboxCreationURL
                        ApplicationId                                             = $ApplicationId
                        TenantId                                                  = $TenantId
                        CertificateThumbprint                                     = $CertificateThumbprint
                        CertificatePassword                                       = $CertificatePassword
                        CertificatePath                                           = $CertificatePath
                    }
                }
            }else{
                Node localhost{
                    EXOOrganizationConfig "data"{
                        Credential                                                = $Credscredential;
        
                        ActivityBasedAuthenticationTimeoutEnabled                 = $ActivityBasedAuthenticationTimeoutEnabled
                        ActivityBasedAuthenticationTimeoutInterval                = $ActivityBasedAuthenticationTimeoutInterval
                        ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled = $ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled
                        AllowPlusAddressInRecipients                              = $AllowPlusAddressInRecipients
                        AppsForOfficeEnabled                                      = $AppsForOfficeEnabled
                        AsyncSendEnabled                                          = $AsyncSendEnabled
                        AuditDisabled                                             = $AuditDisabled
                        AutoExpandingArchive                                      = $AutoExpandingArchive
                        BookingsEnabled                                           = $BookingsEnabled
                        BookingsPaymentsEnabled                                   = $BookingsPaymentsEnabled
                        BookingsSocialSharingRestricted                           = $BookingsSocialSharingRestricted
                        ByteEncoderTypeFor7BitCharsets                            = $ByteEncoderTypeFor7BitCharsets
                        ConnectorsActionableMessagesEnabled                       = $ConnectorsActionableMessagesEnabled
                        ConnectorsEnabled                                         = $ConnectorsEnabled
                        ConnectorsEnabledForOutlook                               = $ConnectorsEnabledForOutlook
                        ConnectorsEnabledForSharepoint                            = $ConnectorsEnabledForSharepoint
                        ConnectorsEnabledForTeams                                 = $ConnectorsEnabledForTeams
                        ConnectorsEnabledForYammer                                = $ConnectorsEnabledForYammer
                        DefaultGroupAccessType                                    = $DefaultGroupAccessType
                        DefaultPublicFolderDeletedItemRetention                   = $DefaultPublicFolderDeletedItemRetention
                        DefaultPublicFolderIssueWarningQuota                      = $DefaultPublicFolderIssueWarningQuota
                        DefaultPublicFolderMaxItemSize                            = $DefaultPublicFolderMaxItemSize
                        DefaultPublicFolderMovedItemRetention                     = $DefaultPublicFolderMovedItemRetention
                        DefaultPublicFolderProhibitPostQuota                      = $DefaultPublicFolderProhibitPostQuota
                        DirectReportsGroupAutoCreationEnabled                     = $DirectReportsGroupAutoCreationEnabled
                        DistributionGroupNameBlockedWordsList                     = $DistributionGroupNameBlockedWordsList
                        DistributionGroupNamingPolicy                             = $DistributionGroupNamingPolicy
                        ElcProcessingDisabled                                     = $ElcProcessingDisabled
                        EndUserDLUpgradeFlowsDisabled                             = $EndUserDLUpgradeFlowsDisabled
                        ExchangeNotificationEnabled                               = $ExchangeNotificationEnabled
                        ExchangeNotificationRecipients                            = $ExchangeNotificationRecipients
                        IPListBlocked                                             = $IPListBlocked
                        IsSingleInstance                                          = $IsSingleInstance
                        LeanPopoutEnabled                                         = $LeanPopoutEnabled
                        LinkPreviewEnabled                                        = $LinkPreviewEnabled
                        MailTipsAllTipsEnabled                                    = $MailTipsAllTipsEnabled
                        MailTipsExternalRecipientsTipsEnabled                     = $MailTipsExternalRecipientsTipsEnabled
                        MailTipsGroupMetricsEnabled                               = $MailTipsGroupMetricsEnabled
                        MailTipsLargeAudienceThreshold                            = $MailTipsLargeAudienceThreshold
                        MailTipsMailboxSourcedTipsEnabled                         = $MailTipsMailboxSourcedTipsEnabled
                        MessageRemindersEnabled                                   = $MessageRemindersEnabled
                        MobileAppEducationEnabled                                 = $MobileAppEducationEnabled
                        OAuth2ClientProfileEnabled                                = $OAuth2ClientProfileEnabled
                        OutlookGifPickerDisabled                                  = $OutlookGifPickerDisabled
                        OutlookMobileGCCRestrictionsEnabled                       = $OutlookMobileGCCRestrictionsEnabled
                        OutlookPayEnabled                                         = $OutlookPayEnabled
                        PublicComputersDetectionEnabled                           = $PublicComputersDetectionEnabled
                        PublicFoldersEnabled                                      = $PublicFoldersEnabled
                        PublicFolderShowClientControl                             = $PublicFolderShowClientControl
                        ReadTrackingEnabled                                       = $ReadTrackingEnabled
                        RemotePublicFolderMailboxes                               = $RemotePublicFolderMailboxes
                        SendFromAliasEnabled                                      = $SendFromAliasEnabled
                        SmtpActionableMessagesEnabled                             = $SmtpActionableMessagesEnabled
                        VisibleMeetingUpdateProperties                            = $VisibleMeetingUpdateProperties
                        WebPushNotificationsDisabled                              = $WebPushNotificationsDisabled
                        WebSuggestedRepliesDisabled                               = $WebSuggestedRepliesDisabled
                    
                        DefaultAuthenticationPolicy                               = $DefaultAuthenticationPolicy
                        DefaultPublicFolderAgeLimit                               = $DefaultPublicFolderAgeLimit
                        DistributionGroupDefaultOU                                = $DistributionGroupDefaultOU
                        EwsAllowEntourage                                         = $EwsAllowEntourage
                        #EwsAllowList                                              = $EwsAllowList
                        EwsAllowMacOutlook                                        = $EwsAllowMacOutlook
                        EwsAllowOutlook                                           = $EwsAllowOutlook
                        EwsApplicationAccessPolicy                                = $EwsApplicationAccessPolicy
                        EwsBlockList                                              = $EwsBlockList
                        EwsEnabled                                                = $EwsEnabled
                        FocusedInboxOn                                            = $FocusedInboxOn
                        HierarchicalAddressBookRoot                               = $HierarchicalAddressBookRoot
                        OnlineMeetingsByDefaultEnabled                            = $OnlineMeetingsByDefaultEnabled
                        SiteMailboxCreationURL                                    = $SiteMailboxCreationURL
                        ApplicationId                                             = $ApplicationId
                        TenantId                                                  = $TenantId
                        CertificateThumbprint                                     = $CertificateThumbprint
                        CertificatePassword                                       = $CertificatePassword
                        CertificatePath                                           = $CertificatePath
                    }
                }
            }
        }else{
            if($null -eq $EwsApplicationAccessPolicy){
                Node localhost{
                    EXOOrganizationConfig "data"{
                        Credential                                                = $Credscredential;
        
                        ActivityBasedAuthenticationTimeoutEnabled                 = $ActivityBasedAuthenticationTimeoutEnabled
                        ActivityBasedAuthenticationTimeoutInterval                = $ActivityBasedAuthenticationTimeoutInterval
                        ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled = $ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled
                        AllowPlusAddressInRecipients                              = $AllowPlusAddressInRecipients
                        AppsForOfficeEnabled                                      = $AppsForOfficeEnabled
                        AsyncSendEnabled                                          = $AsyncSendEnabled
                        AuditDisabled                                             = $AuditDisabled
                        AutoExpandingArchive                                      = $AutoExpandingArchive
                        BookingsEnabled                                           = $BookingsEnabled
                        BookingsPaymentsEnabled                                   = $BookingsPaymentsEnabled
                        BookingsSocialSharingRestricted                           = $BookingsSocialSharingRestricted
                        ByteEncoderTypeFor7BitCharsets                            = $ByteEncoderTypeFor7BitCharsets
                        ConnectorsActionableMessagesEnabled                       = $ConnectorsActionableMessagesEnabled
                        ConnectorsEnabled                                         = $ConnectorsEnabled
                        ConnectorsEnabledForOutlook                               = $ConnectorsEnabledForOutlook
                        ConnectorsEnabledForSharepoint                            = $ConnectorsEnabledForSharepoint
                        ConnectorsEnabledForTeams                                 = $ConnectorsEnabledForTeams
                        ConnectorsEnabledForYammer                                = $ConnectorsEnabledForYammer
                        DefaultGroupAccessType                                    = $DefaultGroupAccessType
                        DefaultPublicFolderDeletedItemRetention                   = $DefaultPublicFolderDeletedItemRetention
                        DefaultPublicFolderIssueWarningQuota                      = $DefaultPublicFolderIssueWarningQuota
                        DefaultPublicFolderMaxItemSize                            = $DefaultPublicFolderMaxItemSize
                        DefaultPublicFolderMovedItemRetention                     = $DefaultPublicFolderMovedItemRetention
                        DefaultPublicFolderProhibitPostQuota                      = $DefaultPublicFolderProhibitPostQuota
                        DirectReportsGroupAutoCreationEnabled                     = $DirectReportsGroupAutoCreationEnabled
                        DistributionGroupNameBlockedWordsList                     = $DistributionGroupNameBlockedWordsList
                        DistributionGroupNamingPolicy                             = $DistributionGroupNamingPolicy
                        ElcProcessingDisabled                                     = $ElcProcessingDisabled
                        EndUserDLUpgradeFlowsDisabled                             = $EndUserDLUpgradeFlowsDisabled
                        ExchangeNotificationEnabled                               = $ExchangeNotificationEnabled
                        ExchangeNotificationRecipients                            = $ExchangeNotificationRecipients
                        IPListBlocked                                             = $IPListBlocked
                        IsSingleInstance                                          = $IsSingleInstance
                        LeanPopoutEnabled                                         = $LeanPopoutEnabled
                        LinkPreviewEnabled                                        = $LinkPreviewEnabled
                        MailTipsAllTipsEnabled                                    = $MailTipsAllTipsEnabled
                        MailTipsExternalRecipientsTipsEnabled                     = $MailTipsExternalRecipientsTipsEnabled
                        MailTipsGroupMetricsEnabled                               = $MailTipsGroupMetricsEnabled
                        MailTipsLargeAudienceThreshold                            = $MailTipsLargeAudienceThreshold
                        MailTipsMailboxSourcedTipsEnabled                         = $MailTipsMailboxSourcedTipsEnabled
                        MessageRemindersEnabled                                   = $MessageRemindersEnabled
                        MobileAppEducationEnabled                                 = $MobileAppEducationEnabled
                        OAuth2ClientProfileEnabled                                = $OAuth2ClientProfileEnabled
                        OutlookGifPickerDisabled                                  = $OutlookGifPickerDisabled
                        OutlookMobileGCCRestrictionsEnabled                       = $OutlookMobileGCCRestrictionsEnabled
                        OutlookPayEnabled                                         = $OutlookPayEnabled
                        PublicComputersDetectionEnabled                           = $PublicComputersDetectionEnabled
                        PublicFoldersEnabled                                      = $PublicFoldersEnabled
                        PublicFolderShowClientControl                             = $PublicFolderShowClientControl
                        ReadTrackingEnabled                                       = $ReadTrackingEnabled
                        RemotePublicFolderMailboxes                               = $RemotePublicFolderMailboxes
                        SendFromAliasEnabled                                      = $SendFromAliasEnabled
                        SmtpActionableMessagesEnabled                             = $SmtpActionableMessagesEnabled
                        VisibleMeetingUpdateProperties                            = $VisibleMeetingUpdateProperties
                        WebPushNotificationsDisabled                              = $WebPushNotificationsDisabled
                        WebSuggestedRepliesDisabled                               = $WebSuggestedRepliesDisabled
                    
                        DefaultAuthenticationPolicy                               = $DefaultAuthenticationPolicy
                        DefaultPublicFolderAgeLimit                               = $DefaultPublicFolderAgeLimit
                        DistributionGroupDefaultOU                                = $DistributionGroupDefaultOU
                        EwsAllowEntourage                                         = $EwsAllowEntourage
                        EwsAllowList                                              = $EwsAllowList
                        EwsAllowMacOutlook                                        = $EwsAllowMacOutlook
                        EwsAllowOutlook                                           = $EwsAllowOutlook
                        #EwsApplicationAccessPolicy                                = $EwsApplicationAccessPolicy
                        #EwsBlockList                                              = $EwsBlockList
                        EwsEnabled                                                = $EwsEnabled
                        FocusedInboxOn                                            = $FocusedInboxOn
                        HierarchicalAddressBookRoot                               = $HierarchicalAddressBookRoot
                        OnlineMeetingsByDefaultEnabled                            = $OnlineMeetingsByDefaultEnabled
                        SiteMailboxCreationURL                                    = $SiteMailboxCreationURL
                        ApplicationId                                             = $ApplicationId
                        TenantId                                                  = $TenantId
                        CertificateThumbprint                                     = $CertificateThumbprint
                        CertificatePassword                                       = $CertificatePassword
                        CertificatePath                                           = $CertificatePath
                    }
                }
            }else{
                Node localhost{
                    EXOOrganizationConfig "data"{
                        Credential                                                = $Credscredential;
        
                        ActivityBasedAuthenticationTimeoutEnabled                 = $ActivityBasedAuthenticationTimeoutEnabled
                        ActivityBasedAuthenticationTimeoutInterval                = $ActivityBasedAuthenticationTimeoutInterval
                        ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled = $ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled
                        AllowPlusAddressInRecipients                              = $AllowPlusAddressInRecipients
                        AppsForOfficeEnabled                                      = $AppsForOfficeEnabled
                        AsyncSendEnabled                                          = $AsyncSendEnabled
                        AuditDisabled                                             = $AuditDisabled
                        AutoExpandingArchive                                      = $AutoExpandingArchive
                        BookingsEnabled                                           = $BookingsEnabled
                        BookingsPaymentsEnabled                                   = $BookingsPaymentsEnabled
                        BookingsSocialSharingRestricted                           = $BookingsSocialSharingRestricted
                        ByteEncoderTypeFor7BitCharsets                            = $ByteEncoderTypeFor7BitCharsets
                        ConnectorsActionableMessagesEnabled                       = $ConnectorsActionableMessagesEnabled
                        ConnectorsEnabled                                         = $ConnectorsEnabled
                        ConnectorsEnabledForOutlook                               = $ConnectorsEnabledForOutlook
                        ConnectorsEnabledForSharepoint                            = $ConnectorsEnabledForSharepoint
                        ConnectorsEnabledForTeams                                 = $ConnectorsEnabledForTeams
                        ConnectorsEnabledForYammer                                = $ConnectorsEnabledForYammer
                        DefaultGroupAccessType                                    = $DefaultGroupAccessType
                        DefaultPublicFolderDeletedItemRetention                   = $DefaultPublicFolderDeletedItemRetention
                        DefaultPublicFolderIssueWarningQuota                      = $DefaultPublicFolderIssueWarningQuota
                        DefaultPublicFolderMaxItemSize                            = $DefaultPublicFolderMaxItemSize
                        DefaultPublicFolderMovedItemRetention                     = $DefaultPublicFolderMovedItemRetention
                        DefaultPublicFolderProhibitPostQuota                      = $DefaultPublicFolderProhibitPostQuota
                        DirectReportsGroupAutoCreationEnabled                     = $DirectReportsGroupAutoCreationEnabled
                        DistributionGroupNameBlockedWordsList                     = $DistributionGroupNameBlockedWordsList
                        DistributionGroupNamingPolicy                             = $DistributionGroupNamingPolicy
                        ElcProcessingDisabled                                     = $ElcProcessingDisabled
                        EndUserDLUpgradeFlowsDisabled                             = $EndUserDLUpgradeFlowsDisabled
                        ExchangeNotificationEnabled                               = $ExchangeNotificationEnabled
                        ExchangeNotificationRecipients                            = $ExchangeNotificationRecipients
                        IPListBlocked                                             = $IPListBlocked
                        IsSingleInstance                                          = $IsSingleInstance
                        LeanPopoutEnabled                                         = $LeanPopoutEnabled
                        LinkPreviewEnabled                                        = $LinkPreviewEnabled
                        MailTipsAllTipsEnabled                                    = $MailTipsAllTipsEnabled
                        MailTipsExternalRecipientsTipsEnabled                     = $MailTipsExternalRecipientsTipsEnabled
                        MailTipsGroupMetricsEnabled                               = $MailTipsGroupMetricsEnabled
                        MailTipsLargeAudienceThreshold                            = $MailTipsLargeAudienceThreshold
                        MailTipsMailboxSourcedTipsEnabled                         = $MailTipsMailboxSourcedTipsEnabled
                        MessageRemindersEnabled                                   = $MessageRemindersEnabled
                        MobileAppEducationEnabled                                 = $MobileAppEducationEnabled
                        OAuth2ClientProfileEnabled                                = $OAuth2ClientProfileEnabled
                        OutlookGifPickerDisabled                                  = $OutlookGifPickerDisabled
                        OutlookMobileGCCRestrictionsEnabled                       = $OutlookMobileGCCRestrictionsEnabled
                        OutlookPayEnabled                                         = $OutlookPayEnabled
                        PublicComputersDetectionEnabled                           = $PublicComputersDetectionEnabled
                        PublicFoldersEnabled                                      = $PublicFoldersEnabled
                        PublicFolderShowClientControl                             = $PublicFolderShowClientControl
                        ReadTrackingEnabled                                       = $ReadTrackingEnabled
                        RemotePublicFolderMailboxes                               = $RemotePublicFolderMailboxes
                        SendFromAliasEnabled                                      = $SendFromAliasEnabled
                        SmtpActionableMessagesEnabled                             = $SmtpActionableMessagesEnabled
                        VisibleMeetingUpdateProperties                            = $VisibleMeetingUpdateProperties
                        WebPushNotificationsDisabled                              = $WebPushNotificationsDisabled
                        WebSuggestedRepliesDisabled                               = $WebSuggestedRepliesDisabled
                    
                        DefaultAuthenticationPolicy                               = $DefaultAuthenticationPolicy
                        DefaultPublicFolderAgeLimit                               = $DefaultPublicFolderAgeLimit
                        DistributionGroupDefaultOU                                = $DistributionGroupDefaultOU
                        EwsAllowEntourage                                         = $EwsAllowEntourage
                        EwsAllowList                                              = $EwsAllowList
                        EwsAllowMacOutlook                                        = $EwsAllowMacOutlook
                        EwsAllowOutlook                                           = $EwsAllowOutlook
                        EwsApplicationAccessPolicy                                = $EwsApplicationAccessPolicy
                        #EwsBlockList                                              = $EwsBlockList
                        EwsEnabled                                                = $EwsEnabled
                        FocusedInboxOn                                            = $FocusedInboxOn
                        HierarchicalAddressBookRoot                               = $HierarchicalAddressBookRoot
                        OnlineMeetingsByDefaultEnabled                            = $OnlineMeetingsByDefaultEnabled
                        SiteMailboxCreationURL                                    = $SiteMailboxCreationURL
                        ApplicationId                                             = $ApplicationId
                        TenantId                                                  = $TenantId
                        CertificateThumbprint                                     = $CertificateThumbprint
                        CertificatePassword                                       = $CertificatePassword
                        CertificatePath                                           = $CertificatePath
                    }
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
        "ActivityBasedAuthenticationTimeoutEnabled",
        "ActivityBasedAuthenticationTimeoutInterval",
        "ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled",
        "AppsForOfficeEnabled",
        "AllowPlusAddressInRecipients",
        "AsyncSendEnabled",
        "AuditDisabled",
        "AutoExpandingArchive",
        "BookingsEnabled",
        "BookingsPaymentsEnabled",
        "BookingsSocialSharingRestricted",
        "ByteEncoderTypeFor7BitCharsets",
        "ConnectorsActionableMessagesEnabled",
        "ConnectorsEnabled",
        "ConnectorsEnabledForOutlook",
        "ConnectorsEnabledForSharepoint",
        "ConnectorsEnabledForTeams",
        "ConnectorsEnabledForYammer	",
        "DefaultAuthenticationPolicy",
        "DefaultGroupAccessType",
        "DefaultPublicFolderAgeLimit",
        "DefaultPublicFolderDeletedItemRetention",
        "DefaultPublicFolderIssueWarningQuota",
        "DefaultPublicFolderMaxItemSize",
        "DefaultPublicFolderMovedItemRetention",
        "DefaultPublicFolderProhibitPostQuota",
        "DirectReportsGroupAutoCreationEnabled",
        "DistributionGroupDefaultOU",
        "DistributionGroupNameBlockedWordsList",
        "DistributionGroupNamingPolicy",
        "ElcProcessingDisabled",
        "EndUserDLUpgradeFlowsDisabled",
        "EwsAllowEntourage",
        "EwsAllowList",
        "EwsAllowMacOutlook",
        "EwsAllowOutlook",
        "EwsApplicationAccessPolicy",
        "EwsBlockList",
        "EwsEnabled",
        "ExchangeNotificationEnabled",
        "ExchangeNotificationRecipients",
        "FocusedInboxOn",
        "HierarchicalAddressBookRoot",
        "IPListBlocked",
        "LeanPopoutEnabled",
        "LinkPreviewEnabled",
        "MailTipsAllTipsEnabled",
        "MailTipsExternalRecipientsTipsEnabled",
        "MailTipsGroupMetricsEnabled",
        "MailTipsLargeAudienceThreshold",
        "MailTipsMailboxSourcedTipsEnabled",
        "MessageRemindersEnabled",
        "MobileAppEducationEnabled",
        "OAuth2ClientProfileEnabled",
        "OnlineMeetingsByDefaultEnabled",
        "OutlookGifPickerDisabled",
        "OutlookMobileGCCRestrictionsEnabled",
        "OutlookPayEnabled",
        "PublicComputersDetectionEnabled",
        "PublicFoldersEnabled",
        "PublicFolderShowClientControl",
        "ReadTrackingEnabled",
        "RemotePublicFolderMailboxes",
        "SendFromAliasEnabled",
        "SiteMailboxCreationURL",
        "SmtpActionableMessagesEnabled",
        "VisibleMeetingUpdateProperties",
        "WebPushNotificationsDisabled",
        "WebSuggestedRepliesDisabled",
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