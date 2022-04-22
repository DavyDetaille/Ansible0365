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
$admin_username                = Get-AnsibleParam -obj $params -name "admin_username" -type "str" -failifempty $true
$admin_password                = Get-AnsibleParam -obj $params -name "admin_password" -type "str" -failifempty $true


$Identity                                   = Get-AnsibleParam -obj $params -name "Identity" -type "str"
$Description                                = Get-AnsibleParam -obj $params -name "Description" -type "str"
$AllowChannelMeetingScheduling              = Get-AnsibleParam -obj $params -name "AllowChannelMeetingScheduling" -type "bool"
$AllowMeetNow                               = Get-AnsibleParam -obj $params -name "AllowMeetNow" -type "bool"
$AllowPrivateMeetNow                        = Get-AnsibleParam -obj $params -name "AllowPrivateMeetNow" -type "bool"
$MeetingChatEnabledType                     = Get-AnsibleParam -obj $params -name "MeetingChatEnabledType" -type "str" -validateset "Disabled", "Enabled"
$LiveCaptionsEnabledType                    = Get-AnsibleParam -obj $params -name "LiveCaptionsEnabledType" -type "str" -validateset "Disabled", "DisabledUserOverride"
$AllowIPAudio                               = Get-AnsibleParam -obj $params -name "AllowIPAudio" -type "bool"
$AllowIPVideo                               = Get-AnsibleParam -obj $params -name "AllowIPVideo" -type "bool"
$AllowEngagementReport                      = Get-AnsibleParam -obj $params -name "AllowEngagementReport" -type "str" -validateset "Enabled", "Disabled"
$IPAudioMode                                = Get-AnsibleParam -obj $params -name "IPAudioMode" -type "str" -validateset "EnabledOutgoingIncoming", "Disabled"
$IPVideoMode                                = Get-AnsibleParam -obj $params -name "IPVideoMode" -type "str" -validateset "EnabledOutgoingIncoming", "Disabled"
$AllowAnonymousUsersToDialOut               = Get-AnsibleParam -obj $params -name "AllowAnonymousUsersToDialOut" -type "bool"
$AllowAnonymousUsersToStartMeeting          = Get-AnsibleParam -obj $params -name "AllowAnonymousUsersToStartMeeting" -type "bool"
$AllowPrivateMeetingScheduling              = Get-AnsibleParam -obj $params -name "AllowPrivateMeetingScheduling" -type "bool"
$AutoAdmittedUsers                          = Get-AnsibleParam -obj $params -name "AutoAdmittedUsers" -type "str" -validateset "EveryoneInCompany", "Everyone", "EveryoneInSameAndFederatedCompany", "OrganizerOnly", "InvitedUsers", "EveryoneInCompanyExcludingGuests"
$AllowPSTNUsersToBypassLobby                = Get-AnsibleParam -obj $params -name "AllowPSTNUsersToBypassLobby" -type "bool"
$AllowCloudRecording                        = Get-AnsibleParam -obj $params -name "AllowCloudRecording" -type "bool"
$AllowRecordingStorageOutsideRegion         = Get-AnsibleParam -obj $params -name "AllowRecordingStorageOutsideRegion" -type "bool"
$DesignatedPresenterRoleMode                = Get-AnsibleParam -obj $params -name "DesignatedPresenterRoleMode" -type "str" -validateset "OrganizerOnlyUserOverride", "EveryoneInCompanyUserOverride", "EveryoneUserOverride"
$RecordingStorageMode                       = Get-AnsibleParam -obj $params -name "RecordingStorageMode" -type "str" -validateset "Stream", "OneDriveForBusiness"
$AllowOutlookAddIn                          = Get-AnsibleParam -obj $params -name "AllowOutlookAddIn" -type "bool"
$AllowPowerPointSharing                     = Get-AnsibleParam -obj $params -name "AllowPowerPointSharing" -type "bool"
$AllowParticipantGiveRequestControl         = Get-AnsibleParam -obj $params -name "AllowParticipantGiveRequestControl" -type "bool"
$AllowExternalParticipantGiveRequestControl = Get-AnsibleParam -obj $params -name "AllowExternalParticipantGiveRequestControl" -type "bool"
$AllowSharedNotes                           = Get-AnsibleParam -obj $params -name "AllowSharedNotes" -type "bool"
$AllowWhiteboard                            = Get-AnsibleParam -obj $params -name "AllowWhiteboard" -type "bool"
$AllowTranscription                         = Get-AnsibleParam -obj $params -name "AllowTranscription" -type "bool"
$MediaBitRateKb                             = Get-AnsibleParam -obj $params -name "MediaBitRateKb" -type "int"
$ScreenSharingMode                          = Get-AnsibleParam -obj $params -name "ScreenSharingMode" -type "str" -validateset "SingleApplication", "EntireScreen", "Disabled"
$VideoFiltersMode                           = Get-AnsibleParam -obj $params -name "VideoFiltersMode" -type "str" -AllowIPAudio "NoFilters", "BlurOnly", "BlurAndDefaultBackgrounds", "AllFilters"
$AllowOrganizersToOverrideLobbySettings     = Get-AnsibleParam -obj $params -name "AllowOrganizersToOverrideLobbySettings" -type "bool"
$PreferredMeetingProviderForIslandsMode     = Get-AnsibleParam -obj $params -name "PreferredMeetingProviderForIslandsMode" -type "str" -validateset "TeamsAndSfb", "Teams"
$AllowNDIStreaming                          = Get-AnsibleParam -obj $params -name "AllowNDIStreaming" -type "bool"
$AllowUserToJoinExternalMeeting             = Get-AnsibleParam -obj $params -name "AllowUserToJoinExternalMeeting" -type "str" -validateset "Enabled", "FederatedOnly", "Disabled"
$EnrollUserOverride                         = Get-AnsibleParam -obj $params -name "EnrollUserOverride" -type "str" -validateset "Disabled", "Enabled"
$RoomAttributeUserOverride                  = Get-AnsibleParam -obj $params -name "RoomAttributeUserOverride" -type "str" -validateset "Off", "Distinguish", "Attribute"
$StreamingAttendeeMode                      = Get-AnsibleParam -obj $params -name "StreamingAttendeeMode" -type "str" -validateset "Disabled", "Enabled"
$AllowBreakoutRooms                         = Get-AnsibleParam -obj $params -name "AllowBreakoutRooms" -type "bool"
$TeamsCameraFarEndPTZMode                   = Get-AnsibleParam -obj $params -name "TeamsCameraFarEndPTZMode" -type "str" -validateset "Disabled", "Enabled"
$AllowMeetingReactions                      = Get-AnsibleParam -obj $params -name "AllowMeetingReactions" -type "bool" 
$WhoCanRegister                             = Get-AnsibleParam -obj $params -name "WhoCanRegister" -type "str" -validateset "Everyone", "EveryoneInCompany"
$Ensure                                     = Get-AnsibleParam -obj $params -name "Ensure" -type "str" -validateset "Present", "Absent"


if(($null -ne $CertificatePassword) -and ("" -ne $CertificatePassword)){
    $CertificatePassword                = New-Object System.Management.Automation.PSCredential -ArgumentList ("none",$(ConvertTo-SecureString $CertificatePassword -AsPlainText -Force))
}else{
    $CertificatePassword = $null
}

$inputData = @{
    admin_username                    = $admin_username
    #admin_password                    = $admin_password
    
    Identity                                   = $Identity
    Description                                = $Description
    AllowChannelMeetingScheduling              = $AllowChannelMeetingScheduling
    AllowMeetNow                               = $AllowMeetNow
    AllowPrivateMeetNow                        = $AllowPrivateMeetNow
    MeetingChatEnabledType                     = $MeetingChatEnabledType
    LiveCaptionsEnabledType                    = $LiveCaptionsEnabledType
    AllowIPAudio                               = $AllowIPAudio
    AllowIPVideo                               = $AllowIPVideo
    AllowEngagementReport                      = $AllowEngagementReport
    IPAudioMode                                = $IPAudioMode
    IPVideoMode                                = $IPVideoMode
    AllowAnonymousUsersToDialOut               = $AllowAnonymousUsersToDialOut
    AllowAnonymousUsersToStartMeeting          = $AllowAnonymousUsersToStartMeeting
    AllowPrivateMeetingScheduling              = $AllowPrivateMeetingScheduling
    AutoAdmittedUsers                          = $AutoAdmittedUsers
    AllowPSTNUsersToBypassLobby                = $AllowPSTNUsersToBypassLobby
    AllowCloudRecording                        = $AllowCloudRecording
    AllowRecordingStorageOutsideRegion         = $AllowRecordingStorageOutsideRegion
    DesignatedPresenterRoleMode                = $DesignatedPresenterRoleMode
    RecordingStorageMode                       = $RecordingStorageMode
    AllowOutlookAddIn                          = $AllowOutlookAddIn
    AllowPowerPointSharing                     = $AllowPowerPointSharing
    AllowParticipantGiveRequestControl         = $AllowParticipantGiveRequestControl
    AllowExternalParticipantGiveRequestControl = $AllowExternalParticipantGiveRequestControl
    AllowSharedNotes                           = $AllowSharedNotes
    AllowWhiteboard                            = $AllowWhiteboard
    AllowTranscription                         = $AllowTranscription
    MediaBitRateKb                             = $MediaBitRateKb
    ScreenSharingMode                          = $ScreenSharingMode
    VideoFiltersMode                           = $VideoFiltersMode
    AllowOrganizersToOverrideLobbySettings     = $AllowOrganizersToOverrideLobbySettings
    PreferredMeetingProviderForIslandsMode     = $PreferredMeetingProviderForIslandsMode
    AllowNDIStreaming                          = $AllowNDIStreaming
    AllowUserToJoinExternalMeeting             = $AllowUserToJoinExternalMeeting
    EnrollUserOverride                         = $EnrollUserOverride
    RoomAttributeUserOverride                  = $RoomAttributeUserOverride
    StreamingAttendeeMode                      = $StreamingAttendeeMode
    AllowBreakoutRooms                         = $AllowBreakoutRooms
    TeamsCameraFarEndPTZMode                   = $TeamsCameraFarEndPTZMode
    AllowMeetingReactions                      = $AllowMeetingReactions
    WhoCanRegister                             = $WhoCanRegister
    Ensure                                     = $Ensure
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

        if($null -eq $RoomAttributeUserOverride){
            Node localhost{
                TeamsMeetingPolicy "data"{
                    Credential                                 = $Credscredential

                    Identity                                   = $Identity
                    Description                                = $Description
                    AllowChannelMeetingScheduling              = $AllowChannelMeetingScheduling
                    AllowMeetNow                               = $AllowMeetNow
                    AllowPrivateMeetNow                        = $AllowPrivateMeetNow
                    MeetingChatEnabledType                     = $MeetingChatEnabledType
                    LiveCaptionsEnabledType                    = $LiveCaptionsEnabledType
                    AllowIPAudio                               = $AllowIPAudio
                    AllowIPVideo                               = $AllowIPVideo
                    AllowEngagementReport                      = $AllowEngagementReport
                    IPAudioMode                                = $IPAudioMode
                    IPVideoMode                                = $IPVideoMode
                    AllowAnonymousUsersToDialOut               = $AllowAnonymousUsersToDialOut
                    AllowAnonymousUsersToStartMeeting          = $AllowAnonymousUsersToStartMeeting
                    AllowPrivateMeetingScheduling              = $AllowPrivateMeetingScheduling
                    AutoAdmittedUsers                          = $AutoAdmittedUsers
                    AllowPSTNUsersToBypassLobby                = $AllowPSTNUsersToBypassLobby
                    AllowCloudRecording                        = $AllowCloudRecording
                    AllowRecordingStorageOutsideRegion         = $AllowRecordingStorageOutsideRegion
                    DesignatedPresenterRoleMode                = $DesignatedPresenterRoleMode
                    RecordingStorageMode                       = $RecordingStorageMode
                    AllowOutlookAddIn                          = $AllowOutlookAddIn
                    AllowPowerPointSharing                     = $AllowPowerPointSharing
                    AllowParticipantGiveRequestControl         = $AllowParticipantGiveRequestControl
                    AllowExternalParticipantGiveRequestControl = $AllowExternalParticipantGiveRequestControl
                    AllowSharedNotes                           = $AllowSharedNotes
                    AllowWhiteboard                            = $AllowWhiteboard
                    AllowTranscription                         = $AllowTranscription
                    MediaBitRateKb                             = $MediaBitRateKb
                    ScreenSharingMode                          = $ScreenSharingMode
                    VideoFiltersMode                           = $VideoFiltersMode
                    AllowOrganizersToOverrideLobbySettings     = $AllowOrganizersToOverrideLobbySettings
                    PreferredMeetingProviderForIslandsMode     = $PreferredMeetingProviderForIslandsMode
                    AllowNDIStreaming                          = $AllowNDIStreaming
                    AllowUserToJoinExternalMeeting             = $AllowUserToJoinExternalMeeting
                    EnrollUserOverride                         = $EnrollUserOverride
                    #RoomAttributeUserOverride                  = $RoomAttributeUserOverride
                    StreamingAttendeeMode                      = $StreamingAttendeeMode
                    AllowBreakoutRooms                         = $AllowBreakoutRooms
                    TeamsCameraFarEndPTZMode                   = $TeamsCameraFarEndPTZMode
                    AllowMeetingReactions                      = $AllowMeetingReactions
                    WhoCanRegister                             = $WhoCanRegister
                    Ensure                                     = $Ensure
                }
            }
        }else{
            Node localhost{
                TeamsMeetingPolicy "data"{
                    Credential                                 = $Credscredential

                    Identity                                   = $Identity
                    Description                                = $Description
                    AllowChannelMeetingScheduling              = $AllowChannelMeetingScheduling
                    AllowMeetNow                               = $AllowMeetNow
                    AllowPrivateMeetNow                        = $AllowPrivateMeetNow
                    MeetingChatEnabledType                     = $MeetingChatEnabledType
                    LiveCaptionsEnabledType                    = $LiveCaptionsEnabledType
                    AllowIPAudio                               = $AllowIPAudio
                    AllowIPVideo                               = $AllowIPVideo
                    AllowEngagementReport                      = $AllowEngagementReport
                    IPAudioMode                                = $IPAudioMode
                    IPVideoMode                                = $IPVideoMode
                    AllowAnonymousUsersToDialOut               = $AllowAnonymousUsersToDialOut
                    AllowAnonymousUsersToStartMeeting          = $AllowAnonymousUsersToStartMeeting
                    AllowPrivateMeetingScheduling              = $AllowPrivateMeetingScheduling
                    AutoAdmittedUsers                          = $AutoAdmittedUsers
                    AllowPSTNUsersToBypassLobby                = $AllowPSTNUsersToBypassLobby
                    AllowCloudRecording                        = $AllowCloudRecording
                    AllowRecordingStorageOutsideRegion         = $AllowRecordingStorageOutsideRegion
                    DesignatedPresenterRoleMode                = $DesignatedPresenterRoleMode
                    RecordingStorageMode                       = $RecordingStorageMode
                    AllowOutlookAddIn                          = $AllowOutlookAddIn
                    AllowPowerPointSharing                     = $AllowPowerPointSharing
                    AllowParticipantGiveRequestControl         = $AllowParticipantGiveRequestControl
                    AllowExternalParticipantGiveRequestControl = $AllowExternalParticipantGiveRequestControl
                    AllowSharedNotes                           = $AllowSharedNotes
                    AllowWhiteboard                            = $AllowWhiteboard
                    AllowTranscription                         = $AllowTranscription
                    MediaBitRateKb                             = $MediaBitRateKb
                    ScreenSharingMode                          = $ScreenSharingMode
                    VideoFiltersMode                           = $VideoFiltersMode
                    AllowOrganizersToOverrideLobbySettings     = $AllowOrganizersToOverrideLobbySettings
                    PreferredMeetingProviderForIslandsMode     = $PreferredMeetingProviderForIslandsMode
                    AllowNDIStreaming                          = $AllowNDIStreaming
                    AllowUserToJoinExternalMeeting             = $AllowUserToJoinExternalMeeting
                    EnrollUserOverride                         = $EnrollUserOverride
                    RoomAttributeUserOverride                  = $RoomAttributeUserOverride
                    StreamingAttendeeMode                      = $StreamingAttendeeMode
                    AllowBreakoutRooms                         = $AllowBreakoutRooms
                    TeamsCameraFarEndPTZMode                   = $TeamsCameraFarEndPTZMode
                    AllowMeetingReactions                      = $AllowMeetingReactions
                    WhoCanRegister                             = $WhoCanRegister
                    Ensure                                     = $Ensure
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
        "Identity",
        "Description",
        "AllowChannelMeetingScheduling",
        "AllowMeetNow",
        "AllowPrivateMeetNow",
        "MeetingChatEnabledType",
        "LiveCaptionsEnabledType",
        "AllowIPAudio",
        "AllowIPVideo",
        "AllowEngagementReport",
        "IPAudioMode",
        "IPVideoMode",
        "AllowAnonymousUsersToDialOut",
        "AllowAnonymousUsersToStartMeeting",
        "AllowPrivateMeetingScheduling",
        "AutoAdmittedUsers",
        "AllowPSTNUsersToBypassLobby",
        "AllowCloudRecording",
        "AllowRecordingStorageOutsideRegion",
        "DesignatedPresenterRoleMode",
        "RecordingStorageMode",
        "AllowOutlookAddIn",
        "AllowPowerPointSharing",
        "AllowParticipantGiveRequestControl",
        "AllowExternalParticipantGiveRequestControl",
        "AllowSharedNotes",
        "AllowWhiteboard",
        "AllowTranscription",
        "MediaBitRateKb",
        "ScreenSharingMode",
        "VideoFiltersMode",
        "AllowOrganizersToOverrideLobbySettings",
        "PreferredMeetingProviderForIslandsMode",
        "AllowNDIStreaming",
        "AllowUserToJoinExternalMeeting",
        "EnrollUserOverride",
        "RoomAttributeUserOverride",
        "StreamingAttendeeMode",
        "AllowBreakoutRooms",
        "TeamsCameraFarEndPTZMode",
        "AllowMeetingReactions",
        "WhoCanRegister",
        "Ensure"
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
        $result.msg = "This teams team is revoved or don't exist"
    }else{
        $result.msg = "This teams team is created or alredy exist"
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