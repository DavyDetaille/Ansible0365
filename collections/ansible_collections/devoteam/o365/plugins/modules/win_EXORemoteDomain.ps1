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


$AllowedOOFType                       = Get-AnsibleParam -obj $params -name "AllowedOOFType" -type "str" -validateset "External", "ExternalLegacy", "InternalLegacy", "None"
$AutoForwardEnabled                   = Get-AnsibleParam -obj $params -name "AutoForwardEnabled" -type "bool"
$AutoReplyEnabled                     = Get-AnsibleParam -obj $params -name "AutoReplyEnabled" -type "bool"
$ByteEncoderTypeFor7BitCharsets       = Get-AnsibleParam -obj $params -name "ByteEncoderTypeFor7BitCharsets" -type "str" -validateset "Use7Bit", "UseQP", "UseBase64", "UseQPHtmlDetectTextPlain", "UseBase64HtmlDetectTextPlain", "UseQPHtml7BitTextPlain", "UseBase64Html7BitTextPlain", "Undefined"
$CharacterSet                         = Get-AnsibleParam -obj $params -name "CharacterSet" -type "str"
$ContentType                          = Get-AnsibleParam -obj $params -name "ContentType" -type "str" -validateset "MimeHtmlText", "MimeText", "MimeHtml"
$DeliveryReportEnabled                = Get-AnsibleParam -obj $params -name "DeliveryReportEnabled" -type "bool"
$DisplaySenderName                    = Get-AnsibleParam -obj $params -name "DisplaySenderName" -type "bool"
$DomainName                           = Get-AnsibleParam -obj $params -name "DomainName" -type "str"
$Ensure                               = Get-AnsibleParam -obj $params -name "Ensure" -type "str" -validateset "Present", "Absent"
$Identity                             = Get-AnsibleParam -obj $params -name "Identity" -type "str"
$IsInternal                           = Get-AnsibleParam -obj $params -name "IsInternal" -type "bool"
$LineWrapSize                         = Get-AnsibleParam -obj $params -name "LineWrapSize" -type "str"
$MeetingForwardNotificationEnabled    = Get-AnsibleParam -obj $params -name "MeetingForwardNotificationEnabled" -type "bool"
$Name                                 = Get-AnsibleParam -obj $params -name "Name" -type "str"
$NonMimeCharacterSet                  = Get-AnsibleParam -obj $params -name "NonMimeCharacterSet" -type "str"
$PreferredInternetCodePageForShiftJis = Get-AnsibleParam -obj $params -name "PreferredInternetCodePageForShiftJis" -type "str" -validateset "50220", "50221", "50222", "Undefined"
$TargetDeliveryDomain                 = Get-AnsibleParam -obj $params -name "TargetDeliveryDomain" -type "bool"
$TrustedMailInboundEnabled            = Get-AnsibleParam -obj $params -name "TrustedMailInboundEnabled" -type "bool"
$TrustedMailOutboundEnabled           = Get-AnsibleParam -obj $params -name "TrustedMailOutboundEnabled" -type "bool"
$UseSimpleDisplayName                 = Get-AnsibleParam -obj $params -name "UseSimpleDisplayName" -type "bool"


$RequiredCharsetCoverage             = Get-AnsibleParam -obj $params -name "RequiredCharsetCoverage" -type "int"
$TNEFEnabled                         = Get-AnsibleParam -obj $params -name "TNEFEnabled" -type "bool"
$ApplicationId                       = Get-AnsibleParam -obj $params -name "ApplicationId" -type "str"
$TenantId                            = Get-AnsibleParam -obj $params -name "TenantId" -type "str"
$CertificateThumbprint               = Get-AnsibleParam -obj $params -name "CertificateThumbprint" -type "str"
$CertificatePassword                 = Get-AnsibleParam -obj $params -name "CertificatePassword" -type "str"
$CertificatePath                     = Get-AnsibleParam -obj $params -name "CertificatePath" -type "str"


if(($null -ne $CertificatePassword) -and ("" -ne $CertificatePassword)){
    $CertificatePassword                = New-Object System.Management.Automation.PSCredential -ArgumentList ("none",$(ConvertTo-SecureString $CertificatePassword -AsPlainText -Force))
}else{
    $CertificatePassword = $null
}

$inputData = @{
    admin_username                    = $admin_username
    #admin_password                    = $admin_password

    Identity                              = $Identity
    DomainName                            = $DomainName
    Ensure                                = $Ensure
    AllowedOOFType                        = $AllowedOOFType
    AutoForwardEnabled                    = $AutoForwardEnabled
    AutoReplyEnabled                      = $AutoReplyEnabled
    ByteEncoderTypeFor7BitCharsets        = $ByteEncoderTypeFor7BitCharsets
    CharacterSet                          = $CharacterSet
    ContentType                           = $ContentType
    DeliveryReportEnabled                 = $DeliveryReportEnabled
    DisplaySenderName                     = $DisplaySenderName
    IsInternal                            = $IsInternal
    LineWrapSize                          = $LineWrapSize
    MeetingForwardNotificationEnabled     = $MeetingForwardNotificationEnabled
    Name                                  = $Name
    NonMimeCharacterSet                   = $NonMimeCharacterSet
    PreferredInternetCodePageForShiftJis  = $PreferredInternetCodePageForShiftJis
    RequiredCharsetCoverage               = $RequiredCharsetCoverage
    TargetDeliveryDomain                  = $TargetDeliveryDomain
    TNEFEnabled                           = $TNEFEnabled
    TrustedMailInboundEnabled             = $TrustedMailInboundEnabled
    TrustedMailOutboundEnabled            = $TrustedMailOutboundEnabled
    UseSimpleDisplayName                  = $UseSimpleDisplayName
    ApplicationId                         = $ApplicationId
    TenantId                              = $TenantId
    CertificateThumbprint                 = $CertificateThumbprint
    CertificatePassword                   = $CertificatePassword
    CertificatePath                       = $CertificatePath
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
            EXORemoteDomain "data" {
                Credential                           = $Credscredential;
                
                Identity                              = $Identity
                DomainName                            = $DomainName
                Ensure                                = $Ensure
                AllowedOOFType                        = $AllowedOOFType
                AutoForwardEnabled                    = $AutoForwardEnabled
                AutoReplyEnabled                      = $AutoReplyEnabled
                ByteEncoderTypeFor7BitCharsets        = $ByteEncoderTypeFor7BitCharsets
                CharacterSet                          = $CharacterSet
                ContentType                           = $ContentType
                DeliveryReportEnabled                 = $DeliveryReportEnabled
                DisplaySenderName                     = $DisplaySenderName
                IsInternal                            = $IsInternal
                LineWrapSize                          = $LineWrapSize
                MeetingForwardNotificationEnabled     = $MeetingForwardNotificationEnabled
                Name                                  = $Name
                NonMimeCharacterSet                   = $NonMimeCharacterSet
                PreferredInternetCodePageForShiftJis  = $PreferredInternetCodePageForShiftJis
                RequiredCharsetCoverage               = $RequiredCharsetCoverage
                TargetDeliveryDomain                  = $TargetDeliveryDomain
                TNEFEnabled                           = $TNEFEnabled
                TrustedMailInboundEnabled             = $TrustedMailInboundEnabled
                TrustedMailOutboundEnabled            = $TrustedMailOutboundEnabled
                UseSimpleDisplayName                  = $UseSimpleDisplayName
                ApplicationId                         = $ApplicationId
                TenantId                              = $TenantId
                CertificateThumbprint                 = $CertificateThumbprint
                CertificatePassword                   = $CertificatePassword
                CertificatePath                       = $CertificatePath
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
        "DomainName",
        "Ensure",
        "AllowedOOFType",
        "AutoForwardEnabled",
        "AutoReplyEnabled",
        "ByteEncoderTypeFor7BitCharsets",
        "CharacterSet",
        "ContentType",
        "DeliveryReportEnabled",
        "DisplaySenderName",
        "IsInternal",
        "LineWrapSize",
        "MeetingForwardNotificationEnabled",
        "Name",
        "NonMimeCharacterSet",
        "PreferredInternetCodePageForShiftJis",
        "RequiredCharsetCoverage",
        "TargetDeliveryDomain",
        "TNEFEnabled",
        "TrustedMailInboundEnabled",
        "TrustedMailOutboundEnabled",
        "UseSimpleDisplayName",
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
        $result.msg = "This hosted outbound spam filter policy is revoved or don't exist"
    }else{
        $result.msg = "This hosted outbound spam filter policy is revoved or don't exist"
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