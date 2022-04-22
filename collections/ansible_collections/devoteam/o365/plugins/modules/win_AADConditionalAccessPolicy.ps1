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
$admin_username                             = Get-AnsibleParam -obj $params -name "admin_username" -type "str" -failifempty $true
$admin_password                             = Get-AnsibleParam -obj $params -name "admin_password" -type "str" -failifempty $true

$ApplicationEnforcedRestrictionsIsEnabled   = Get-AnsibleParam -obj $params -name "ApplicationEnforcedRestrictionsIsEnabled" -type "bool"
$BuiltInControls                            = Get-AnsibleParam -obj $params -name "BuiltInControls" -type "list" -failifempty $true
$ClientAppTypes                             = Get-AnsibleParam -obj $params -name "ClientAppTypes" -type "list" -failifempty $true
$CloudAppSecurityIsEnabled                  = Get-AnsibleParam -obj $params -name "CloudAppSecurityIsEnabled" -type "bool"
$CloudAppSecurityType                       = Get-AnsibleParam -obj $params -name "CloudAppSecurityType" -type "str"
$DisplayName                                = Get-AnsibleParam -obj $params -name "DisplayName" -type "str" -failifempty $true
$Ensure                                     = Get-AnsibleParam -obj $params -name "Ensure" -type "str" -validateset "Present", "Absent" -failifempty $true
$ExcludeApplications                        = Get-AnsibleParam -obj $params -name "ExcludeApplications" -type "list"
$ExcludeDevices                             = Get-AnsibleParam -obj $params -name "ExcludeDevices" -type "list"
$ExcludeGroups                              = Get-AnsibleParam -obj $params -name "ExcludeGroups" -type "list"
$ExcludeLocations                           = Get-AnsibleParam -obj $params -name "ExcludeLocations" -type "list"
$ExcludePlatforms                           = Get-AnsibleParam -obj $params -name "ExcludePlatforms" -type "list"
$ExcludeRoles                               = Get-AnsibleParam -obj $params -name "ExcludeRoles" -type "list"
$ExcludeUsers                               = Get-AnsibleParam -obj $params -name "ExcludeUsers" -type "list"
$GrantControlOperator                       = Get-AnsibleParam -obj $params -name "GrantControlOperator" -type "str" -validateset "AND", "OR" -failifempty $true
$Id                                         = Get-AnsibleParam -obj $params -name "Id" -type "str"
$IncludeApplications                        = Get-AnsibleParam -obj $params -name "IncludeApplications" -type "list" -failifempty $true
$IncludeDevices                             = Get-AnsibleParam -obj $params -name "IncludeDevices" -type "list"
$IncludeGroups                              = Get-AnsibleParam -obj $params -name "IncludeGroups" -type "list"
$IncludeLocations                           = Get-AnsibleParam -obj $params -name "IncludeLocations" -type "list"
$IncludePlatforms                           = Get-AnsibleParam -obj $params -name "IncludePlatforms" -type "list"
$IncludeRoles                               = Get-AnsibleParam -obj $params -name "IncludeRoles" -type "list"
$IncludeUserActions                         = Get-AnsibleParam -obj $params -name "IncludeUserActions" -type "list"
$IncludeUsers                               = Get-AnsibleParam -obj $params -name "IncludeUsers" -type "list" -failifempty $true
$PersistentBrowserIsEnabled                 = Get-AnsibleParam -obj $params -name "PersistentBrowserIsEnabled" -type "bool"
$PersistentBrowserMode                      = Get-AnsibleParam -obj $params -name "PersistentBrowserMode" -type "str" -validateset "Always", "Never", "" -default ""
$SignInFrequencyIsEnabled                   = Get-AnsibleParam -obj $params -name "SignInFrequencyIsEnabled" -type "bool"
$SignInFrequencyType                        = Get-AnsibleParam -obj $params -name "SignInFrequencyType" -type "str" -validateset "Days", "Hours", "" -default ""
$SignInRiskLevels                           = Get-AnsibleParam -obj $params -name "SignInRiskLevels" -type "list"
$State                                      = Get-AnsibleParam -obj $params -name "State" -type "str" -validateset "disabled", "enabled", "enabledForReportingButNotEnforced" # "enabledForReportingButNotEnforced";
$UserRiskLevels                             = Get-AnsibleParam -obj $params -name "UserRiskLevels" -type "list"

$SignInFrequencyValue                       = Get-AnsibleParam -obj $params -name "SignInFrequencyValue" -type "int"
$TermsOfUse                                 = Get-AnsibleParam -obj $params -name "TermsOfUse" -type "str"
$ApplicationId							    = Get-AnsibleParam -obj $params -name "ApplicationId" -type "str"
$TenantId								    = Get-AnsibleParam -obj $params -name "TenantId" -type "str"
$ApplicationSecret						    = Get-AnsibleParam -obj $params -name "ApplicationSecret" -type "str"
$CertificateThumbprint					    = Get-AnsibleParam -obj $params -name "CertificateThumbprint" -type "str"

$inputData = @{
    admin_username                             = $admin_username
    #admin_password                             = $admin_password

    ApplicationEnforcedRestrictionsIsEnabled   = $ApplicationEnforcedRestrictionsIsEnabled
    BuiltInControls                            = $BuiltInControls
    ClientAppTypes                             = $ClientAppTypes
    CloudAppSecurityIsEnabled                  = $CloudAppSecurityIsEnabled
    CloudAppSecurityType                       = $CloudAppSecurityType
    DisplayName                                = $DisplayName
    Ensure                                     = $Ensure
    ExcludeApplications                        = $ExcludeApplications
    ExcludeDevices                             = $ExcludeDevices
    ExcludeGroups                              = $ExcludeGroups
    ExcludeLocations                           = $ExcludeLocations
    ExcludePlatforms                           = $ExcludePlatforms
    ExcludeRoles                               = $ExcludeRoles
    ExcludeUsers                               = $ExcludeUsers
    GrantControlOperator                       = $GrantControlOperator
    Id                                         = $Id
    IncludeApplications                        = $IncludeApplications
    IncludeDevices                             = $IncludeDevices
    IncludeGroups                              = $IncludeGroups
    IncludeLocations                           = $IncludeLocations
    IncludePlatforms                           = $IncludePlatforms
    IncludeRoles                               = $IncludeRoles
    IncludeUserActions                         = $IncludeUserActions
    IncludeUsers                               = $IncludeUsers
    PersistentBrowserIsEnabled                 = $PersistentBrowserIsEnabled
    PersistentBrowserMode                      = $PersistentBrowserMode
    SignInFrequencyIsEnabled                   = $SignInFrequencyIsEnabled
    SignInFrequencyType                        = $SignInFrequencyType
    SignInRiskLevels                           = $SignInRiskLevels
    State                                      = $State
    UserRiskLevels                             = $UserRiskLevels
}

$result.invocation = @{
    module_args = $inputData
}

function AADConditionalAccessPolicy{
    $admin_password = ConvertTo-SecureString "$admin_password" -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($admin_username,$admin_password)

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

    Configuration AADConditionalAccessPolicy{
        param(
            #[Parameter(Mandatory = $true)]
            [Parameter()]
            [System.Management.Automation.PSCredential]
            $Credential
        )
        $OrganizationName = $Credential.UserName.Split('@')[1]
        Import-DscResource -ModuleName 'Microsoft365DSC'

        Node localhost {
            AADConditionalAccessPolicy 'data'{
                ApplicationEnforcedRestrictionsIsEnabled = $ApplicationEnforcedRestrictionsIsEnabled;
                BuiltInControls                          = $BuiltInControls;
                ClientAppTypes                           = $ClientAppTypes;
                CloudAppSecurityIsEnabled                = $CloudAppSecurityIsEnabled;
                CloudAppSecurityType                     = $CloudAppSecurityType;
                Credential                               = $Credential;
                DisplayName                              = $DisplayName;
                Ensure                                   = $Ensure;
                ExcludeApplications                      = $ExcludeApplications;
                ExcludeDevices                           = $ExcludeDevices;
                ExcludeGroups                            = $ExcludeGroups;
                ExcludeLocations                         = $ExcludeLocations;
                ExcludePlatforms                         = $ExcludePlatforms;
                ExcludeRoles                             = $ExcludeRoles;
                ExcludeUsers                             = $ExcludeUsers;
                GrantControlOperator                     = $GrantControlOperator;
                Id                                       = $Id;
                IncludeApplications                      = $IncludeApplications;
                IncludeDevices                           = $IncludeDevices;
                IncludeGroups                            = $IncludeGroups;
                IncludeLocations                         = $IncludeLocations;
                IncludePlatforms                         = $IncludePlatforms;
                IncludeRoles                             = $IncludeRoles;
                IncludeUserActions                       = $IncludeUserActions;
                IncludeUsers                             = $IncludeUsers;
                PersistentBrowserIsEnabled               = $PersistentBrowserIsEnabled;
                PersistentBrowserMode                    = $PersistentBrowserMode;
                SignInFrequencyIsEnabled                 = $SignInFrequencyIsEnabled;
                SignInFrequencyType                      = $SignInFrequencyType;
                SignInRiskLevels                         = $SignInRiskLevels;
                State                                    = $State;
                UserRiskLevels                           = $UserRiskLevels;

                SignInFrequencyValue					 = $SignInFrequencyValue;
                TermsOfUse                               = $TermsOfUse;
                ApplicationId							 = $ApplicationId;
                TenantId								 = $TenantId;
                ApplicationSecret						 = $ApplicationSecret;
                CertificateThumbprint					 = $CertificateThumbprint;
            }
        }
    }
    $noData = AADConditionalAccessPolicy -ConfigurationData $config -Credential $Credential
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
                    if(" " -eq $temp[1]){
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
                    if(" " -eq $temp[1]){
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
        "CertificateThumbprint",
        "PersistentBrowserIsEnabled",
        "IncludeApplications",
        "IncludeRoles",
        "DisplayName",
        "TenantId",
        "ExcludeUsers",
        "GrantControlOperator",
        "CloudAppSecurityIsEnabled",
        "SignInFrequencyIsEnabled",
        "IncludeGroups",
        "PersistentBrowserMode",
        "Credential",
        "IncludePlatforms",
        "ExcludeGroups",
        "ExcludeLocations",
        "UserRiskLevels",
        "TermsOfUse",
        "BuiltInControls",
        "IncludeUserActions",
        "ApplicationId",
        "Ensure",
        "IncludeDevices",
        "Id",
        "CloudAppSecurityType",
        "SignInRiskLevels",
        "ExcludeRoles",
        "ExcludeDevices",
        "SignInFrequencyType",
        "SignInFrequencyValue",
        "ExcludeApplications",
        "ApplicationSecret",
        "State",
        "ExcludePlatforms",
        "ClientAppTypes",
        "IncludeLocations",
        "IncludeUsers"
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
        $result.msg = "This conditional access is removed or don't exist"
    }else{
        $result.msg = "This conditional access is created or alredy exist"
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
    AADConditionalAccessPolicy -ErrorAction Stop
    $output = Start-DscConfiguration AADConditionalAccessPolicy -Force -wait -verbose 4>&1 -ErrorAction Stop
    Actions(FormatText($output))
}catch{
    Fail-Json -obj $result -message ( $error[0] | out-string )
}

Exit-Json $result