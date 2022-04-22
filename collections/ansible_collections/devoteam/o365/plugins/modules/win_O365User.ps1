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
$admin_username        = Get-AnsibleParam -obj $params -name "admin_username" -type "str" -failifempty $true
$admin_password        = Get-AnsibleParam -obj $params -name "admin_password" -type "str" -failifempty $true

$UserPrincipalName     = Get-AnsibleParam -obj $params -name "UserPrincipalName" -type "str"
$DisplayName           = Get-AnsibleParam -obj $params -name "DisplayName" -type "str"
$FirstName             = Get-AnsibleParam -obj $params -name "FirstName" -type "str"
$LastName              = Get-AnsibleParam -obj $params -name "LastName" -type "str"
$UsageLocation         = Get-AnsibleParam -obj $params -name "UsageLocation" -type "str"
$LicenseAssignment     = Get-AnsibleParam -obj $params -name "LicenseAssignment" -type "list"
$Password              = Get-AnsibleParam -obj $params -name "Password" -type "str"
$City                  = Get-AnsibleParam -obj $params -name "City" -type "str"
$Country               = Get-AnsibleParam -obj $params -name "Country" -type "str"
$Department            = Get-AnsibleParam -obj $params -name "Department" -type "str"
$Fax                   = Get-AnsibleParam -obj $params -name "Fax" -type "str"
$MobilePhone           = Get-AnsibleParam -obj $params -name "MobilePhone" -type "str"
$Office                = Get-AnsibleParam -obj $params -name "Office" -type "str"
$PasswordNeverExpires  = Get-AnsibleParam -obj $params -name "PasswordNeverExpires" -type "bool"
$PhoneNumber           = Get-AnsibleParam -obj $params -name "PhoneNumber" -type "str"
$PostalCode            = Get-AnsibleParam -obj $params -name "PostalCode" -type "str"
$PreferredDataLocation = Get-AnsibleParam -obj $params -name "PreferredDataLocation" -type "str"
$PreferredLanguage     = Get-AnsibleParam -obj $params -name "PreferredLanguage" -type "str"
$State                 = Get-AnsibleParam -obj $params -name "State" -type "str"
$StreetAddress         = Get-AnsibleParam -obj $params -name "StreetAddress" -type "str"
$Title                 = Get-AnsibleParam -obj $params -name "Title" -type "str"
$UserType              = Get-AnsibleParam -obj $params -name "UserType" -type "str" -validateset "Guest", "Member", "Other", "Viral" -failifempty $true
$Ensure                = Get-AnsibleParam -obj $params -name "Ensure" -type "str" -validateset "Present", "Absent" -failifempty $true
$ApplicationId         = Get-AnsibleParam -obj $params -name "ApplicationId" -type "str"
$TenantId              = Get-AnsibleParam -obj $params -name "TenantId" -type "str"
$ApplicationSecret     = Get-AnsibleParam -obj $params -name "ApplicationSecret" -type "str"
$CertificateThumbprint = Get-AnsibleParam -obj $params -name "CertificateThumbprint" -type "str"
$IsGlobalAdmin           = Get-AnsibleParam -obj $params -name "GlobalAdmin" -type "bool" -default $False

if(($null -ne $CertificatePassword) -and ("" -ne $CertificatePassword)){
    $CertificatePassword                = New-Object System.Management.Automation.PSCredential -ArgumentList ("none",$(ConvertTo-SecureString $CertificatePassword -AsPlainText -Force))
}else{
    $CertificatePassword = $null
}

$inputData = @{
    admin_username                    = $admin_username
    #admin_password                    = $admin_password
 
    UserPrincipalName     = $UserPrincipalName
    DisplayName           = $DisplayName
    FirstName             = $FirstName
    LastName              = $LastName
    UsageLocation         = $UsageLocation
    LicenseAssignment     = $LicenseAssignment
    Password              = $Password
    City                  = $City
    Country               = $Country
    Department            = $Department
    Fax                   = $Fax
    MobilePhone           = $MobilePhone
    Office                = $Office
    PasswordNeverExpires  = $PasswordNeverExpires
    PhoneNumber           = $PhoneNumber
    PostalCode            = $PostalCode
    PreferredDataLocation = $PreferredDataLocation
    PreferredLanguage     = $PreferredLanguage
    State                 = $State
    StreetAddress         = $StreetAddress
    Title                 = $Title
    UserType              = $UserType
    Ensure                = $Ensure
    ApplicationId         = $ApplicationId
    TenantId              = $TenantId
    ApplicationSecret     = $ApplicationSecret
    CertificateThumbprint = $CertificateThumbprint
    IsGlobalAdmin         = $IsGlobalAdmin
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
            if($Ensure -eq "Absent"){
                O365User "Configure$DisplayName"{
                    Ensure                  = $Ensure
                    DisplayName             = $DisplayName
                    UserPrincipalName       = $UserPrincipalName
                    Credential              = $Credential
                }
            }else{
                O365User "Configure$DisplayName"{
                    Ensure                  = $Ensure
                    UserPrincipalName       = $UserPrincipalName
                    FirstName               = $FirstName
                    LastName                = $LastName
                    DisplayName             = $DisplayName
                    City                    = $City
                    Country                 = $Country
                    Office                  = $Office
                    UsageLocation           = $UsageLocation
                    Credential              = $Credential
                    Password                = $UserCredential
                    ApplicationId           = $ApplicationId
                    ApplicationSecret       = $ApplicationSecret
                    CertificateThumbprint   = $CertificateThumbprint
                    Department              = $Department
                    Fax                     = $Fax
                    LicenseAssignment       = $LicenseAssignment
                    MobilePhone             = $MobilePhone
                    PasswordNeverExpires    = $PasswordNeverExpires
                    PhoneNumber             = $PhoneNumber
                    PostalCode              = $PostalCode
                    PreferredDataLocation   = $PreferredDataLocation
                    PreferredLanguage       = $PreferredLanguage
                    State                   = $State
                    StreetAddress           = $StreetAddress
                    TenantId                = $TenantId
                    Title                   = $Title
                    UserType                = $UserType
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
        "UserPrincipalName",
        "DisplayName",
        "FirstName",
        "LastName",
        "UsageLocation",
        "LicenseAssignment",
        "Password",
        "City",
        "Country",
        "Department",
        "Fax",
        "MobilePhone",
        "Office",
        "PasswordNeverExpires",
        "PhoneNumber",
        "PostalCode",
        "PreferredDataLocation",
        "PreferredLanguage",
        "State",
        "StreetAddress",
        "Title",
        "UserType",
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


    if($newData["Ensure"] -eq "Absent"){
        $result.msg = "This user is revoved or don't exist"
    }else{
        $result.msg = "This user is created or alredy exist"
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

function GlobalAdmin($dispName){
    Start-Sleep -s 30
    if($null -ne $dispName){
        $roleName="Company Administrator"
        $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($admin_username, $(ConvertTo-SecureString "$admin_password" -AsPlainText -Force))
        Connect-MsolService -Credential $Credential
        try{
            Add-MsolRoleMember -RoleMemberEmailAddress $((Get-MsolUser -All | Where-Object DisplayName -eq $dispName).UserPrincipalName) -RoleName $roleName
            $result.changed = $true
        }catch{
            $curentError = $error[0] | out-string
            if($null -ne (Select-String -Pattern "The role member you are trying to add is already a member of this role." -inputObject $curentError)){
                #echo "The role member you are trying to add is already a member of this role."
            }else {
                #( $error[0] | out-string )
                Fail-Json -obj $result -message ( $error[0] | out-string )
            }
        }
    }
}



try{
    M365TenantConfig -ErrorAction Stop
    $output = Start-DscConfiguration M365TenantConfig -Force -wait -verbose 4>&1 -ErrorAction Stop
    Actions(FormatText($output))
    if($IsGlobalAdmin){
        GlobalAdmin($DisplayName)
    }
}catch{
    Fail-Json -obj $result -message ( $error[0] | out-string )
}

Exit-Json $result