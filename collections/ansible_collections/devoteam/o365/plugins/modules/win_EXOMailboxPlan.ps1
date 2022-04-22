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
$admin_username           = Get-AnsibleParam -obj $params -name "admin_username" -type "str" -failifempty $true
$admin_password           = Get-AnsibleParam -obj $params -name "admin_password" -type "str" -failifempty $true

$Ensure                   = Get-AnsibleParam -obj $params -name "Ensure" -type "str"
$Identity                 = Get-AnsibleParam -obj $params -name "Identity" -type "str"
$IssueWarningQuota        = Get-AnsibleParam -obj $params -name "IssueWarningQuota" -type "str"
$MaxReceiveSize           = Get-AnsibleParam -obj $params -name "MaxReceiveSize" -type "str"
$MaxSendSize              = Get-AnsibleParam -obj $params -name "MaxSendSize" -type "str"
$ProhibitSendQuota        = Get-AnsibleParam -obj $params -name "ProhibitSendQuota" -type "str"
$ProhibitSendReceiveQuota = Get-AnsibleParam -obj $params -name "ProhibitSendReceiveQuota" -type "str"
$RetainDeletedItemsFor    = Get-AnsibleParam -obj $params -name "RetainDeletedItemsFor" -type "str"
$RoleAssignmentPolicy     = Get-AnsibleParam -obj $params -name "RoleAssignmentPolicy" -type "str"
$RetentionPolicy          = Get-AnsibleParam -obj $params -name "RetentionPolicy" -type "str"
$ApplicationId            = Get-AnsibleParam -obj $params -name "ApplicationId" -type "str"
$TenantId                 = Get-AnsibleParam -obj $params -name "TenantId" -type "str"
$CertificateThumbprint    = Get-AnsibleParam -obj $params -name "CertificateThumbprint" -type "str"
$CertificatePassword      = Get-AnsibleParam -obj $params -name "CertificatePassword" -type "str"
$CertificatePath          = Get-AnsibleParam -obj $params -name "CertificatePath" -type "str"


if(($null -ne $CertificatePassword) -and ("" -ne $CertificatePassword)){
    $CertificatePassword                = New-Object System.Management.Automation.PSCredential -ArgumentList ("none",$(ConvertTo-SecureString $CertificatePassword -AsPlainText -Force))
}else{
    $CertificatePassword = $null
}

$inputData = @{
    admin_username                    = $admin_username
    #admin_password                    = $admin_password

    Identity                 = $Identity
    Ensure                   = $Ensure
    IssueWarningQuota        = $IssueWarningQuota
    MaxReceiveSize           = $MaxReceiveSize
    MaxSendSize              = $MaxSendSize
    ProhibitSendQuota        = $ProhibitSendQuota
    ProhibitSendReceiveQuota = $ProhibitSendReceiveQuota
    RetainDeletedItemsFor    = $RetainDeletedItemsFor
    RetentionPolicy          = $RetentionPolicy
    RoleAssignmentPolicy     = $RoleAssignmentPolicy
    ApplicationId            = $ApplicationId
    TenantId                 = $TenantId
    CertificateThumbprint    = $CertificateThumbprint
    CertificatePassword      = $CertificatePassword
    CertificatePath          = $CertificatePath
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

        Node localhost  {
            EXOMailboxPlan "data" {
                Credential               = $Credscredential

                Identity                 = $Identity
                Ensure                   = $Ensure
                IssueWarningQuota        = $IssueWarningQuota
                MaxReceiveSize           = $MaxReceiveSize
                MaxSendSize              = $MaxSendSize
                ProhibitSendQuota        = $ProhibitSendQuota
                ProhibitSendReceiveQuota = $ProhibitSendReceiveQuota
                RetainDeletedItemsFor    = $RetainDeletedItemsFor
                RetentionPolicy          = $RetentionPolicy
                RoleAssignmentPolicy     = $RoleAssignmentPolicy
                ApplicationId            = $ApplicationId
                TenantId                 = $TenantId
                CertificateThumbprint    = $CertificateThumbprint
                CertificatePassword      = $CertificatePassword
                CertificatePath          = $CertificatePath
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
        "RetainDeletedItemsFor",
        "RetentionPolicy",
        "RoleAssignmentPolicy",
        "ApplicationId",
        "TenantId",
        "CertificateThumbprint",
        "CertificatePassword",
        "CertificatePath"
    )

    $keyListSpecial = @(
        "IssueWarningQuota",
        "MaxReceiveSize",
        "MaxSendSize",
        "ProhibitSendQuota",
        "ProhibitSendReceiveQuota"
    )

    $output = @{}

    for($i = 0; $i -lt $keyList.Count; $i++){
        if( ($null -ne $data[1][$keyList[$i]]) -and ("" -ne $data[1][$keyList[$i]]) ){
            if($data[0][$keyList[$i]] -ne $data[1][$keyList[$i]]){
                $output.add($keyList[$i], "Data change : '$($data[0][$keyList[$i]])' -> '$($data[1][$keyList[$i]])'")
            }
        }
    }

    for($i = 0; $i -lt $keyListSpecial.Count; $i++){
        if( ($null -ne $data[1][$keyListSpecial[$i]]) -and ("" -ne $data[1][$keyListSpecial[$i]]) ){
            if ($data[0][$keyListSpecial[$i]].Substring(0,$data[1][$keyListSpecial[$i]].Length) -ne $data[1][$keyListSpecial[$i]] ){
                $output.add($keyListSpecial[$i], "Data change : '$($data[0][$keyListSpecial[$i]])' -> '$($data[1][$keyListSpecial[$i]])'")
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
    #     $result.msg = "This hosted outbound spam filter policy is revoved or don't exist"
    # }else{
    #     $result.msg = "This hosted outbound spam filter policy is created or already exist"
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