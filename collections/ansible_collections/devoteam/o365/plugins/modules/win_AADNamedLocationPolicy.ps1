# avec la version 1.22.216.1 du module Microsoft365DSC il faut modifier la ligne 277 du fichier : 
# C:\Program Files\WindowsPowerShell\Modules\Microsoft365DSC\1.22.216.1\DSCResources\MSFT_AADNamedLocationPolicy\MSFT_AADNamedLocationPolicy.psm1
# $APIUrl = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
# $APIUrl = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations/$($desiredValues.NamedLocationId)"

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

$OdataType                         = Get-AnsibleParam -obj $params -name "OdataType" -type "str" -failifempty $true -validateset "#microsoft.graph.countryNamedLocation", "#microsoft.graph.ipNamedLocation"
$Id                                = Get-AnsibleParam -obj $params -name "Id" -type "str"
$IncludeUnknownCountriesAndRegions = Get-AnsibleParam -obj $params -name "IncludeUnknownCountriesAndRegions" -type "bool" -failifempty ($OdataType -eq "#microsoft.graph.countryNamedLocation")
$TenantId                          = Get-AnsibleParam -obj $params -name "TenantId" -type "str"
$DisplayName                       = Get-AnsibleParam -obj $params -name "DisplayName" -type "str" -failifempty $true
$CountriesAndRegions               = Get-AnsibleParam -obj $params -name "CountriesAndRegions" -type "list" -failifempty ($OdataType -eq "#microsoft.graph.countryNamedLocation")
$Ensure                            = Get-AnsibleParam -obj $params -name "Ensure" -type "str" -validateset "Present", "Absent" -failifempty $true
$CertificateThumbprint             = Get-AnsibleParam -obj $params -name "CertificateThumbprint" -type "str"
$IsTrusted                         = Get-AnsibleParam -obj $params -name "IsTrusted" -type "bool" -failifempty ($OdataType -eq "#microsoft.graph.ipNamedLocation")
$ApplicationId                     = Get-AnsibleParam -obj $params -name "ApplicationId" -type "str"
$IpRanges                          = Get-AnsibleParam -obj $params -name "IpRanges" -type "list" -failifempty ($OdataType -eq "#microsoft.graph.ipNamedLocation")
$ApplicationSecret                 = Get-AnsibleParam -obj $params -name "ApplicationSecret" -type "str"


$inputData = @{
    admin_username                             = $admin_username
    #admin_password                             = $admin_password

    Id                                = $Id
    IncludeUnknownCountriesAndRegions = $IncludeUnknownCountriesAndRegions
    TenantId                          = $TenantId
    DisplayName                       = $DisplayName
    CountriesAndRegions               = $CountriesAndRegions
    Ensure                            = $Ensure
    CertificateThumbprint             = $CertificateThumbprint
    IsTrusted                         = $IsTrusted
    ApplicationId                     = $ApplicationId
    IpRanges                          = $IpRanges
    ApplicationSecret                 = $ApplicationSecret
    OdataType                         = $OdataType
}

$result.invocation = @{
    module_args = $inputData
}

function AADNamedLocationPolicy{
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

    Configuration AADNamedLocationPolicy{
        param(
            #[Parameter(Mandatory = $true)]
            [Parameter()]
            [System.Management.Automation.PSCredential]
            $Credential
        )
        $OrganizationName = $Credential.UserName.Split('@')[1]
        Import-DscResource -ModuleName 'Microsoft365DSC'

        switch ($OdataType){
            '#microsoft.graph.countryNamedLocation'{
                Node localhost{
                    AADNamedLocationPolicy 'data'{
                        Id                                = $Id
                        IncludeUnknownCountriesAndRegions = $IncludeUnknownCountriesAndRegions
                        TenantId                          = $TenantId
                        DisplayName                       = $DisplayName
                        CountriesAndRegions               = $CountriesAndRegions
                        Credential                        = $Credential;
                        Ensure                            = $Ensure
                        CertificateThumbprint             = $CertificateThumbprint
                        #IsTrusted                         = $IsTrusted
                        ApplicationId                     = $ApplicationId
                        #IpRanges                          = $IpRanges
                        ApplicationSecret                 = $ApplicationSecret
                        OdataType                         = $OdataType
                    }
                }
            }
            '#microsoft.graph.ipNamedLocation'{
                Node localhost{
                    AADNamedLocationPolicy 'data'{
                        Id                                = $Id
                        #IncludeUnknownCountriesAndRegions = $IncludeUnknownCountriesAndRegions
                        TenantId                          = $TenantId
                        DisplayName                       = $DisplayName
                        #CountriesAndRegions               = $CountriesAndRegions
                        Credential                        = $Credential;
                        Ensure                            = $Ensure
                        CertificateThumbprint             = $CertificateThumbprint
                        IsTrusted                         = $IsTrusted
                        ApplicationId                     = $ApplicationId
                        IpRanges                          = $IpRanges
                        ApplicationSecret                 = $ApplicationSecret
                        OdataType                         = $OdataType
                    }
                }
            }
        }
    }
    $noData = AADNamedLocationPolicy -ConfigurationData $config -Credential $Credential
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
        "Id",
        "IncludeUnknownCountriesAndRegions",
        "TenantId",
        "DisplayName",
        "CountriesAndRegions",
        "Credential",
        "Ensure",
        "CertificateThumbprint",
        "IsTrusted",
        "ApplicationId",
        "IpRanges",
        "ApplicationSecret",
        "OdataType"
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
        $result.msg = "This named location has been removed or didn't exist"
    }else{
        $result.msg = "This named location access has been created or already exist"
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
    AADNamedLocationPolicy -ErrorAction Stop
    $output = Start-DscConfiguration AADNamedLocationPolicy -Force -wait -verbose 4>&1 -ErrorAction Stop
    Actions(FormatText($output))
}catch{
    Fail-Json -obj $result -message ( $error[0] | out-string )
}

Exit-Json $result