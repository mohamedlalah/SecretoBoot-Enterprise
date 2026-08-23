Set-StrictMode -Version Latest
$localPolicyPath=Join-Path $PSScriptRoot 'policy/windows-level1-allowlist.json'
$script:PolicyPath=if([IO.File]::Exists($localPolicyPath)){[IO.Path]::GetFullPath($localPolicyPath)}else{[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../config/windows-level1-allowlist.json'))}
$script:ProviderVersion='3B-A.1'

function Get-Sb3BAllowlist { [IO.File]::ReadAllText($script:PolicyPath)|ConvertFrom-Json -Depth 30 }

function New-SbLevel1ExecutionManifest {
    [CmdletBinding()]
    param(
        [string[]]$OperationsRequested=@('platform.runtime','platform.environment','windows.os.cim','storage.disks','storage.partitions','storage.volumes'),
        [bool]$FeatureGateState=$false,
        [bool]$ExplicitConsent=$false,
        [ValidateSet('Passed','Failed','NotRun')][string]$PlatformCheck='NotRun'
    )
    $policy=Get-Sb3BAllowlist;$known=@($policy.operations.id);$allowed=@($OperationsRequested|Where-Object{$_ -in $known}|Sort-Object -Unique);$denied=@($OperationsRequested|Where-Object{$_ -notin $known}|Sort-Object -Unique)
    $elevation=[ordered]@{};foreach($id in $allowed){$operation=@($policy.operations|Where-Object id -eq $id)[0];$elevation[$id]=[bool]$operation.requiresElevation}
    return [pscustomobject][ordered]@{
        SchemaVersion='v9level1execution1';SecretoBootVersion='9.0.0-alpha';ProviderVersion=$script:ProviderVersion
        RequestedAccessLevel='HostMetadata';FeatureGateState=$FeatureGateState;ExplicitConsent=$ExplicitConsent;PlatformCheck=$PlatformCheck
        OperationsRequested=@($OperationsRequested);OperationsAllowed=$allowed;OperationsDenied=$denied;RequiresElevation=$elevation
        MountRequired=$false;EFIRequested=$false;BCDRequested=$false;NVRAMRequested=$false;SecureBootRequested=$false;WritesRequested=$false
        ExpectedPrivacyLevel='PerReportHmacRedacted'
    }
}

function Test-SbLevel1ExecutionManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Manifest)
    $diagnostics=[Collections.Generic.List[string]]::new();$expected=@('SchemaVersion','SecretoBootVersion','ProviderVersion','RequestedAccessLevel','FeatureGateState','ExplicitConsent','PlatformCheck','OperationsRequested','OperationsAllowed','OperationsDenied','RequiresElevation','MountRequired','EFIRequested','BCDRequested','NVRAMRequested','SecureBootRequested','WritesRequested','ExpectedPrivacyLevel')
    if(@($Manifest.PSObject.Properties.Name|Where-Object{$_ -notin $expected}).Count){$diagnostics.Add('MANIFEST_UNEXPECTED_FIELD')}
    if($Manifest.SchemaVersion-ne'v9level1execution1'-or$Manifest.ProviderVersion-ne$script:ProviderVersion){$diagnostics.Add('MANIFEST_VERSION_DENIED')}
    if($Manifest.RequestedAccessLevel-ne'HostMetadata'){$diagnostics.Add('MANIFEST_ACCESS_DENIED')}
    if($Manifest.FeatureGateState-ne$true){$diagnostics.Add('MANIFEST_FEATURE_DISABLED')}
    if($Manifest.ExplicitConsent-ne$true){$diagnostics.Add('MANIFEST_CONSENT_MISSING')}
    if($Manifest.PlatformCheck-ne'Passed'){$diagnostics.Add('MANIFEST_PLATFORM_DENIED')}
    foreach($name in @('MountRequired','EFIRequested','BCDRequested','NVRAMRequested','SecureBootRequested','WritesRequested')){if($Manifest.$name-ne$false){$diagnostics.Add("MANIFEST_FORBIDDEN_$($name.ToUpperInvariant())")}}
    $policy=Get-Sb3BAllowlist;$known=@($policy.operations.id);$requested=@($Manifest.OperationsRequested)
    if($requested.Count-gt 6-or@($requested|Sort-Object -Unique).Count-ne$requested.Count){$diagnostics.Add('MANIFEST_OPERATION_SET_INVALID')}
    foreach($id in $requested){$operation=@($policy.operations|Where-Object id -eq $id);if($operation.Count-ne 1){$diagnostics.Add('MANIFEST_OPERATION_DENIED')}elseif($operation[0].requiresMount-or$operation[0].touchesBootConfiguration){$diagnostics.Add('MANIFEST_LEVEL2_DEPENDENCY') }}
    $expectedAllowed=@($requested|Where-Object{$_ -in $known}|Sort-Object -Unique);$declaredAllowed=@($Manifest.OperationsAllowed|Sort-Object -Unique)
    if(($expectedAllowed-join'|')-ne($declaredAllowed-join'|')){$diagnostics.Add('MANIFEST_ALLOWED_SET_MISMATCH')}
    if(@($Manifest.OperationsDenied).Count){$diagnostics.Add('MANIFEST_CONTAINS_DENIALS')}
    return [pscustomobject]@{Allowed=($diagnostics.Count-eq 0);DiagnosticCodes=$diagnostics.ToArray()}
}

function Get-SbLevel1ManifestDigest {
    [CmdletBinding()][OutputType([string])]
    param([Parameter(Mandatory)][object]$Manifest)
    $json=$Manifest|ConvertTo-Json -Depth 20 -Compress;$bytes=[Text.Encoding]::UTF8.GetBytes($json);$algorithm=[Security.Cryptography.SHA256]::Create();try{$hash=$algorithm.ComputeHash($bytes)}finally{$algorithm.Dispose()};return [BitConverter]::ToString($hash).Replace('-','').ToLowerInvariant()
}

Export-ModuleMember -Function Get-Sb3BAllowlist,New-SbLevel1ExecutionManifest,Test-SbLevel1ExecutionManifest,Get-SbLevel1ManifestDigest
