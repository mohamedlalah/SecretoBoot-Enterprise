[CmdletBinding()]
param(
    [bool]$FeatureGateState=$false,
    [switch]$UseSyntheticCapabilities,
    [string]$SyntheticPlatform='Windows',
    [version]$SyntheticPowerShellVersion='7.6.5',
    [string[]]$SyntheticAvailableOperations=@('platform.runtime','platform.environment','windows.os.cim','storage.disks','storage.partitions','storage.volumes')
)
$ErrorActionPreference='Stop';Import-Module (Join-Path $PSScriptRoot 'SecretoBoot.WindowsLevel1.Manifest.psm1') -Force;Import-Module (Join-Path $PSScriptRoot 'SecretoBoot.WindowsLevel1.CommandResolution.psm1') -Force
$policy=Get-Sb3BAllowlist;$platform=if($UseSyntheticCapabilities){$SyntheticPlatform}elseif([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)){'Windows'}else{'Unsupported'}
$version=if($UseSyntheticCapabilities){$SyntheticPowerShellVersion}else{$PSVersionTable.PSVersion};$available=[Collections.Generic.List[string]]::new();$commandResolution=[ordered]@{}
if($UseSyntheticCapabilities){foreach($id in $SyntheticAvailableOperations){$available.Add($id)}}else{
    foreach($operation in $policy.operations){
        if($operation.kind-eq'DotNetApi'){$typeAvailable=$null-ne($operation.name-as[type]);if($typeAvailable){$available.Add([string]$operation.id)}}
        else{$resolution=Resolve-SbReviewedPowerShellCommand -OperationId ([string]$operation.id);$commandResolution[$operation.id]=[pscustomobject]@{Available=$resolution.Available;DiagnosticCode=$resolution.DiagnosticCode;CommandType=$resolution.CommandType;ModuleName=$resolution.ModuleName};if($resolution.Available){$available.Add([string]$operation.id)}}
    }
}
$integrity=($policy.defaultAction-eq'deny'-and$policy.maximumAccessLevel-eq 1-and@($policy.operations).Count-eq 6-and@($policy.operations|Where-Object{$_.requiresMount-or$_.touchesBootConfiguration}).Count-eq 0)
$integrityData=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'integrity-manifest.json'))|ConvertFrom-Json -Depth 20;$packageMode=$null-ne$integrityData.PSObject.Properties['packageVersion'];$integrityRoot=if($packageMode){[IO.Path]::GetFullPath($PSScriptRoot)}else{[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))};$toolIntegrity=$integrityData.manifestVersion-eq'v9level1integrity1'
foreach($property in $integrityData.files.PSObject.Properties){$path=[IO.Path]::GetFullPath((Join-Path $integrityRoot $property.Name));$prefix=$integrityRoot.TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar;if(-not$path.StartsWith($prefix,[StringComparison]::Ordinal)-or-not[IO.File]::Exists($path)){$toolIntegrity=$false;continue};$algorithm=[Security.Cryptography.SHA256]::Create();try{$actual=[BitConverter]::ToString($algorithm.ComputeHash([IO.File]::ReadAllBytes($path))).Replace('-','').ToLowerInvariant()}finally{$algorithm.Dispose()};if($actual-ne[string]$property.Value){$toolIntegrity=$false}}
if($packageMode){$expected=@($integrityData.files.PSObject.Properties.Name)+@('integrity-manifest.json');$actualFiles=@(Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -File|ForEach-Object{$_.FullName.Substring($PSScriptRoot.Length+1).Replace([IO.Path]::DirectorySeparatorChar,'/') }|Where-Object{$_ -notmatch'^output/'});if(@($actualFiles|Where-Object{$_ -notin$expected}).Count-or@($expected|Where-Object{$_ -notin$actualFiles}).Count){$toolIntegrity=$false}}
$missing=@($policy.operations.id|Where-Object{$_ -notin $available});$supportedVersion=$version-ge[version]'7.4.0'-and$version-lt[version]'8.0.0';$elevation=[ordered]@{};foreach($operation in $policy.operations){$elevation[$operation.id]=[bool]$operation.requiresElevation}
[pscustomobject][ordered]@{Mode=if($UseSyntheticCapabilities){'SyntheticPreflight'}else{'RealPreflightNoInventory'};Platform=$platform;PowerShellVersion=$version.ToString();SupportedPowerShellVersion=$supportedVersion;PolicyIntegrity=$integrity;ToolIntegrity=$toolIntegrity;FeatureGateState=$FeatureGateState;RequiresElevation=$elevation;AutomaticElevationAttempted=$false;AvailableOperations=@($available);MissingOperations=$missing;CommandResolution=$commandResolution;InventoryOperationsExecuted=0;Ready=($platform-eq'Windows'-and$supportedVersion-and$integrity-and$toolIntegrity-and$FeatureGateState-and$missing.Count-eq 0)}
