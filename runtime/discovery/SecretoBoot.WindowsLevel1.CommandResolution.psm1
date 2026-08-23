Set-StrictMode -Version Latest

$script:CommandSpecifications=@{
    'windows.os.cim'=[pscustomobject]@{CommandName='Get-CimInstance';TrustedModuleName='CimCmdlets';ProxyModuleName=$null;ManifestRelativePath='Modules\CimCmdlets\CimCmdlets.psd1';ManifestRoot='PSHOME';StrictCmdlet=$true}
    'storage.disks'=[pscustomobject]@{CommandName='Get-Disk';TrustedModuleName='Storage';ProxyModuleName='Disk';ManifestRelativePath='System32\WindowsPowerShell\v1.0\Modules\Storage\Storage.psd1';ManifestRoot='SystemRoot';StrictCmdlet=$false}
    'storage.partitions'=[pscustomobject]@{CommandName='Get-Partition';TrustedModuleName='Storage';ProxyModuleName='Partition';ManifestRelativePath='System32\WindowsPowerShell\v1.0\Modules\Storage\Storage.psd1';ManifestRoot='SystemRoot';StrictCmdlet=$false}
    'storage.volumes'=[pscustomobject]@{CommandName='Get-Volume';TrustedModuleName='Storage';ProxyModuleName='Volume';ManifestRelativePath='System32\WindowsPowerShell\v1.0\Modules\Storage\Storage.psd1';ManifestRoot='SystemRoot';StrictCmdlet=$false}
}

function ConvertTo-SbComparableWindowsPath {
    param([AllowNull()][string]$Path)
    if([string]::IsNullOrWhiteSpace($Path)){return ''}
    $value=$Path.Trim().Replace('/','\')
    while($value.Contains('\\')){$value=$value.Replace('\\','\')}
    if($value.Split('\')-contains'..'){return ''}
    return $value.TrimEnd('\').ToLowerInvariant()
}

function Test-SbSameWindowsPath {
    param([string]$Actual,[string]$Expected)
    $actualValue=ConvertTo-SbComparableWindowsPath $Actual;$expectedValue=ConvertTo-SbComparableWindowsPath $Expected
    return $actualValue.Length-gt 0-and$actualValue-eq$expectedValue
}

function Test-SbWindowsPathWithin {
    param([string]$Actual,[string]$TrustedManifestPath)
    $actualValue=ConvertTo-SbComparableWindowsPath $Actual;$manifestValue=ConvertTo-SbComparableWindowsPath $TrustedManifestPath
    if($actualValue.Length-eq 0-or$manifestValue.Length-eq 0){return $false}
    $separator=$manifestValue.LastIndexOf('\');if($separator-lt 0){return $false};$trustedRoot=$manifestValue.Substring(0,$separator)+'\'
    return $actualValue-eq$manifestValue-or$actualValue.StartsWith($trustedRoot,[StringComparison]::OrdinalIgnoreCase)
}

function Get-SbTrustedCimAssemblyPaths {
    param([Parameter(Mandatory)][string]$PowerShellHome)
    $root=$PowerShellHome.Trim().TrimEnd('\','/')
    return @(
        ($root+'\Microsoft.Management.Infrastructure.CimCmdlets.dll')
        ($root+'\Modules\CimCmdlets\Microsoft.Management.Infrastructure.CimCmdlets.dll')
    )
}

function Test-SbReviewedCommandMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('windows.os.cim','storage.disks','storage.partitions','storage.volumes')][string]$OperationId,
        [Parameter(Mandatory)][object]$Metadata,
        [Parameter(Mandatory)][string]$ExpectedTrustedManifestPath,
        [string]$ExpectedTrustedPowerShellHome
    )
    $specification=$script:CommandSpecifications[$OperationId];$diagnostics=[Collections.Generic.List[string]]::new()
    $required=@('ModulePresent','Name','CommandType','ModuleName','Source','ResolvedModulePath','OriginModuleName','OriginModulePath','ExportedByTrustedModule','IsCompatibilityProxy');$optional=@('ImplementingAssemblyName','ImplementingAssemblyPath')
    if(@($Metadata.PSObject.Properties.Name|Where-Object{$_ -notin@($required+$optional)}).Count-or@($required|Where-Object{$_ -notin$Metadata.PSObject.Properties.Name}).Count){$diagnostics.Add('COMMAND_METADATA_SHAPE_DENIED')}
    if($Metadata.ModulePresent-ne$true){$diagnostics.Add('COMMAND_TRUSTED_MODULE_MISSING')}
    if([string]$Metadata.Name-ne$specification.CommandName){$diagnostics.Add('COMMAND_NAME_DENIED')}
    if($specification.StrictCmdlet){$trustedOrigins=@($ExpectedTrustedManifestPath);if(-not[string]::IsNullOrWhiteSpace($ExpectedTrustedPowerShellHome)){$trustedOrigins+=@(Get-SbTrustedCimAssemblyPaths $ExpectedTrustedPowerShellHome)};$originAllowed=[string]$Metadata.OriginModuleName-eq$specification.TrustedModuleName-and@($trustedOrigins|Where-Object{Test-SbSameWindowsPath ([string]$Metadata.OriginModulePath) $_}).Count-eq 1}
    else{$originAllowed=[string]$Metadata.OriginModuleName-eq$specification.TrustedModuleName-and(Test-SbSameWindowsPath ([string]$Metadata.OriginModulePath) $ExpectedTrustedManifestPath)}
    if(-not$originAllowed){$diagnostics.Add('COMMAND_ORIGIN_DENIED')}
    if($Metadata.ExportedByTrustedModule-ne$true){$diagnostics.Add('COMMAND_EXPORT_PROVENANCE_DENIED')}
    if($specification.StrictCmdlet){
        if([string]$Metadata.CommandType-ne'Cmdlet'-or[string]$Metadata.ModuleName-ne'CimCmdlets'-or[string]$Metadata.Source-ne'CimCmdlets'-or$Metadata.IsCompatibilityProxy-ne$false){$diagnostics.Add('COMMAND_CIM_PROVENANCE_DENIED')}
        $assemblyPaths=if([string]::IsNullOrWhiteSpace($ExpectedTrustedPowerShellHome)){@()}else{@(Get-SbTrustedCimAssemblyPaths $ExpectedTrustedPowerShellHome)}
        $originTrusted=(Test-SbSameWindowsPath ([string]$Metadata.OriginModulePath) $ExpectedTrustedManifestPath)-or@($assemblyPaths|Where-Object{Test-SbSameWindowsPath ([string]$Metadata.OriginModulePath) $_}).Count-eq 1
        $resolvedTrusted=(Test-SbWindowsPathWithin ([string]$Metadata.ResolvedModulePath) $ExpectedTrustedManifestPath)-or@($assemblyPaths|Where-Object{Test-SbSameWindowsPath ([string]$Metadata.ResolvedModulePath) $_}).Count-eq 1
        $assemblyTrusted=$null-ne$Metadata.PSObject.Properties['ImplementingAssemblyName']-and[string]$Metadata.ImplementingAssemblyName-eq'Microsoft.Management.Infrastructure.CimCmdlets'-and$null-ne$Metadata.PSObject.Properties['ImplementingAssemblyPath']-and@($assemblyPaths|Where-Object{Test-SbSameWindowsPath ([string]$Metadata.ImplementingAssemblyPath) $_}).Count-eq 1
        if(-not$originTrusted-or-not$resolvedTrusted-or-not$assemblyTrusted){$diagnostics.Add('COMMAND_MODULE_PATH_DENIED')}
    }else{
        $native=[string]$Metadata.ModuleName-eq'Storage'-and[string]$Metadata.CommandType-in@('Cmdlet','Function')-and$Metadata.IsCompatibilityProxy-eq$false-and(Test-SbWindowsPathWithin ([string]$Metadata.ResolvedModulePath) $ExpectedTrustedManifestPath)
        $proxy=[string]$Metadata.ModuleName-eq$specification.ProxyModuleName-and[string]$Metadata.CommandType-eq'Function'-and$Metadata.IsCompatibilityProxy-eq$true
        if(-not($native-or$proxy)){$diagnostics.Add('COMMAND_STORAGE_PROVENANCE_DENIED')}
    }
    return [pscustomobject]@{Allowed=($diagnostics.Count-eq 0);DiagnosticCodes=$diagnostics.ToArray()}
}

function Get-SbTrustedModuleManifestPath {
    param([Parameter(Mandatory)][object]$Specification)
    $root=if($Specification.ManifestRoot-eq'PSHOME'){$PSHOME}else{[Environment]::GetEnvironmentVariable('SystemRoot')}
    if([string]::IsNullOrWhiteSpace([string]$root)){return $null}
    return [IO.Path]::GetFullPath((Join-Path $root ([string]$Specification.ManifestRelativePath)))
}

function Resolve-SbReviewedPowerShellCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('windows.os.cim','storage.disks','storage.partitions','storage.volumes')][string]$OperationId)
    $specification=$script:CommandSpecifications[$OperationId];$trustedManifest=Get-SbTrustedModuleManifestPath $specification
    if([string]::IsNullOrWhiteSpace($trustedManifest)){return [pscustomobject]@{Available=$false;DiagnosticCode='COMMAND_TRUSTED_MODULE_MISSING';CommandType=$null;ModuleName=$null}}
    try{
        if($OperationId-eq'windows.os.cim'){
            $assemblyPaths=@(Get-SbTrustedCimAssemblyPaths $PSHOME);$trustedArtifacts=@($trustedManifest)+$assemblyPaths;$existingArtifacts=@($trustedArtifacts|Where-Object{[IO.File]::Exists($_)})
            if(-not$existingArtifacts.Count){return [pscustomobject]@{Available=$false;DiagnosticCode='COMMAND_TRUSTED_MODULE_MISSING';CommandType=$null;ModuleName=$null}}
            $imported=@(Microsoft.PowerShell.Core\Get-Module -Name CimCmdlets|Where-Object{$module=$_;[string]$module.Name-eq'CimCmdlets'-and@($trustedArtifacts|Where-Object{Test-SbSameWindowsPath ([string]$module.Path) $_}).Count-eq 1})
            if(-not$imported.Count){foreach($artifact in $existingArtifacts){try{$imported=@(Microsoft.PowerShell.Core\Import-Module -Name $artifact -PassThru -ErrorAction Stop);if($imported.Count){break}}catch{$imported=@()}}}
            $origin=@($imported|Where-Object{$module=$_;[string]$module.Name-eq'CimCmdlets'-and@($trustedArtifacts|Where-Object{Test-SbSameWindowsPath ([string]$module.Path) $_}).Count-eq 1})[0]
        }else{
            if(-not[IO.File]::Exists($trustedManifest)){return [pscustomobject]@{Available=$false;DiagnosticCode='COMMAND_TRUSTED_MODULE_MISSING';CommandType=$null;ModuleName=$null}}
            $imported=@(Microsoft.PowerShell.Core\Import-Module -Name $trustedManifest -Force -PassThru -ErrorAction Stop)
            $origin=@($imported|Where-Object{Test-SbSameWindowsPath ([string]$_.Path) $trustedManifest})[0]
        }
        if($null-eq$origin){return [pscustomobject]@{Available=$false;DiagnosticCode='COMMAND_TRUSTED_MODULE_IMPORT_DENIED';CommandType=$null;ModuleName=$null}}
        $command=$origin.ExportedCommands[[string]$specification.CommandName]
        if($null-eq$command){return [pscustomobject]@{Available=$false;DiagnosticCode='COMMAND_EXPORT_MISSING';CommandType=$null;ModuleName=$null}}
        $moduleName=[string]$command.ModuleName;$resolvedPath=if($null-ne$command.Module){[string]$command.Module.Path}else{''}
        $metadata=[ordered]@{
            ModulePresent=$true;Name=[string]$command.Name;CommandType=$command.CommandType.ToString();ModuleName=$moduleName;Source=[string]$command.Source
            ResolvedModulePath=$resolvedPath;OriginModuleName=[string]$origin.Name;OriginModulePath=[string]$origin.Path;ExportedByTrustedModule=$true
            IsCompatibilityProxy=($specification.TrustedModuleName-eq'Storage'-and$moduleName-eq$specification.ProxyModuleName-and$command.CommandType.ToString()-eq'Function')
        }
        if($OperationId-eq'windows.os.cim'){$metadata.ImplementingAssemblyName=[string]$command.ImplementingType.Assembly.GetName().Name;$metadata.ImplementingAssemblyPath=[string]$command.ImplementingType.Assembly.Location}
        $review=Test-SbReviewedCommandMetadata -OperationId $OperationId -Metadata ([pscustomobject]$metadata) -ExpectedTrustedManifestPath $trustedManifest -ExpectedTrustedPowerShellHome $(if($OperationId-eq'windows.os.cim'){$PSHOME}else{$null})
        return [pscustomobject]@{Available=$review.Allowed;DiagnosticCode=if($review.Allowed){'COMMAND_PROVENANCE_APPROVED'}else{($review.DiagnosticCodes-join',')};CommandType=$metadata.CommandType;ModuleName=$metadata.ModuleName}
    }catch{return [pscustomobject]@{Available=$false;DiagnosticCode='COMMAND_TRUSTED_MODULE_IMPORT_FAILED';CommandType=$null;ModuleName=$null}}
}

Export-ModuleMember -Function Test-SbReviewedCommandMetadata,Resolve-SbReviewedPowerShellCommand
