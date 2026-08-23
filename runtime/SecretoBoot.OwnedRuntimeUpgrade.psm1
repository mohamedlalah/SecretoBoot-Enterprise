Set-StrictMode -Version Latest

function Get-SbUpgradeHash {
    param([Parameter(Mandatory)][string]$Path)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($Path))).ToLowerInvariant()
}

function Get-SbUpgradeJson {
    param([Parameter(Mandatory)][object]$Value)
    $Value | ConvertTo-Json -Depth 16
}

function Resolve-SbOwnedPath {
    param([Parameter(Mandatory)][string]$Root,[Parameter(Mandatory)][string]$Relative)
    if($Relative-notmatch'^[A-Za-z0-9._/-]+$'-or$Relative-match'(^|/)[.][.](/|$)'){throw 'UPGRADE_OWNED_PATH_DENIED'}
    $rootFull=[IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar
    $path=[IO.Path]::GetFullPath((Join-Path $Root $Relative))
    if(-not$path.StartsWith($rootFull,[StringComparison]::OrdinalIgnoreCase)){throw 'UPGRADE_OWNED_PATH_DENIED'}
    $path
}

function Write-SbAtomicFile {
    param([Parameter(Mandatory)][string]$Destination,[Parameter(Mandatory)][byte[]]$Bytes)
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Destination))|Out-Null
    $temporary=$Destination+'.sbnew-'+[guid]::NewGuid().ToString('N')
    try{[IO.File]::WriteAllBytes($temporary,$Bytes);[IO.File]::Move($temporary,$Destination,$true)}finally{if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}}
}

function Invoke-SbOwnedRuntimeUpgrade {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$OldManifest,
        [Parameter(Mandatory)][string]$OwnedRoot,
        [Parameter(Mandatory)][string]$AssetsRoot,
        [Parameter(Mandatory)][string]$ConfigText,
        [Parameter(Mandatory)][string]$StateManifestPath,
        [Parameter(Mandatory)][string]$BackupRoot,
        [Parameter(Mandatory)][string]$NewRevision,
        [Parameter(Mandatory)][string]$ThemeRevision,
        [Parameter(Mandatory)][string[]]$SupportedOldRevisions
    )
    if([string]$OldManifest.SchemaVersion-cne'v9-ownership-manifest-1'-or$OldManifest.OwnershipVerified-ne$true-or[string]$OldManifest.Revision-notin$SupportedOldRevisions){throw 'UPGRADE_OWNERSHIP_DENIED'}
    if(-not[IO.Directory]::Exists($OwnedRoot)-or-not[IO.Directory]::Exists($AssetsRoot)){throw 'UPGRADE_SOURCE_OR_TARGET_MISSING'}
    $efiManifestPath=Join-Path $OwnedRoot 'ownership-manifest.json'
    if(-not[IO.File]::Exists($efiManifestPath)-or-not[IO.File]::Exists($StateManifestPath)){throw 'UPGRADE_OWNERSHIP_MANIFEST_MISSING'}
    $oldJson=Get-SbUpgradeJson $OldManifest;$oldBytes=[Text.UTF8Encoding]::new($false).GetBytes($oldJson)
    $oldManifestHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($oldBytes)).ToLowerInvariant()
    if((Get-SbUpgradeHash $efiManifestPath)-cne$oldManifestHash-or(Get-SbUpgradeHash $StateManifestPath)-cne$oldManifestHash){throw 'UPGRADE_OWNERSHIP_MANIFEST_IDENTITY_DENIED'}

    $oldFiles=[ordered]@{}
    foreach($property in $OldManifest.InstalledFiles.PSObject.Properties){$path=Resolve-SbOwnedPath $OwnedRoot ([string]$property.Name);if(-not[IO.File]::Exists($path)-or(Get-SbUpgradeHash $path)-cne[string]$property.Value){throw 'UPGRADE_OWNED_FILE_IDENTITY_DENIED'};$oldFiles[[string]$property.Name]=[string]$property.Value}

    $sources=[ordered]@{}
    foreach($source in [IO.Directory]::EnumerateFiles($AssetsRoot,'*',[IO.SearchOption]::AllDirectories)){$relative=[IO.Path]::GetRelativePath($AssetsRoot,$source).Replace('\','/');$null=Resolve-SbOwnedPath $OwnedRoot $relative;$sources[$relative]=$source}
    $configBytes=[Text.UTF8Encoding]::new($false).GetBytes($ConfigText)
    if($ConfigText-notmatch'(?m)^include themes/SecretoBootV9/theme[.]conf\s*$'){throw 'UPGRADE_ACTIVE_THEME_REFERENCE_DENIED'}
    $marker='themes/SecretoBootV9/theme-revision.txt'
    if(-not$sources.Contains($marker)-or([IO.File]::ReadAllText([string]$sources[$marker])).Trim()-cne$ThemeRevision){throw 'UPGRADE_THEME_REVISION_DENIED'}
    $sources['refind.conf']=$null
    foreach($relative in $sources.Keys){$destination=Resolve-SbOwnedPath $OwnedRoot $relative;if([IO.File]::Exists($destination)-and-not$oldFiles.Contains($relative)){throw 'UPGRADE_UNOWNED_DESTINATION_CONFLICT'} }

    [IO.Directory]::CreateDirectory($BackupRoot)|Out-Null
    $backupFiles=Join-Path $BackupRoot 'files';[IO.Directory]::CreateDirectory($backupFiles)|Out-Null
    foreach($relative in $oldFiles.Keys){$source=Resolve-SbOwnedPath $OwnedRoot $relative;$backup=Resolve-SbOwnedPath $backupFiles $relative;[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($backup))|Out-Null;[IO.File]::Copy($source,$backup,$false);if((Get-SbUpgradeHash $backup)-cne$oldFiles[$relative]){throw 'UPGRADE_BACKUP_VERIFICATION_DENIED'}}
    [IO.File]::Copy($efiManifestPath,(Join-Path $BackupRoot 'efi-ownership-manifest.json'),$false)
    [IO.File]::Copy($StateManifestPath,(Join-Path $BackupRoot 'state-ownership-manifest.json'),$false)

    $newFiles=[ordered]@{};$committed=$false
    try{
        foreach($relative in $sources.Keys){$bytes=if($relative-ceq'refind.conf'){$configBytes}else{[IO.File]::ReadAllBytes([string]$sources[$relative])};$destination=Resolve-SbOwnedPath $OwnedRoot $relative;Write-SbAtomicFile $destination $bytes;$newFiles[$relative]=Get-SbUpgradeHash $destination}
        foreach($relative in @($oldFiles.Keys)){if(-not$newFiles.Contains($relative)){[IO.File]::Delete((Resolve-SbOwnedPath $OwnedRoot $relative))}}
        foreach($property in $newFiles.GetEnumerator()){if((Get-SbUpgradeHash (Resolve-SbOwnedPath $OwnedRoot $property.Key))-cne$property.Value){throw 'UPGRADE_DEPLOYED_FILE_READBACK_DENIED'}}
        if(([IO.File]::ReadAllText((Resolve-SbOwnedPath $OwnedRoot 'refind.conf')))-notmatch'(?m)^include themes/SecretoBootV9/theme[.]conf\s*$'){throw 'UPGRADE_ACTIVE_THEME_REFERENCE_DENIED'}
        if(([IO.File]::ReadAllText((Resolve-SbOwnedPath $OwnedRoot $marker))).Trim()-cne$ThemeRevision){throw 'UPGRADE_THEME_REVISION_READBACK_DENIED'}
        $newManifest=[pscustomobject][ordered]@{SchemaVersion='v9-ownership-manifest-1';OwnershipVerified=$true;Revision=$NewRevision;ThemeRevision=$ThemeRevision;ThemeDeployment='MATCH';RefindVersion=[string]$OldManifest.RefindVersion;InstalledUtc=[string]$OldManifest.InstalledUtc;UpgradedUtc=[DateTime]::UtcNow.ToString('o');TargetEspPartitionGuid=[string]$OldManifest.TargetEspPartitionGuid;InstalledFiles=[pscustomobject]$newFiles;FirmwareEntryName=[string]$OldManifest.FirmwareEntryName;FirmwareEntryNumber=[int]$OldManifest.FirmwareEntryNumber;FirmwareLoadOptionBase64=[string]$OldManifest.FirmwareLoadOptionBase64;PreviousBootOrderBase64=[string]$OldManifest.PreviousBootOrderBase64;ForeignLoaderHashes=$OldManifest.ForeignLoaderHashes;BootOrderChangedByMakeDefault=[bool]$OldManifest.BootOrderChangedByMakeDefault}
        $newBytes=[Text.UTF8Encoding]::new($false).GetBytes((Get-SbUpgradeJson $newManifest));Write-SbAtomicFile $efiManifestPath $newBytes;Write-SbAtomicFile $StateManifestPath $newBytes
        $expected=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($newBytes)).ToLowerInvariant();if((Get-SbUpgradeHash $efiManifestPath)-cne$expected-or(Get-SbUpgradeHash $StateManifestPath)-cne$expected){throw 'UPGRADE_MANIFEST_READBACK_DENIED'}
        $committed=$true
        return [pscustomobject]@{Status='Upgraded';Manifest=$newManifest;InstalledFiles=[pscustomobject]$newFiles;ThemeRevision=$ThemeRevision;ThemeDeployment='MATCH'}
    }finally{
        if(-not$committed){
            $rollbackFailed=$false
            foreach($relative in @($newFiles.Keys)){if(-not$oldFiles.Contains($relative)){try{[IO.File]::Delete((Resolve-SbOwnedPath $OwnedRoot $relative))}catch{$rollbackFailed=$true}}}
            foreach($relative in $oldFiles.Keys){$backup=Resolve-SbOwnedPath $backupFiles $relative;$destination=Resolve-SbOwnedPath $OwnedRoot $relative;try{Write-SbAtomicFile $destination ([IO.File]::ReadAllBytes($backup))}catch{$rollbackFailed=$true}}
            try{Write-SbAtomicFile $efiManifestPath ([IO.File]::ReadAllBytes((Join-Path $BackupRoot 'efi-ownership-manifest.json')))}catch{$rollbackFailed=$true}
            try{Write-SbAtomicFile $StateManifestPath ([IO.File]::ReadAllBytes((Join-Path $BackupRoot 'state-ownership-manifest.json')))}catch{$rollbackFailed=$true}
            try{foreach($relative in $oldFiles.Keys){if((Get-SbUpgradeHash (Resolve-SbOwnedPath $OwnedRoot $relative))-cne$oldFiles[$relative]){$rollbackFailed=$true}};if((Get-SbUpgradeHash $efiManifestPath)-cne$oldManifestHash-or(Get-SbUpgradeHash $StateManifestPath)-cne$oldManifestHash){$rollbackFailed=$true}}catch{$rollbackFailed=$true}
            if($rollbackFailed){throw 'UPGRADE_ROLLBACK_INCOMPLETE'}
            [IO.Directory]::Delete($BackupRoot,$true)
        }
        if($committed){[IO.Directory]::Delete($BackupRoot,$true)}
    }
}

Export-ModuleMember -Function Invoke-SbOwnedRuntimeUpgrade
