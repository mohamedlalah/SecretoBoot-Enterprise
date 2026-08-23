Set-StrictMode -Version Latest

function New-SbMultiOsMvpEfiManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Level1ManifestDigest,[bool]$FeatureGateState=$false,[bool]$ExplicitConsent=$false,[bool]$NonElevated=$false,[ValidateSet('Passed','Failed','NotRun')][string]$PlatformCheck='NotRun')
    [pscustomobject][ordered]@{
        SchemaVersion='v9multiosefiexecution1';PackageRevision='MultiOS-EFI-MVP.1';FeatureGateState=$FeatureGateState;ExplicitConsent=$ExplicitConsent;PlatformCheck=$PlatformCheck;NonElevated=$NonElevated;Level1ManifestDigest=$Level1ManifestDigest
        DynamicDetectedSystems=$true;MaximumPartitionCandidates=4096;MaximumEspCandidates=64;MaximumVendorDirectoriesPerEsp=64;MaximumLoaderFilesPerEsp=256;MaximumConfigFilesPerEsp=64;MaximumLoaderBytes=33554432;MaximumConfigBytes=16384;TimeoutMillisecondsPerEsp=10000
        EfiReadAccess=$true;ApprovedPathGrammar='EFI/<safe-vendor>/<x64-efi-or-grub.cfg>';Mounts=$false;DriveLetterAssignment=$false;EfiWrites=$false;BcdAccess=$false;NvramAccess=$false;SecureBootAccess=$false;BootOrderAccess=$false;PartitionWrites=$false;BootStateWrites=$false;Network=$false;RefindAccess=$false
    }
}
function Test-SbMultiOsMvpEfiManifest {
    [CmdletBinding()]param([Parameter(Mandatory)][object]$Manifest)
    $codes=[Collections.Generic.List[string]]::new();$expected=@('SchemaVersion','PackageRevision','FeatureGateState','ExplicitConsent','PlatformCheck','NonElevated','Level1ManifestDigest','DynamicDetectedSystems','MaximumPartitionCandidates','MaximumEspCandidates','MaximumVendorDirectoriesPerEsp','MaximumLoaderFilesPerEsp','MaximumConfigFilesPerEsp','MaximumLoaderBytes','MaximumConfigBytes','TimeoutMillisecondsPerEsp','EfiReadAccess','ApprovedPathGrammar','Mounts','DriveLetterAssignment','EfiWrites','BcdAccess','NvramAccess','SecureBootAccess','BootOrderAccess','PartitionWrites','BootStateWrites','Network','RefindAccess')
    if(@($Manifest.PSObject.Properties.Name|Where-Object{$_ -notin$expected}).Count-or@($expected|Where-Object{$_ -notin$Manifest.PSObject.Properties.Name}).Count){$codes.Add('EFI_MANIFEST_SHAPE_DENIED')}
    if($Manifest.SchemaVersion-cne'v9multiosefiexecution1'-or$Manifest.PackageRevision-cne'MultiOS-EFI-MVP.1'){$codes.Add('EFI_MANIFEST_VERSION_DENIED')}
    if($Manifest.FeatureGateState-ne$true-or$Manifest.ExplicitConsent-ne$true-or$Manifest.PlatformCheck-cne'Passed'-or$Manifest.NonElevated-ne$true){$codes.Add('EFI_MANIFEST_GATE_DENIED')}
    if([string]$Manifest.Level1ManifestDigest-notmatch'^[0-9a-f]{64}$'-or$Manifest.DynamicDetectedSystems-ne$true-or[int]$Manifest.MaximumPartitionCandidates-ne4096-or[int]$Manifest.MaximumEspCandidates-ne64-or[int]$Manifest.MaximumVendorDirectoriesPerEsp-ne64-or[int]$Manifest.MaximumLoaderFilesPerEsp-ne256-or[int]$Manifest.MaximumConfigFilesPerEsp-ne64-or[int]$Manifest.MaximumLoaderBytes-ne33554432-or[int]$Manifest.MaximumConfigBytes-ne16384-or[int]$Manifest.TimeoutMillisecondsPerEsp-ne10000){$codes.Add('EFI_MANIFEST_LIMIT_DENIED')}
    if($Manifest.EfiReadAccess-ne$true-or$Manifest.ApprovedPathGrammar-cne'EFI/<safe-vendor>/<x64-efi-or-grub.cfg>'){$codes.Add('EFI_MANIFEST_SCOPE_DENIED')}
    foreach($name in @('Mounts','DriveLetterAssignment','EfiWrites','BcdAccess','NvramAccess','SecureBootAccess','BootOrderAccess','PartitionWrites','BootStateWrites','Network','RefindAccess')){if($Manifest.$name-ne$false){$codes.Add('EFI_MANIFEST_FORBIDDEN_CAPABILITY')}}
    [pscustomobject]@{Allowed=($codes.Count-eq0);DiagnosticCodes=@($codes|Sort-Object -Unique)}
}
function Get-SbMultiOsMvpEfiManifestDigest{[CmdletBinding()]param([Parameter(Mandatory)][object]$Manifest);$a=[Security.Cryptography.SHA256]::Create();try{$h=$a.ComputeHash([Text.Encoding]::UTF8.GetBytes(($Manifest|ConvertTo-Json -Depth 20 -Compress)))}finally{$a.Dispose()};[BitConverter]::ToString($h).Replace('-','').ToLowerInvariant()}
Export-ModuleMember -Function New-SbMultiOsMvpEfiManifest,Test-SbMultiOsMvpEfiManifest,Get-SbMultiOsMvpEfiManifestDigest
