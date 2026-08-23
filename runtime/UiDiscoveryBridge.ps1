[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [switch]$ApproveReadOnlyDiscovery
)

$ErrorActionPreference = 'Stop'
$consent = 'I_APPROVE_SECRETOBOOT_READ_ONLY_ANDROID_VOLUME_EVIDENCE'
$backend = Join-Path $PSScriptRoot 'discovery'
$projectionPath = Join-Path $PSScriptRoot 'SecretoBoot.UiProjection.psm1'
$bootPreviewPath = Join-Path $PSScriptRoot 'SecretoBoot.BootPreview.psm1'
$canonicalTargetPath = Join-Path $PSScriptRoot 'SecretoBoot.CanonicalBootTarget.psm1'
$canonicalPipelinePath = Join-Path $PSScriptRoot 'Invoke-CanonicalEvidenceDiscovery.ps1'
$canonicalIntegrityPath = Join-Path $PSScriptRoot 'canonical-runtime-integrity.json'
$refindSetupPath = Join-Path $PSScriptRoot 'SecretoBoot.RefindSetupPreview.psm1'
$endToEndPath = Join-Path $PSScriptRoot 'SecretoBoot.EndToEnd.psm1'
$refindAssetsPath = Join-Path $PSScriptRoot 'refind-assets.json'
$stage = 'BridgeStartup'

function ConvertTo-SbSafeFailureText {
    param([AllowNull()][object]$Value,[int]$MaximumLength=240)
    $text=([string]$Value)-replace'[\x00-\x1f\x7f]',' '
    $text=$text-replace'(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}','[REDACTED-GUID]'
    $text=$text-replace'(?i)(?:[A-Z]:\\|\\\\\?\\)[^\r\n;]+','[REDACTED-PATH]'
    $text=$text-replace'(?<![A-Za-z0-9])/(?:Users|home|Volumes|private)/[^\r\n;"'']+','[REDACTED-PATH]'
    if($text.Length-gt$MaximumLength){$text=$text.Substring(0,$MaximumLength)}
    if([string]::IsNullOrWhiteSpace($text)){return 'No safe exception message available.'}
    return $text
}

function Get-SbPackagedDependencyAvailability {
    $required=[ordered]@{
        UiProjection=$projectionPath;BootPreview=$bootPreviewPath;CanonicalTarget=$canonicalTargetPath;CanonicalPipeline=$canonicalPipelinePath
        CanonicalIntegrity=$canonicalIntegrityPath;RefindSetupPreview=$refindSetupPath;EndToEnd=$endToEndPath;RefindAssets=$refindAssetsPath
        DiscoveryPreflight=(Join-Path $backend 'Invoke-Preflight.ps1');DiscoveryManifest=(Join-Path $backend 'New-DiscoveryManifest.ps1')
        AndroidNativeSource=(Join-Path $PSScriptRoot 'canonical-runtime/Providers/WindowsAndroidEvidence/Native/SecretoBoot.WindowsAndroidEvidence.Native.cs')
        EfiNativeSource=(Join-Path $PSScriptRoot 'canonical-runtime/Providers/WindowsEfiEvidence/Native/SecretoBoot.WindowsEfiEvidence.Native.cs')
        RefindX64=(Join-Path $PSScriptRoot 'resources/refind/0.14.2/refind_x64.efi')
    }
    return @($required.GetEnumerator()|ForEach-Object{"$($_.Key)="+$(if([IO.File]::Exists([string]$_.Value)){'Present'}else{'Missing'})})-join'; '
}

try {
    $stage = 'PackageIntegrity'
    if (-not $ApproveReadOnlyDiscovery) { throw 'UI_EXPLICIT_CONSENT_REQUIRED' }
    $projectionHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($projectionPath))).ToLowerInvariant()
    $bootPreviewHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($bootPreviewPath))).ToLowerInvariant()
    $canonicalTargetHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($canonicalTargetPath))).ToLowerInvariant()
    $canonicalPipelineHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($canonicalPipelinePath))).ToLowerInvariant()
    $canonicalIntegrityHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($canonicalIntegrityPath))).ToLowerInvariant()
    $refindSetupHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($refindSetupPath))).ToLowerInvariant()
    $endToEndHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($endToEndPath))).ToLowerInvariant()
    $refindAssetsHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($refindAssetsPath))).ToLowerInvariant()
    if ($projectionHash -cne '987f41952aa2aea04c36e5abd1f62631562189b1b225c560b285549405730da9' -or $bootPreviewHash -cne '101c707b547ca8fa908be547f6d91752cfe0e55c5a80b5aa1072264ab78664c2' -or $canonicalTargetHash -cne '283298371c430b6d49e4cd30c528dd3e240d9bd8e583593f9766f1a319836787' -or $canonicalPipelineHash -cne '55703fecbcb3b8502472f3763ba07155a30087a3c7dedc0f568a9b2538546af5' -or $canonicalIntegrityHash -cne 'aa8a8b0a5f8512292961777cf8d79f3e58d89904d0f62308009ccafc18213a4c' -or $refindSetupHash -cne 'f1bf10fc683c47fbb441c91ffd79c4af5686747554d84a675d08ef7ce18489e1' -or $endToEndHash -cne '881ac54429ee534964baacdbb5437f7477fe640cacacf0ce40f954bdd09f3781' -or $refindAssetsHash -cne 'a818cc7c8d4ac49b2d228cbb1d06ea584fe356c629b7cb73d1ca66c1a95233d9') { throw 'UI_MODULE_INTEGRITY_DENIED' }
    $stage = 'ModuleImport'
    Import-Module $canonicalTargetPath -Force
    Import-Module $bootPreviewPath -Force
    Import-Module $projectionPath -Force
    $stage = 'DiscoveryManifestConstruction'
    $prepared = & (Join-Path $backend 'New-DiscoveryManifest.ps1') `
        -ApproveAndroidAccessibleEvidence `
        -ConsentPhrase $consent
    $stage = 'CanonicalDiscoveryPipeline'
    $result = & $canonicalPipelinePath `
        -ApproveCanonicalEvidence `
        -ConsentPhrase 'I_APPROVE_SECRETOBOOT_BOUNDED_READ_ONLY_CANONICAL_EVIDENCE' `
        -ExpectedManifestDigest ([string]$prepared.Digest)
    $stage = 'UiProjection'
    ConvertTo-SbUiDiscoveryProtocol -DiscoveryResult $result
}
catch {
    $exceptionType=ConvertTo-SbSafeFailureText $_.Exception.GetType().FullName 120
    $message=ConvertTo-SbSafeFailureText $_.Exception.Message
    $component=if($message-match'REFIND_SETUP'){'RefindSetupPreview'}elseif($message-match'CANONICAL_RUNTIME_INTEGRITY|UI_MODULE_INTEGRITY'){'PackageIntegrity'}else{$stage}
    $report=@(
        'SecretoBoot V9 Safe Discovery Failure Diagnostic'
        ('Exception type: {0}' -f $exceptionType)
        ('Safe exception message: {0}' -f $message)
        ('Failing stage/component: {0}' -f $component)
        ('Packaged dependency/resource availability: {0}' -f (Get-SbPackagedDependencyAvailability))
        'Sensitive identifiers: redacted'
        'Boot-state changes: 0'
    )-join"`r`n"
    'SBUI1'
    "STATUS`tFailed"
    "SUMMARY`t0`t0`t0`t0"
    "BOOTSUMMARY`t0`t0`tNotGenerated"
    'ERRORREPORT' + "`t" + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($report))
    exit 1
}
