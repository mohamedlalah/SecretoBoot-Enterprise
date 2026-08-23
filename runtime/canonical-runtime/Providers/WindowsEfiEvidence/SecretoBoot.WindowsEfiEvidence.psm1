Set-StrictMode -Version Latest

function Initialize-SbWindowsEfiEvidenceAdapter {
    [CmdletBinding()]
    param()
    if($null-ne('SecretoBoot.V9.WindowsEfiEvidence.EspEvidenceAdapter'-as[type])){return $true}
    $source=Join-Path $PSScriptRoot 'Native/SecretoBoot.WindowsEfiEvidence.Native.cs'
    if(-not[IO.File]::Exists($source)){throw 'EFI_EVIDENCE_NATIVE_SOURCE_MISSING'}
    Add-Type -Path $source -ErrorAction Stop
    return $null-ne('SecretoBoot.V9.WindowsEfiEvidence.EspEvidenceAdapter'-as[type])
}

function Invoke-SbWindowsEfiEvidenceInspection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid]$VolumeGuid,
        [Parameter(Mandatory)][ValidatePattern('^report:partition:[0-9a-f]{20}$')][string]$EspToken,
        [Parameter(Mandatory)][switch]$EnableEfiEvidence,
        [Parameter(Mandatory)][switch]$GrantExplicitConsent
    )
    $null=Initialize-SbWindowsEfiEvidenceAdapter
    $request=[SecretoBoot.V9.WindowsEfiEvidence.EspInspectionRequest]::new();$request.FeatureEnabled=$EnableEfiEvidence.IsPresent;$request.ExplicitConsent=$GrantExplicitConsent.IsPresent;$request.RequireNonElevated=$true;$request.VolumeGuid=$VolumeGuid.ToString('D');$request.EspToken=$EspToken
    return [SecretoBoot.V9.WindowsEfiEvidence.EspEvidenceAdapter]::Inspect($request)
}

Export-ModuleMember -Function Initialize-SbWindowsEfiEvidenceAdapter,Invoke-SbWindowsEfiEvidenceInspection
