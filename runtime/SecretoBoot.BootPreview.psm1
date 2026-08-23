Set-StrictMode -Version Latest

function Get-SbBootPreviewId([string]$Value) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $hash = [Security.Cryptography.SHA256]::HashData($bytes)
    return 'boot-preview:' + [Convert]::ToHexString($hash).Substring(0, 20).ToLowerInvariant()
}

function ConvertTo-SbBootEntries {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ConsolidatedSystems,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$CanonicalBootTargets
    )

    if ($ConsolidatedSystems.Count -gt 4096) { throw 'BOOT_PREVIEW_RESOURCE_CAP_EXCEEDED' }
    $targetBySystem = @{}
    foreach ($target in $CanonicalBootTargets) {
        if ($target.ValidationStatus -cne 'Validated' -or $target.Confidence -cne 'Confirmed' -or [string]::IsNullOrWhiteSpace([string]$target.SourceSystemId) -or $targetBySystem.ContainsKey([string]$target.SourceSystemId)) { throw 'BOOT_PREVIEW_CANONICAL_TARGET_DENIED' }
        $targetBySystem[[string]$target.SourceSystemId] = $target
    }
    $entries = [Collections.Generic.List[object]]::new()
    foreach ($system in $ConsolidatedSystems) {
        $sourceId = [string]$system.ConsolidatedSystemId
        if ([string]::IsNullOrWhiteSpace($sourceId)) { throw 'BOOT_PREVIEW_SOURCE_ID_DENIED' }
        $family = [string]$system.Family
        $distribution = [string]$system.Distribution
        $displayName = if ($family -ceq 'Android' -and $distribution -and $distribution -notmatch '^Unknown') { $distribution } elseif ($family -in @('Windows', 'Android', 'Linux')) { $family } elseif ($distribution -and $distribution -notmatch '^Unknown') { $distribution } else { 'Unknown system' }
        $icon = if ($family -in @('Windows', 'Android', 'Linux')) { $family } else { 'Unknown' }
        $missingReason = switch ($family) {
            'Windows' { 'BOOT_PREVIEW_WINDOWS_LOADER_EVIDENCE_REQUIRED' }
            'Linux' { 'BOOT_PREVIEW_LINUX_LOADER_RELATIONSHIP_REQUIRED' }
            'Android' { 'BOOT_PREVIEW_ANDROID_LOADER_RELATIONSHIP_REQUIRED' }
            default { 'BOOT_PREVIEW_UNKNOWN_NOT_BOOT_READY' }
        }
        $target = if ($targetBySystem.ContainsKey($sourceId)) { $targetBySystem[$sourceId] } else { $null }
        if ($null -ne $target -and [string]$target.Family -cne $family) { throw 'BOOT_PREVIEW_TARGET_FAMILY_MISMATCH' }
        $ready = $null -ne $target
        $entries.Add([pscustomobject][ordered]@{
            EntryId = Get-SbBootPreviewId $sourceId
            DisplayName = $displayName
            Family = if ($family) { $family } else { 'Unknown' }
            Distribution = if ($distribution) { $distribution } else { 'Unknown' }
            Confidence = [string]$system.Confidence
            SourceSystemId = $sourceId
            SourceCandidateReferences = @($system.CandidateReferences)
            IconKind = $icon
            BootMethod = if ($ready) { [string]$target.BootMethod } else { 'NotAssigned' }
            BootTargetStatus = if ($ready) { 'BootTargetResolved' } else { 'NeedsEvidence' }
            IsBootReady = $ready
            ReasonCode = if ($ready) { 'BOOT_PREVIEW_CANONICAL_TARGET_RESOLVED' } else { $missingReason }
            CanonicalBootTarget = $target
        })
    }
    return $entries.ToArray()
}

function New-SbRefindConfigPreview {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$BootEntries)

    $lines = [Collections.Generic.List[string]]::new()
    foreach ($line in @(
        '# SecretoBoot V9 / rEFInd configuration preview — NOT DEPLOYED',
        '# rEFInd remains the boot-time loader-scanning backend.',
        '# Preserve upstream rEFInd licensing and attribution when a runtime is later bundled.',
        'timeout 10',
        'default_selection "Windows"',
        'scanfor internal,manual',
        '# Manual menu entries are omitted until canonical loader evidence is proven.'
    )) { $lines.Add($line) }
    foreach ($entry in @($BootEntries | Where-Object IsBootReady -eq $true)) {
        $target = $entry.CanonicalBootTarget
        if ($null -eq $target -or $target.ValidationStatus -cne 'Validated' -or $target.SourcePartitionId -notmatch '^[0-9a-fA-F-]{36}$') { throw 'REFIND_PREVIEW_READY_TARGET_DENIED' }
        $name = ([string]$entry.DisplayName).Replace('"','')
        $lines.Add(('menuentry "{0}" {{' -f $name))
        $lines.Add(('    volume {0}' -f $target.SourcePartitionId))
        if ($target.BootMethod -in @('UefiLoader','AndroidInitrdRuntimeDiscovery') -and [string]$target.LoaderPath -match '^/EFI/[A-Za-z0-9._+/-]+\.efi$') {
            $lines.Add(('    loader {0}' -f $target.LoaderPath))
        } elseif ($target.BootMethod -ceq 'KernelInitrd' -and [string]$target.KernelPath -match '^/[A-Za-z0-9._+/-]+$' -and [string]$target.InitrdPath -match '^/[A-Za-z0-9._+/-]+$' -and -not [string]::IsNullOrWhiteSpace([string]$target.BootArguments)) {
            $lines.Add(('    loader {0}' -f $target.KernelPath))
            $lines.Add(('    initrd {0}' -f $target.InitrdPath))
            $lines.Add(('    options "{0}"' -f $target.BootArguments))
        } else { throw 'REFIND_PREVIEW_BOOT_METHOD_DENIED' }
        $lines.Add('}')
    }
    return [pscustomobject][ordered]@{
        Status = 'PreviewGeneratedNotDeployed'
        OwnedNamespace = 'EFI/SecretoBootV9'
        ConceptualFiles = @('refind_x64.efi', 'refind.conf', 'themes/', 'icons/')
        ConfigText = $lines.ToArray() -join "`r`n"
        BootEntryCount = $BootEntries.Count
        ReadyEntryCount = @($BootEntries | Where-Object IsBootReady -eq $true).Count
        SafetyCounters = [pscustomobject]@{ EfiWrites=0; BcdWrites=0; NvramWrites=0; BootOrderChanges=0; PartitionWrites=0; Mounts=0; DriveLetterAssignments=0; RefindInstallations=0; Reboots=0; Network=0 }
    }
}

Export-ModuleMember -Function ConvertTo-SbBootEntries, New-SbRefindConfigPreview
