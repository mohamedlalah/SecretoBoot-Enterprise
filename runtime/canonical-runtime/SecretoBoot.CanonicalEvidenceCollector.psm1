Set-StrictMode -Version Latest

function ConvertTo-SbCanonicalEfiEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Artifact,
        [Parameter(Mandatory)][guid]$SourcePartitionId,
        [Parameter(Mandatory)][guid]$SourceDiskId
    )
    $path = ([string]$Artifact.RelativePath).Replace('\','/').TrimStart('/')
    $approved = $path -match '(?i)^EFI/[A-Za-z0-9._-]{1,64}/[A-Za-z0-9._-]{1,64}\.efi$' -or $path -ceq 'EFI/Microsoft/Boot/bootmgfw.efi'
    if (-not $approved -or $Artifact.Kind -cne 'EfiLoader' -or $Artifact.ValidPeX64 -ne $true -or [long]$Artifact.SizeBytes -lt 1 -or [long]$Artifact.SizeBytes -gt 33554432) { throw 'CANONICAL_EFI_ARTIFACT_DENIED' }
    $signals = @($Artifact.Signals + @('bounded-read-validated','esp-partition-related') | Sort-Object -Unique)
    if ('shim-loader' -in $signals -or 'grub-loader' -in $signals) { $signals += 'linux-loader' }
    return [pscustomobject][ordered]@{
        EvidenceId = 'canonical:' + [string]$Artifact.EvidenceId
        EvidenceKind = 'CanonicalEfiLoader'
        Kind = 'EfiLoader'
        RelativePath = $path
        SourcePartitionId = $SourcePartitionId.ToString('D')
        PartitionId = $SourcePartitionId.ToString('D')
        SourceDiskId = $SourceDiskId.ToString('D')
        DiskId = $SourceDiskId.ToString('D')
        Signals = @($signals | Sort-Object -Unique)
        ValidationStatus = 'Validated'
        ContainmentStatus = 'Passed'
        IsRegularFile = $true
        SizeBytes = [long]$Artifact.SizeBytes
    }
}

function New-SbCanonicalEvidenceCollectionSummary {
    [CmdletBinding()]
    param([object[]]$Evidence,[object[]]$Denied,[int]$EspInspections,[int]$NativeOpens,[int]$BoundedReads,[long]$BytesRead)
    if ($EspInspections -gt 64 -or $NativeOpens -gt 25000 -or $BoundedReads -gt 20480 -or $BytesRead -gt 134217728) { throw 'CANONICAL_EVIDENCE_READ_CAP_EXCEEDED' }
    return [pscustomobject][ordered]@{
        Evidence = @($Evidence); Denied = @($Denied)
        Counters = [pscustomobject][ordered]@{ EspInspections=$EspInspections; NativeOpenOperations=$NativeOpens; BoundedReadOperations=$BoundedReads; BytesRead=$BytesRead; EfiWrites=0; BcdWrites=0; NvramWrites=0; BootOrderChanges=0; PartitionWrites=0; FilesystemWrites=0; Mounts=0; DriveLetterAssignments=0; RefindInstallations=0; Reboots=0; Network=0 }
    }
}

Export-ModuleMember -Function ConvertTo-SbCanonicalEfiEvidence,New-SbCanonicalEvidenceCollectionSummary
