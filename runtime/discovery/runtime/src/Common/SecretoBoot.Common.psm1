Set-StrictMode -Version Latest

enum SbLoaderFamily {
    Windows
    Linux
    AndroidGoogleTV
    UnknownUEFI
    Invalid
}

enum SbConfidenceLevel {
    Confirmed
    Probable
    Possible
    Unknown
    Invalid
}

enum SbDuplicateRelationshipKind {
    ExactIdentity
    ByteIdenticalCopy
    LikelyFallbackAlias
    RelatedButDistinct
    Ambiguous
}

enum SbWarningSeverity {
    Information
    Warning
    Error
}

enum SbInventoryAccessLevel {
    SyntheticOnly = 0
    HostMetadata = 1
    EspRead = 2
    WriteCapable = 3
}

enum SbProviderSafetyClassification {
    RepositoryOnly
    HostReadOnly
    EspReadOnlyApprovalRequired
    ProhibitedWrite
}

class SbProviderCapability {
    [string] $Name
    [SbInventoryAccessLevel] $AccessLevel
    [bool] $RequiresHostAccess
    [bool] $RequiresElevation
    [bool] $RequiresMount
    [string[]] $DataReturned
    [string] $FailureBehavior
    [string] $PrivacyImpact
    [SbProviderSafetyClassification] $SafetyClassification
    [string] $SupportedPlatform

    SbProviderCapability(
        [string] $name,
        [SbInventoryAccessLevel] $accessLevel,
        [bool] $requiresHostAccess,
        [bool] $requiresElevation,
        [bool] $requiresMount,
        [string[]] $dataReturned,
        [string] $failureBehavior,
        [string] $privacyImpact,
        [SbProviderSafetyClassification] $safetyClassification,
        [string] $supportedPlatform
    ) {
        $this.Name = $name
        $this.AccessLevel = $accessLevel
        $this.RequiresHostAccess = $requiresHostAccess
        $this.RequiresElevation = $requiresElevation
        $this.RequiresMount = $requiresMount
        $this.DataReturned = $dataReturned
        $this.FailureBehavior = $failureBehavior
        $this.PrivacyImpact = $privacyImpact
        $this.SafetyClassification = $safetyClassification
        $this.SupportedPlatform = $supportedPlatform
    }
}

class SbHostAccessPolicy {
    [SbInventoryAccessLevel] $MaximumLevel
    [bool] $HostMetadataFeatureEnabled

    SbHostAccessPolicy() {
        $this.MaximumLevel = [SbInventoryAccessLevel]::SyntheticOnly
        $this.HostMetadataFeatureEnabled = $false
    }
}

class SbDiskIdentity {
    [guid] $DiskGuid

    SbDiskIdentity([string] $diskGuid) {
        [guid] $parsed = [guid]::Empty
        if (-not [guid]::TryParse($diskGuid, [ref] $parsed)) {
            throw "Invalid disk GUID: $diskGuid"
        }
        $this.DiskGuid = $parsed
    }

    [string] ToString() {
        return $this.DiskGuid.ToString('D').ToUpperInvariant()
    }
}

class SbEspIdentity {
    [SbDiskIdentity] $Disk
    [guid] $PartitionGuid

    SbEspIdentity([SbDiskIdentity] $disk, [string] $partitionGuid) {
        [guid] $parsed = [guid]::Empty
        if (-not [guid]::TryParse($partitionGuid, [ref] $parsed)) {
            throw "Invalid ESP partition GUID: $partitionGuid"
        }
        $this.Disk = $disk
        $this.PartitionGuid = $parsed
    }

    [string] ToString() {
        return $this.PartitionGuid.ToString('D').ToUpperInvariant()
    }
}

class SbLoaderPath {
    [string] $Value

    SbLoaderPath([string] $path) {
        $this.Value = [SbLoaderPath]::Normalize($path)
    }

    static [string] Normalize([string] $path) {
        if ([string]::IsNullOrWhiteSpace($path)) {
            throw 'Loader path is empty.'
        }

        $candidate = $path.Trim().Replace('\', '/')
        while ($candidate.Contains('//')) {
            $candidate = $candidate.Replace('//', '/')
        }

        if ($candidate.Length -gt 1024) {
            throw 'Loader path exceeds the 1024-character safety limit.'
        }
        if ($candidate.IndexOf([char] 0) -ge 0 -or $candidate.Contains([char] 0xFFFD)) {
            throw 'Loader path contains an unsafe null or replacement character.'
        }
        foreach ($character in $candidate.ToCharArray()) {
            if ([char]::IsControl($character)) {
                throw 'Loader path contains an unsafe control character.'
            }
        }

        if (-not $candidate.StartsWith('/')) {
            throw 'Loader path must be absolute within the EFI filesystem.'
        }

        foreach ($segment in $candidate.Split('/')) {
            if ($segment -eq '..') {
                throw 'Loader path traversal is not allowed.'
            }
        }

        if (-not $candidate.StartsWith('/EFI/', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Loader path must begin with /EFI/.'
        }

        if (-not $candidate.EndsWith('.efi', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Loader path must identify an EFI executable.'
        }

        return $candidate.ToLowerInvariant()
    }

    [string] ToString() {
        return $this.Value
    }
}

class SbLoaderIdentity {
    [guid] $EspPartitionGuid
    [SbLoaderPath] $LoaderPath
    [string] $CanonicalKey

    SbLoaderIdentity([string] $espPartitionGuid, [string] $loaderPath) {
        [guid] $parsed = [guid]::Empty
        if (-not [guid]::TryParse($espPartitionGuid, [ref] $parsed)) {
            throw "Invalid ESP partition GUID: $espPartitionGuid"
        }
        $this.EspPartitionGuid = $parsed
        $this.LoaderPath = [SbLoaderPath]::new($loaderPath)
        $this.CanonicalKey = '{0}:{1}' -f $parsed.ToString('B').ToUpperInvariant(), $this.LoaderPath.Value
    }

    [string] ToString() {
        return $this.CanonicalKey
    }
}

class SbLoaderEvidence {
    [string[]] $Signals

    SbLoaderEvidence([string[]] $signals) {
        if ($null -eq $signals) {
            $this.Signals = @()
        } else {
            $this.Signals = @($signals | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
        }
    }

    [bool] Has([string] $signal) {
        return $this.Signals -contains $signal.ToLowerInvariant()
    }
}

class SbLoaderMetadata {
    [string] $DiskGuid
    [string] $EspPartitionGuid
    [string] $RawPath
    [string] $Sha256
    [bool] $PeValid
    [string] $Architecture
    [string] $VolumeLabel
    [SbLoaderEvidence] $Evidence

    SbLoaderMetadata(
        [string] $diskGuid,
        [string] $espPartitionGuid,
        [string] $rawPath,
        [string] $sha256,
        [bool] $peValid,
        [string] $architecture,
        [string] $volumeLabel,
        [string[]] $evidence
    ) {
        $this.DiskGuid = $diskGuid
        $this.EspPartitionGuid = $espPartitionGuid
        $this.RawPath = $rawPath
        $this.Sha256 = if ($null -eq $sha256) { '' } else { $sha256.ToLowerInvariant() }
        $this.PeValid = $peValid
        $this.Architecture = if ($null -eq $architecture) { '' } else { $architecture.ToLowerInvariant() }
        $this.VolumeLabel = $volumeLabel
        $this.Evidence = [SbLoaderEvidence]::new($evidence)
    }
}

class SbReasonCode {
    [string] $Code
    [string] $Description

    SbReasonCode([string] $code, [string] $description) {
        $this.Code = $code
        $this.Description = $description
    }
}

class SbClassificationResult {
    [SbLoaderFamily] $Family
    [SbConfidenceLevel] $Confidence
    [SbReasonCode[]] $Reasons

    SbClassificationResult([SbLoaderFamily] $family, [SbConfidenceLevel] $confidence, [SbReasonCode[]] $reasons) {
        $this.Family = $family
        $this.Confidence = $confidence
        $this.Reasons = $reasons
    }
}

class SbDiagnosticWarning {
    [string] $Code
    [SbWarningSeverity] $Severity
    [string] $Description
    [string] $LoaderIdentity

    SbDiagnosticWarning([string] $code, [SbWarningSeverity] $severity, [string] $description, [string] $loaderIdentity) {
        $this.Code = $code
        $this.Severity = $severity
        $this.Description = $description
        $this.LoaderIdentity = $loaderIdentity
    }
}

class SbDuplicateRelationship {
    [SbDuplicateRelationshipKind] $Kind
    [string] $LeftIdentity
    [string] $RightIdentity
    [SbReasonCode[]] $Reasons

    SbDuplicateRelationship([SbDuplicateRelationshipKind] $kind, [string] $leftIdentity, [string] $rightIdentity, [SbReasonCode[]] $reasons) {
        $this.Kind = $kind
        $this.LeftIdentity = $leftIdentity
        $this.RightIdentity = $rightIdentity
        $this.Reasons = $reasons
    }
}

class SbPresentationMetadata {
    [string] $CanonicalId
    [string] $DisplayFamily
    [string] $PreferredLabel
    [string] $IconKey
    [SbConfidenceLevel] $Confidence
    [bool] $AdvancedViewRecommended
    [string] $DuplicateGroup
    [string] $WarningState
    [string] $StaleState
    [string] $SourceEspId

    SbPresentationMetadata(
        [string] $canonicalId,
        [string] $displayFamily,
        [string] $preferredLabel,
        [string] $iconKey,
        [SbConfidenceLevel] $confidence,
        [bool] $advancedViewRecommended,
        [string] $duplicateGroup,
        [string] $warningState,
        [string] $staleState,
        [string] $sourceEspId
    ) {
        $this.CanonicalId = $canonicalId
        $this.DisplayFamily = $displayFamily
        $this.PreferredLabel = $preferredLabel
        $this.IconKey = $iconKey
        $this.Confidence = $confidence
        $this.AdvancedViewRecommended = $advancedViewRecommended
        $this.DuplicateGroup = $duplicateGroup
        $this.WarningState = $warningState
        $this.StaleState = $staleState
        $this.SourceEspId = $sourceEspId
    }
}

class SbRedactionResult {
    [string] $Category
    [string] $Value
    [bool] $Redacted
    [string] $ReasonCode

    SbRedactionResult([string] $category, [string] $value, [bool] $redacted, [string] $reasonCode) {
        $this.Category = $category
        $this.Value = $value
        $this.Redacted = $redacted
        $this.ReasonCode = $reasonCode
    }
}

class SbLoaderAssessment {
    [SbLoaderMetadata] $Metadata
    [SbLoaderIdentity] $Identity
    [SbClassificationResult] $Classification
    [SbPresentationMetadata] $Presentation
    [bool] $PotentiallyStale

    SbLoaderAssessment([SbLoaderMetadata] $metadata) {
        $this.Metadata = $metadata
        $this.PotentiallyStale = $false
    }
}

class SbEspInventory {
    [SbEspIdentity] $Identity
    [string] $ObservedLabel
    [System.Collections.Generic.List[SbLoaderAssessment]] $Loaders

    SbEspInventory([SbEspIdentity] $identity, [string] $observedLabel) {
        $this.Identity = $identity
        $this.ObservedLabel = $observedLabel
        $this.Loaders = [System.Collections.Generic.List[SbLoaderAssessment]]::new()
    }
}

class SbDiskInventory {
    [SbDiskIdentity] $Identity
    [bool] $Present
    [System.Collections.Generic.List[SbEspInventory]] $Esps

    SbDiskInventory([SbDiskIdentity] $identity, [bool] $present) {
        $this.Identity = $identity
        $this.Present = $present
        $this.Esps = [System.Collections.Generic.List[SbEspInventory]]::new()
    }
}

class SbDiscoveryInventory {
    [string] $ScenarioId
    [System.Collections.Generic.List[SbDiskInventory]] $Disks
    [System.Collections.Generic.List[SbLoaderAssessment]] $Loaders
    [System.Collections.Generic.List[SbDuplicateRelationship]] $DuplicateRelationships
    [System.Collections.Generic.List[SbDiagnosticWarning]] $Warnings

    SbDiscoveryInventory([string] $scenarioId) {
        $this.ScenarioId = $scenarioId
        $this.Disks = [System.Collections.Generic.List[SbDiskInventory]]::new()
        $this.Loaders = [System.Collections.Generic.List[SbLoaderAssessment]]::new()
        $this.DuplicateRelationships = [System.Collections.Generic.List[SbDuplicateRelationship]]::new()
        $this.Warnings = [System.Collections.Generic.List[SbDiagnosticWarning]]::new()
    }
}

class SbAuditResult {
    [string] $ScenarioId
    [SbDiscoveryInventory] $Inventory
    [bool] $ReadOnly
    [string] $Result

    SbAuditResult([string] $scenarioId, [SbDiscoveryInventory] $inventory, [string] $result) {
        $this.ScenarioId = $scenarioId
        $this.Inventory = $inventory
        $this.ReadOnly = $true
        $this.Result = $result
    }
}
