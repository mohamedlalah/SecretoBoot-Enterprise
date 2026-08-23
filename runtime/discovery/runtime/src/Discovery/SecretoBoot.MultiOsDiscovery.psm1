using module ../Common/SecretoBoot.Common.psm1

Set-StrictMode -Version Latest

enum SbEvidenceSourceLayer { HostStorageMetadata; FilesystemVolumeEvidence; EfiLoaderEvidence; BootConfigurationEvidence; OsRootEvidence }
enum SbEvidenceTrustTier { Strong; Medium; Weak }
enum SbEvidencePolarity { Positive; Negative; Neutral }
enum SbEvidenceAccessibility { Accessible; Inaccessible; Partial }
enum SbEvidenceFreshness { Current; Stale; Unknown }
enum SbEvidenceSubjectType { Disk; Partition; Filesystem; OsRootCandidate; Esp; EfiLoader; BootloaderConfig; BootEntry; Kernel; Initrd; OsMetadata; OsInstanceCandidate }
enum SbEvidenceGraphNodeType { Disk; Partition; Filesystem; OsRootCandidate; Esp; EfiLoader; BootloaderConfig; BootEntry; Kernel; Initrd; OsMetadata; OsInstanceCandidate }
enum SbEvidenceGraphEdgeType { Contains; BelongsTo; References; Chainloads; Boots; Corroborates; ConflictsWith; Aliases; RelatedButDistinct; StaleReference }
enum SbOsFamily { Windows; Linux; Android; ChromeOSStyle; Unknown }
enum SbOsDistribution { Windows; Zorin; Ubuntu; Fedora; Debian; GenericLinux; AndroidX86; AndroidTV; GoogleTV; FydeOS; ChromeOSStyle; UnknownLinux; UnknownAndroidLike; UnknownChromeOSLike; UnknownUEFI; UnknownBootable }
enum SbOsStaleState { Active; RootOnly; LoaderOnly; EntryOnly; BrokenReference; MissingDevice; UnknownFreshness }
enum SbOsAmbiguousState { None; MultipleRoots; MultipleLoaders; ConflictingFamily; UnresolvedAssociation }

class SbEvidenceId {
    [string] $Value
    SbEvidenceId([string] $value) {
        if ($value -notmatch '^ev:[a-z0-9][a-z0-9._-]{0,126}$') { throw "Invalid evidence ID: $value" }
        $this.Value=$value
    }
    [string] ToString(){ return $this.Value }
}

class SbEvidenceSubject {
    [string] $SubjectId
    [SbEvidenceSubjectType] $SubjectType
    SbEvidenceSubject([string]$subjectId,[SbEvidenceSubjectType]$subjectType){
        if($subjectId -notmatch '^node:[a-z0-9][a-z0-9._-]{0,126}$'){throw "Invalid subject ID: $subjectId"}
        $this.SubjectId=$subjectId;$this.SubjectType=$subjectType
    }
}

class SbEvidenceReason {
    [string] $Code
    [string] $Detail
    SbEvidenceReason([string]$code,[string]$detail){
        if($code -notmatch '^[A-Z][A-Z0-9_]+$'){throw "Invalid reason code: $code"}
        $this.Code=$code;$this.Detail=if($null-eq$detail){''}else{$detail}
    }
}

class SbEvidenceRecord {
    [SbEvidenceId] $EvidenceId
    [SbEvidenceSourceLayer] $SourceLayer
    [SbEvidenceTrustTier] $TrustTier
    [SbEvidencePolarity] $Polarity
    [SbEvidenceAccessibility] $Accessibility
    [SbEvidenceFreshness] $Freshness
    [SbEvidenceSubject] $Subject
    [string] $Signal
    [string] $Value
    [string] $SourceArtifactId
    [SbEvidenceReason[]] $Reasons
    SbEvidenceRecord([string]$evidenceId,[SbEvidenceSourceLayer]$sourceLayer,[SbEvidenceTrustTier]$trustTier,[SbEvidencePolarity]$polarity,[SbEvidenceAccessibility]$accessibility,[SbEvidenceFreshness]$freshness,[SbEvidenceSubject]$subject,[string]$signal,[string]$value,[string]$sourceArtifactId,[SbEvidenceReason[]]$reasons){
        if($signal -notmatch '^[a-z][a-z0-9.-]{0,127}$'){throw "Invalid evidence signal: $signal"}
        if([string]::IsNullOrWhiteSpace($sourceArtifactId) -or $sourceArtifactId.Length-gt128){throw 'Evidence provenance is required.'}
        if($null-ne$value -and $value.Length-gt256){throw 'Evidence value exceeds the 256-character safety limit.'}
        if($null-eq$reasons -or $reasons.Count-eq0){throw 'Evidence reasons are required.'}
        $this.EvidenceId=[SbEvidenceId]::new($evidenceId);$this.SourceLayer=$sourceLayer;$this.TrustTier=$trustTier;$this.Polarity=$polarity;$this.Accessibility=$accessibility;$this.Freshness=$freshness;$this.Subject=$subject;$this.Signal=$signal;$this.Value=if($null-eq$value){''}else{$value};$this.SourceArtifactId=$sourceArtifactId;$this.Reasons=$reasons
    }
}

class SbEvidenceConflict {
    [string] $ConflictId;[string[]] $EvidenceIds;[string] $ReasonCode
    SbEvidenceConflict([string]$conflictId,[string[]]$evidenceIds,[string]$reasonCode){$this.ConflictId=$conflictId;$this.EvidenceIds=@($evidenceIds|Sort-Object -Unique);$this.ReasonCode=$reasonCode}
}

class SbEvidenceGraphNode {
    [string] $NodeId;[SbEvidenceGraphNodeType] $NodeType;[string[]] $EvidenceIds
    SbEvidenceGraphNode([string]$nodeId,[SbEvidenceGraphNodeType]$nodeType,[string[]]$evidenceIds){
        if($nodeId -notmatch '^node:[a-z0-9][a-z0-9._-]{0,126}$'){throw "Invalid graph node ID: $nodeId"}
        $this.NodeId=$nodeId;$this.NodeType=$nodeType;$this.EvidenceIds=@($evidenceIds|Sort-Object -Unique)
    }
}

class SbEvidenceGraphEdge {
    [string] $EdgeId;[string] $FromNodeId;[string] $ToNodeId;[SbEvidenceGraphEdgeType] $EdgeType;[string[]] $EvidenceIds
    SbEvidenceGraphEdge([string]$edgeId,[string]$fromNodeId,[string]$toNodeId,[SbEvidenceGraphEdgeType]$edgeType,[string[]]$evidenceIds){
        if($edgeId -notmatch '^edge:[a-z0-9][a-z0-9._-]{0,126}$'){throw "Invalid graph edge ID: $edgeId"}
        if($fromNodeId-eq$toNodeId){throw 'Self-referencing graph edges are prohibited.'}
        $this.EdgeId=$edgeId;$this.FromNodeId=$fromNodeId;$this.ToNodeId=$toNodeId;$this.EdgeType=$edgeType;$this.EvidenceIds=@($evidenceIds|Sort-Object -Unique)
    }
}

class SbOsPresentationMetadata {
    [string]$DisplayLabel;[string]$IconKey;[SbConfidenceLevel]$Confidence;[string]$WarningState;[SbOsStaleState]$StaleState;[SbOsAmbiguousState]$AmbiguousState;[string]$PrimaryCandidate;[string[]]$AdvancedAlternatives;[bool]$PresentationEligible
    SbOsPresentationMetadata([string]$displayLabel,[string]$iconKey,[SbConfidenceLevel]$confidence,[string]$warningState,[SbOsStaleState]$staleState,[SbOsAmbiguousState]$ambiguousState,[string]$primaryCandidate,[string[]]$advancedAlternatives){$this.DisplayLabel=$displayLabel;$this.IconKey=$iconKey;$this.Confidence=$confidence;$this.WarningState=$warningState;$this.StaleState=$staleState;$this.AmbiguousState=$ambiguousState;$this.PrimaryCandidate=$primaryCandidate;$this.AdvancedAlternatives=@($advancedAlternatives|Sort-Object -Unique);$this.PresentationEligible=$true}
}

class SbOsInstance {
    [string]$OsInstanceId;[SbOsFamily]$Family;[SbOsDistribution]$Distribution;[string]$Version;[SbConfidenceLevel]$Confidence;[string[]]$ReasonCodes;[string]$RootPartitionId;[string[]]$AssociatedEspIds;[string[]]$AssociatedLoaderIds;[string[]]$AssociatedBootEntryIds;[string[]]$EvidenceIds;[string]$PrimaryBootCandidate;[SbOsStaleState]$StaleState;[SbOsAmbiguousState]$AmbiguousState;[string[]]$Warnings;[SbOsPresentationMetadata]$PresentationMetadata
}

class SbOsDiscoveryResult {
    [string]$SchemaVersion='v9osdiscovery1';[bool]$SyntheticOnly=$true;[SbEvidenceGraphNode[]]$Nodes;[SbEvidenceGraphEdge[]]$Edges;[SbEvidenceConflict[]]$Conflicts;[SbOsInstance[]]$OsInstances;[int]$HostOperationsExecuted=0;[int]$BootOperationsExecuted=0;[int]$NetworkOperationsExecuted=0
}

$script:DiscoveryReasonRegistry=$null
function Get-SbDiscoveryReasonRegistry {
    if($null-eq$script:DiscoveryReasonRegistry){
        $path=Join-Path $PSScriptRoot '../../config/reason-codes.json';$raw=[IO.File]::ReadAllText([IO.Path]::GetFullPath($path))|ConvertFrom-Json -Depth 20;$table=@{};foreach($property in $raw.codes.PSObject.Properties){$table[$property.Name]=[string]$property.Value};$script:DiscoveryReasonRegistry=$table
    }
    return $script:DiscoveryReasonRegistry
}

function Add-SbDiscoveryReason([System.Collections.Generic.List[string]]$List,[string]$Code){$registry=Get-SbDiscoveryReasonRegistry;if(-not$registry.ContainsKey($Code)){throw "Unregistered reason code: $Code"};if(-not$List.Contains($Code)){$List.Add($Code)}}

function Get-SbOpaqueId([string]$Prefix,[string]$InputValue){$bytes=[Text.Encoding]::UTF8.GetBytes($InputValue);$hash=[Security.Cryptography.SHA256]::HashData($bytes);return '{0}:{1}'-f$Prefix,([Convert]::ToHexString($hash).Substring(0,20).ToLowerInvariant())}

function Test-SbSignal([SbEvidenceRecord[]]$Evidence,[string]$Signal){return @($Evidence|Where-Object{$_.Accessibility-eq'Accessible'-and$_.Polarity-eq'Positive'-and$_.Signal-eq$Signal}).Count-gt0}
function Get-SbSignalRecords([SbEvidenceRecord[]]$Evidence,[string]$Signal){return @($Evidence|Where-Object{$_.Accessibility-eq'Accessible'-and$_.Polarity-eq'Positive'-and$_.Signal-eq$Signal})}
function Test-SbNegativeSignal([SbEvidenceRecord[]]$Evidence,[string]$Signal){return @($Evidence|Where-Object{$_.Accessibility-eq'Accessible'-and$_.Polarity-eq'Negative'-and$_.Signal-eq$Signal}).Count-gt0}

function Test-SbGraphCycle {
    param([SbEvidenceGraphNode[]] $Nodes, [SbEvidenceGraphEdge[]] $Edges)
    $structural = @($Edges | Where-Object { $_.EdgeType -in @('Contains','BelongsTo','References','Chainloads','Boots') })
    $adjacency = @{}
    $indegree = @{}
    foreach ($node in $Nodes) { $adjacency[$node.NodeId] = [System.Collections.Generic.List[string]]::new(); $indegree[$node.NodeId] = 0 }
    foreach ($edge in $structural) { $adjacency[$edge.FromNodeId].Add($edge.ToNodeId); $indegree[$edge.ToNodeId]++ }
    $queue = [System.Collections.Generic.Queue[string]]::new()
    foreach ($nodeId in @($indegree.Keys | Sort-Object)) { if ($indegree[$nodeId] -eq 0) { $queue.Enqueue($nodeId) } }
    $visited = 0
    while ($queue.Count -gt 0) {
        $nodeId = $queue.Dequeue(); $visited++
        foreach ($next in $adjacency[$nodeId]) { $indegree[$next]--; if ($indegree[$next] -eq 0) { $queue.Enqueue($next) } }
    }
    return $visited -ne $Nodes.Count
}

function Assert-SbSyntheticGraph {
    param([SbEvidenceRecord[]] $Evidence, [SbEvidenceGraphNode[]] $Nodes, [SbEvidenceGraphEdge[]] $Edges)
    if ($Evidence.Count -gt 10000 -or $Nodes.Count -gt 1000 -or $Edges.Count -gt 5000) { throw 'Synthetic discovery resource limit exceeded.' }
    $evidenceIds = @($Evidence | ForEach-Object { $_.EvidenceId.Value })
    $nodeIds = @($Nodes | ForEach-Object { $_.NodeId })
    $edgeIds = @($Edges | ForEach-Object { $_.EdgeId })
    if (@($evidenceIds | Sort-Object -Unique).Count -ne $evidenceIds.Count) { throw 'Duplicate evidence ID.' }
    if (@($nodeIds | Sort-Object -Unique).Count -ne $nodeIds.Count) { throw 'Duplicate graph node ID.' }
    if (@($edgeIds | Sort-Object -Unique).Count -ne $edgeIds.Count) { throw 'Duplicate graph edge ID.' }
    $evidenceSet = [System.Collections.Generic.HashSet[string]]::new([string[]] $evidenceIds)
    $nodeSet = [System.Collections.Generic.HashSet[string]]::new([string[]] $nodeIds)
    foreach ($record in $Evidence) { if (-not $nodeSet.Contains($record.Subject.SubjectId)) { throw "Evidence subject missing: $($record.Subject.SubjectId)" } }
    foreach ($node in $Nodes) { foreach ($id in $node.EvidenceIds) { if (-not $evidenceSet.Contains($id)) { throw "Node evidence missing: $id" } } }
    foreach ($edge in $Edges) {
        if (-not $nodeSet.Contains($edge.FromNodeId) -or -not $nodeSet.Contains($edge.ToNodeId)) { throw "Edge endpoint missing: $($edge.EdgeId)" }
        foreach ($id in $edge.EvidenceIds) { if (-not $evidenceSet.Contains($id)) { throw "Edge evidence missing: $id" } }
    }
    if (Test-SbGraphCycle -Nodes $Nodes -Edges $Edges) { throw 'Structural graph cycle detected.' }
}

function Get-SbCandidateEvidence {
    param([SbEvidenceGraphNode] $Candidate, [SbEvidenceRecord[]] $Evidence, [SbEvidenceGraphEdge[]] $Edges)
    $subjectIds = [System.Collections.Generic.HashSet[string]]::new()
    $null = $subjectIds.Add($Candidate.NodeId)
    foreach ($edge in $Edges) {
        if ($edge.EdgeType -eq 'BelongsTo' -and $edge.ToNodeId -eq $Candidate.NodeId) { $null = $subjectIds.Add($edge.FromNodeId) }
    }
    return @($Evidence | Where-Object { $subjectIds.Contains($_.Subject.SubjectId) } | Sort-Object { $_.EvidenceId.Value })
}

function Get-SbCandidateRelations {
    param([SbEvidenceGraphNode] $Candidate, [SbEvidenceGraphNode[]] $Nodes, [SbEvidenceGraphEdge[]] $Edges)
    $relatedIds = @($Edges | Where-Object { $_.EdgeType -eq 'BelongsTo' -and $_.ToNodeId -eq $Candidate.NodeId } | ForEach-Object { $_.FromNodeId })
    return @($Nodes | Where-Object { $_.NodeId -in $relatedIds } | Sort-Object NodeId)
}

function Get-SbClassificationDecision {
    param([SbEvidenceRecord[]] $Evidence)
    $reasons = [System.Collections.Generic.List[string]]::new()
    $family = [SbOsFamily]::Unknown; $distribution = [SbOsDistribution]::UnknownBootable; $confidence = [SbConfidenceLevel]::Unknown
    $windowsRoot = Test-SbSignal -Evidence $Evidence -Signal 'windows-root-candidate'
    $system32 = Test-SbSignal -Evidence $Evidence -Signal 'windows-system32-structure'
    $registry = Test-SbSignal -Evidence $Evidence -Signal 'windows-registry-identity'
    $windowsHost = Test-SbSignal -Evidence $Evidence -Signal 'windows-host-cim'
    $linuxRoot = Test-SbSignal -Evidence $Evidence -Signal 'linux-root'
    $linuxPartition = Test-SbSignal -Evidence $Evidence -Signal 'linux-partition-type'
    $distro = @('zorin','ubuntu','fedora','debian') | Where-Object { Test-SbSignal -Evidence $Evidence -Signal "os-release-$_" } | Select-Object -First 1
    $genericLinux = Test-SbSignal -Evidence $Evidence -Signal 'os-release-linux'
    $androidSystem = (Test-SbSignal -Evidence $Evidence -Signal 'android-system-image') -or (Test-SbSignal -Evidence $Evidence -Signal 'android-build-identity')
    $androidCategories = @(@('android-kernel','android-initrd','android-boot-arguments','android-boot-config') | Where-Object { Test-SbSignal -Evidence $Evidence -Signal $_ })
    $chromeRoot = Test-SbSignal -Evidence $Evidence -Signal 'chromeos-root'; $chromeLayout = Test-SbSignal -Evidence $Evidence -Signal 'chromeos-layout'; $fyde = Test-SbSignal -Evidence $Evidence -Signal 'fydeos-identity'
    $rootFamilies = @()
    if ($registry -or $windowsRoot -or $windowsHost) { $rootFamilies += 'Windows' }; if ($linuxRoot -or $linuxPartition -or $distro -or $genericLinux) { $rootFamilies += 'Linux' }; if ($androidSystem) { $rootFamilies += 'Android' }; if ($chromeRoot -or $fyde) { $rootFamilies += 'ChromeOSStyle' }
    $contradiction = (Test-SbSignal -Evidence $Evidence -Signal 'authoritative-contradiction') -or @($rootFamilies | Sort-Object -Unique).Count -gt 1
    if ($contradiction) {
        Add-SbDiscoveryReason $reasons 'DISCOVERY_AUTHORITATIVE_CONTRADICTION'; Add-SbDiscoveryReason $reasons 'DISCOVERY_CONFLICT'; $confidence = [SbConfidenceLevel]::Possible
    } elseif ($windowsHost) {
        $family='Windows'; $distribution='Windows'; $confidence='Confirmed'; Add-SbDiscoveryReason $reasons 'DISCOVERY_WINDOWS_HOST_CONFIRMED'
    } elseif ($registry -and $windowsRoot -and $system32) {
        $family='Windows'; $distribution='Windows'; $confidence='Confirmed'; Add-SbDiscoveryReason $reasons 'DISCOVERY_WINDOWS_STRONG_ROOT'
    } elseif ($windowsRoot -and $system32) {
        $family='Windows'; $distribution='Windows'; $confidence='Probable'; Add-SbDiscoveryReason $reasons 'DISCOVERY_WINDOWS_ROOT_PROBABLE'
    } elseif ($linuxRoot -and ($distro -or $genericLinux)) {
        $family='Linux'; $confidence='Confirmed'; Add-SbDiscoveryReason $reasons 'DISCOVERY_LINUX_ROOT'; Add-SbDiscoveryReason $reasons 'DISCOVERY_OS_RELEASE_IDENTITY'
        if (-not $distro) { $distribution='GenericLinux' }
        switch ($distro) { 'zorin' {$distribution='Zorin';Add-SbDiscoveryReason $reasons 'DISCOVERY_ZORIN_CONFIRMED'} 'ubuntu' {$distribution='Ubuntu';Add-SbDiscoveryReason $reasons 'DISCOVERY_UBUNTU_CONFIRMED'} 'fedora' {$distribution='Fedora';Add-SbDiscoveryReason $reasons 'DISCOVERY_FEDORA_CONFIRMED'} 'debian' {$distribution='Debian';Add-SbDiscoveryReason $reasons 'DISCOVERY_DEBIAN_CONFIRMED'} }
    } elseif ($linuxRoot) {
        $family='Linux'; $distribution='UnknownLinux'; $confidence='Probable'; Add-SbDiscoveryReason $reasons 'DISCOVERY_LINUX_ROOT'; Add-SbDiscoveryReason $reasons 'DISCOVERY_UNKNOWN_LINUX'
    } elseif ($linuxPartition) {
        $family='Linux'; $distribution='UnknownLinux'; $confidence='Possible'; Add-SbDiscoveryReason $reasons 'DISCOVERY_LINUX_PARTITION_CANDIDATE'; Add-SbDiscoveryReason $reasons 'DISCOVERY_UNKNOWN_LINUX'
    } elseif ($androidSystem -and $androidCategories.Count -ge 2) {
        $family='Android'; $confidence='Confirmed'; Add-SbDiscoveryReason $reasons 'DISCOVERY_ANDROID_SYSTEM_EVIDENCE'; Add-SbDiscoveryReason $reasons 'DISCOVERY_ANDROID_BOOT_EVIDENCE'
        if (Test-SbSignal -Evidence $Evidence -Signal 'google-tv-identity') {$distribution='GoogleTV';Add-SbDiscoveryReason $reasons 'DISCOVERY_GOOGLE_TV_IDENTITY'} elseif (Test-SbSignal -Evidence $Evidence -Signal 'android-tv-identity') {$distribution='AndroidTV';Add-SbDiscoveryReason $reasons 'DISCOVERY_ANDROID_TV_IDENTITY'} else {$distribution='AndroidX86'}
    } elseif ($androidSystem -or $androidCategories.Count -ge 2) {
        $family='Android'; $distribution='UnknownAndroidLike'; $confidence='Possible'; Add-SbDiscoveryReason $reasons 'DISCOVERY_UNKNOWN_ANDROID_LIKE'
    } elseif ($chromeRoot -and $chromeLayout -and $fyde) {
        $family='ChromeOSStyle'; $distribution='FydeOS'; $confidence='Confirmed'; Add-SbDiscoveryReason $reasons 'DISCOVERY_FYDEOS_IDENTITY'
    } elseif ($chromeRoot -and $chromeLayout) {
        $family='ChromeOSStyle'; $distribution='ChromeOSStyle'; $confidence='Probable'; Add-SbDiscoveryReason $reasons 'DISCOVERY_CHROMEOS_STYLE'
    } elseif ($chromeRoot -or $chromeLayout) {
        $family='ChromeOSStyle'; $distribution='UnknownChromeOSLike'; $confidence='Possible'; Add-SbDiscoveryReason $reasons 'DISCOVERY_UNKNOWN_CHROMEOS_LIKE'
    } elseif (Test-SbSignal -Evidence $Evidence -Signal 'valid-efi-loader') {
        $distribution='UnknownUEFI'; Add-SbDiscoveryReason $reasons 'DISCOVERY_UNKNOWN_UEFI'
    } else { Add-SbDiscoveryReason $reasons 'DISCOVERY_UNKNOWN_BOOTABLE' }
    $positive = @($Evidence | Where-Object { $_.Accessibility -eq 'Accessible' -and $_.Polarity -eq 'Positive' })
    if (@('ntfs','microsoft-basic-data','windows-directory-name','bootmgfw-path','microsoft-efi-path') | Where-Object { Test-SbSignal -Evidence $Evidence -Signal $_ }) { Add-SbDiscoveryReason $reasons 'DISCOVERY_WINDOWS_WEAK_EVIDENCE' }
    if (Test-SbNegativeSignal -Evidence $Evidence -Signal 'windows-root-negative') { Add-SbDiscoveryReason $reasons 'DISCOVERY_WINDOWS_NEGATIVE_EVIDENCE' }
    if ($positive.Count -gt 0 -and @($positive | Where-Object { $_.TrustTier -ne 'Weak' }).Count -eq 0) {
        $family='Unknown'; $distribution=if(Test-SbSignal -Evidence $Evidence -Signal 'linux-filesystem'){'UnknownLinux'}else{'UnknownBootable'}; $confidence='Unknown'; Add-SbDiscoveryReason $reasons 'DISCOVERY_WEAK_ONLY_EVIDENCE'
    }
    if ((Test-SbSignal -Evidence $Evidence -Signal 'efi-ubuntu') -and $distribution -ne 'Ubuntu') { Add-SbDiscoveryReason $reasons 'DISCOVERY_UBUNTU_FAMILY_AMBIGUITY' }
    return [pscustomobject]@{Family=$family;Distribution=$distribution;Confidence=$confidence;Version='';ReasonCodes=$reasons.ToArray()}
}

function Get-SbPresentationDecision {
    param([SbOsDistribution]$Distribution,[SbConfidenceLevel]$Confidence,[SbOsStaleState]$Stale,[SbOsAmbiguousState]$Ambiguous,[SbEvidenceGraphNode[]]$Relations)
    $labels=@{Windows='Windows';Zorin='Zorin OS';Ubuntu='Ubuntu';Fedora='Fedora';Debian='Debian';GenericLinux='Linux';UnknownLinux='Unknown Linux';AndroidX86='Android';AndroidTV='Android TV';GoogleTV='Google TV';FydeOS='FydeOS';ChromeOSStyle='ChromeOS-style';UnknownChromeOSLike='Unknown ChromeOS-like';UnknownAndroidLike='Unknown Android-like';UnknownUEFI='Unknown UEFI OS';UnknownBootable='Unknown bootable system'}
    $icons=@{Windows='windows';Zorin='zorin';Ubuntu='ubuntu';Fedora='fedora';Debian='debian';GenericLinux='linux';UnknownLinux='linux';AndroidX86='android';AndroidTV='android';GoogleTV='google-tv';FydeOS='fydeos';ChromeOSStyle='unknown-uefi';UnknownChromeOSLike='unknown-uefi';UnknownAndroidLike='android';UnknownUEFI='unknown-uefi';UnknownBootable='unknown-uefi'}
    $loaderIds=@($Relations|Where-Object{$null-ne$_-and$_.NodeType-eq'EfiLoader'}|ForEach-Object{Get-SbOpaqueId -Prefix 'candidate' -InputValue $_.NodeId}|Sort-Object)
    $primary=if($loaderIds.Count){$loaderIds[0]}else{''};$alternatives=if($loaderIds.Count-gt1){@($loaderIds|Select-Object -Skip 1)}else{@()}
    $warning=if($Stale-ne'Active'){'Stale'}elseif($Ambiguous-ne'None'){'Ambiguous'}elseif($Confidence-in@('Possible','Unknown','Invalid')){'Unclassified'}else{'None'}
    return [SbOsPresentationMetadata]::new($labels[$Distribution.ToString()],$icons[$Distribution.ToString()],$Confidence,$warning,$Stale,$Ambiguous,$primary,$alternatives)
}

function Invoke-SbSyntheticMultiOsDiscovery {
    [CmdletBinding()]
    [OutputType([SbOsDiscoveryResult])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][SbEvidenceRecord[]]$Evidence,
        [Parameter(Mandatory)][AllowEmptyCollection()][SbEvidenceGraphNode[]]$Nodes,
        [Parameter(Mandatory)][AllowEmptyCollection()][SbEvidenceGraphEdge[]]$Edges
    )
    Assert-SbSyntheticGraph -Evidence $Evidence -Nodes $Nodes -Edges $Edges
    $sortedNodes=@($Nodes|Sort-Object NodeId);$sortedEdges=@($Edges|Sort-Object EdgeId);$conflicts=[System.Collections.Generic.List[SbEvidenceConflict]]::new();$instances=[System.Collections.Generic.List[SbOsInstance]]::new()
    foreach($candidate in @($sortedNodes|Where-Object{$_.NodeType-eq'OsInstanceCandidate'})){
        $candidateEvidence=@(Get-SbCandidateEvidence -Candidate $candidate -Evidence $Evidence -Edges $sortedEdges)
        $relations=@(Get-SbCandidateRelations -Candidate $candidate -Nodes $sortedNodes -Edges $sortedEdges)
        $decision=Get-SbClassificationDecision -Evidence $candidateEvidence
        $family=[SbOsFamily]$decision.Family;$distribution=[SbOsDistribution]$decision.Distribution;$confidence=[SbConfidenceLevel]$decision.Confidence;$reasons=[System.Collections.Generic.List[string]]::new()
        foreach($code in [string[]]$decision.ReasonCodes){Add-SbDiscoveryReason $reasons $code}
        $roots=@($relations|Where-Object{$_.NodeType-eq'OsRootCandidate'});$loaders=@($relations|Where-Object{$_.NodeType-eq'EfiLoader'});$entries=@($relations|Where-Object{$_.NodeType-eq'BootEntry'});$esps=@($relations|Where-Object{$_.NodeType-eq'Esp'});$stale=[SbOsStaleState]::Active
        if(Test-SbSignal -Evidence $candidateEvidence -Signal 'missing-device'){$stale='MissingDevice';Add-SbDiscoveryReason $reasons 'DISCOVERY_MISSING_DEVICE'}
        elseif(@($sortedEdges|Where-Object{$_.EdgeType-eq'StaleReference'-and($_.FromNodeId-eq$candidate.NodeId-or$_.ToNodeId-eq$candidate.NodeId)}).Count){$stale='BrokenReference';Add-SbDiscoveryReason $reasons 'DISCOVERY_STALE';Add-SbDiscoveryReason $reasons 'DISCOVERY_BROKEN_REFERENCE'}
        elseif($roots.Count -gt 0 -and $loaders.Count -eq 0){$stale='RootOnly';Add-SbDiscoveryReason $reasons 'DISCOVERY_MISSING_LOADER'}
        elseif($loaders.Count -gt 0 -and $roots.Count -eq 0){$stale='LoaderOnly';Add-SbDiscoveryReason $reasons 'DISCOVERY_MISSING_ROOT'}
        elseif($entries.Count -gt 0 -and $roots.Count -eq 0 -and $loaders.Count -eq 0){$stale='EntryOnly';Add-SbDiscoveryReason $reasons 'DISCOVERY_MISSING_ROOT';Add-SbDiscoveryReason $reasons 'DISCOVERY_MISSING_LOADER'}
        elseif($candidateEvidence.Count -gt 0 -and @($candidateEvidence|Where-Object{$_.Freshness-eq'Unknown'}).Count -eq $candidateEvidence.Count){$stale='UnknownFreshness';Add-SbDiscoveryReason $reasons 'DISCOVERY_UNKNOWN_FRESHNESS'}
        $ambiguous=[SbOsAmbiguousState]::None
        if($roots.Count-gt1){$ambiguous='MultipleRoots';Add-SbDiscoveryReason $reasons 'DISCOVERY_AMBIGUOUS'}elseif($family-eq'Unknown'-and$confidence-eq'Possible'){$ambiguous='ConflictingFamily';Add-SbDiscoveryReason $reasons 'DISCOVERY_AMBIGUOUS'}elseif($loaders.Count-gt1){$ambiguous='MultipleLoaders'}
        foreach($edge in @($sortedEdges|Where-Object{$_.EdgeType-eq'ConflictsWith'-and($_.FromNodeId-eq$candidate.NodeId-or$_.ToNodeId-eq$candidate.NodeId)})){$ambiguous='ConflictingFamily';Add-SbDiscoveryReason $reasons 'DISCOVERY_CONFLICT';$conflicts.Add([SbEvidenceConflict]::new((Get-SbOpaqueId -Prefix 'conflict' -InputValue $edge.EdgeId),$edge.EvidenceIds,'DISCOVERY_CONFLICT'))}
        foreach($edge in @($sortedEdges|Where-Object{$_.EdgeType-eq'RelatedButDistinct'-and($_.FromNodeId-eq$candidate.NodeId-or$_.ToNodeId-eq$candidate.NodeId)})){Add-SbDiscoveryReason $reasons 'DISCOVERY_SHARED_LOADER'}
        if(Test-SbSignal -Evidence $candidateEvidence -Signal 'cross-disk-correlation'){Add-SbDiscoveryReason $reasons 'DISCOVERY_CROSS_DISK_CORRELATION'}
        $instance=[SbOsInstance]::new();$instance.OsInstanceId=Get-SbOpaqueId -Prefix 'os' -InputValue $candidate.NodeId;$instance.Family=$family;$instance.Distribution=$distribution;$instance.Version=$decision.Version;$instance.Confidence=$confidence;$instance.ReasonCodes=@($reasons|Sort-Object);$instance.RootPartitionId=if($roots.Count){Get-SbOpaqueId -Prefix 'root' -InputValue $roots[0].NodeId}else{''};$instance.AssociatedEspIds=@($esps|ForEach-Object{Get-SbOpaqueId -Prefix 'esp' -InputValue $_.NodeId}|Sort-Object);$instance.AssociatedLoaderIds=@($loaders|ForEach-Object{Get-SbOpaqueId -Prefix 'loader' -InputValue $_.NodeId}|Sort-Object);$instance.AssociatedBootEntryIds=@($entries|ForEach-Object{Get-SbOpaqueId -Prefix 'entry' -InputValue $_.NodeId}|Sort-Object);$instance.EvidenceIds=@($candidateEvidence|ForEach-Object{$_.EvidenceId.Value}|Sort-Object);$instance.StaleState=$stale;$instance.AmbiguousState=$ambiguous;$instance.Warnings=@($instance.ReasonCodes|Where-Object{$_-match'CONFLICT|AMBIGUOUS|STALE|MISSING|WEAK'});$instance.PresentationMetadata=Get-SbPresentationDecision -Distribution $distribution -Confidence $confidence -Stale $stale -Ambiguous $ambiguous -Relations $relations;$instance.PrimaryBootCandidate=$instance.PresentationMetadata.PrimaryCandidate;$instances.Add($instance)
    }
    $result=[SbOsDiscoveryResult]::new();$result.Nodes=$sortedNodes;$result.Edges=$sortedEdges;$result.Conflicts=@($conflicts|Sort-Object ConflictId);$result.OsInstances=@($instances|Sort-Object OsInstanceId);return $result
}

function ConvertTo-SbDiscoveryJson {param([Parameter(Mandatory)][SbOsDiscoveryResult]$Result);return ($Result|ConvertTo-Json -Depth 20 -Compress)}

Export-ModuleMember -Function Invoke-SbSyntheticMultiOsDiscovery,ConvertTo-SbDiscoveryJson,Get-SbClassificationDecision
