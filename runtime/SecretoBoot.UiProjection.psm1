Set-StrictMode -Version Latest

function ConvertTo-SbUiSafeValue {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory)][string]$Fallback,
        [int]$MaximumLength = 64
    )

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text) -or $text.Length -gt $MaximumLength -or $text -notmatch '^[A-Za-z0-9 ._+/-]+$') {
        return $Fallback
    }
    return $text
}

function ConvertTo-SbConsolidatedSystems {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$DetectedSystems,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Evidence,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Correlations
    )

    if ($DetectedSystems.Count -gt 4096) { throw 'UI_CONSOLIDATION_RESOURCE_CAP_EXCEEDED' }
    $byId = @{}
    foreach ($system in $DetectedSystems) {
        $id = [string]$system.SystemId
        if ([string]::IsNullOrWhiteSpace($id) -or $byId.ContainsKey($id)) { throw 'UI_CONSOLIDATION_SYSTEM_ID_DENIED' }
        $byId[$id] = $system
    }

    $evidenceIds = @{}
    foreach ($item in $Evidence) {
        $id = [string]$item.EvidenceId
        if ([string]::IsNullOrWhiteSpace($id) -or $evidenceIds.ContainsKey($id)) { throw 'UI_CONSOLIDATION_EVIDENCE_ID_DENIED' }
        $evidenceIds[$id] = $true
    }

    $edges = @{}
    foreach ($id in $byId.Keys) { $edges[$id] = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal) }
    foreach ($group in @($Correlations | Group-Object EvidenceId)) {
        if (-not $evidenceIds.ContainsKey([string]$group.Name)) { continue }
        $links = @($group.Group | Where-Object {
            $_.Relationship -ceq 'Corroborates' -and $_.RootPartitionResolved -eq $true -and $byId.ContainsKey([string]$_.SystemId)
        } | ForEach-Object { [string]$_.SystemId } | Sort-Object -Unique)
        if ($links.Count -lt 2) { continue }
        $presentations = @($links | ForEach-Object {
            $s = $byId[$_]
            '{0}|{1}|{2}' -f $s.Family, $s.Distribution, $s.Confidence
        } | Sort-Object -Unique)
        if ($presentations.Count -ne 1) { continue }
        foreach ($left in $links) { foreach ($right in $links) { if ($left -cne $right) { [void]$edges[$left].Add($right) } } }
    }

    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $output = [Collections.Generic.List[object]]::new()
    foreach ($start in @($byId.Keys | Sort-Object)) {
        if ($seen.Contains($start)) { continue }
        $pending = [Collections.Generic.Stack[string]]::new(); $pending.Push($start)
        $members = [Collections.Generic.List[string]]::new()
        while ($pending.Count) {
            $current = $pending.Pop()
            if (-not $seen.Add($current)) { continue }
            $members.Add($current)
            foreach ($next in $edges[$current]) { $pending.Push($next) }
        }
        $memberSystems = @($members | Sort-Object | ForEach-Object { $byId[$_] })
        $first = $memberSystems[0]
        $filesystems = @($memberSystems | ForEach-Object { [string]$_.Filesystem } | Where-Object { $_ } | Sort-Object -Unique)
        $memberIds = @($memberSystems | ForEach-Object { [string]$_.SystemId })
        $proof = @($Correlations | Where-Object { [string]$_.SystemId -in $memberIds } | ForEach-Object { [string]$_.EvidenceId } | Where-Object { $evidenceIds.ContainsKey($_) } | Group-Object | Where-Object Count -ge $memberIds.Count | ForEach-Object Name | Sort-Object -Unique)
        $output.Add([pscustomobject][ordered]@{
            ConsolidatedSystemId = 'consolidated:' + ($memberIds -join '+')
            Family = $first.Family
            Distribution = $first.Distribution
            Confidence = $first.Confidence
            Filesystem = if ($filesystems.Count) { $filesystems -join ' + ' } else { 'Unknown' }
            NeedsStrongerEvidence = @($memberSystems | Where-Object NeedsStrongerEvidence -eq $true).Count -gt 0
            CandidateReferences = @($memberSystems | ForEach-Object { [pscustomobject]@{ SystemId=$_.SystemId; PartitionId=$_.PartitionId; CandidateKind=$_.CandidateKind } })
            EvidenceReferences = $proof
            ConsolidationStatus = if ($memberSystems.Count -gt 1) { 'ConsolidatedBySharedCorrelatedEvidence' } else { 'KeptSeparateInsufficientProof' }
        })
    }
    return $output.ToArray()
}

function ConvertTo-SbUiDiscoveryProtocol {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$DiscoveryResult)

    if ($DiscoveryResult.DynamicCollection -ne $true -or 'DetectedSystems' -notin $DiscoveryResult.PSObject.Properties.Name) {
        throw 'UI_DISCOVERY_CONTRACT_DENIED'
    }

    $candidates = @($DiscoveryResult.DetectedSystems)
    if ($candidates.Count -gt 4096) { throw 'UI_DISCOVERY_RESOURCE_CAP_EXCEEDED' }

    $evidenceCount = @($DiscoveryResult.Evidence).Count
    $correlationCount = @($DiscoveryResult.Correlations).Count
    $systems = @(ConvertTo-SbConsolidatedSystems -DetectedSystems $candidates -Evidence @($DiscoveryResult.Evidence) -Correlations @($DiscoveryResult.Correlations))
    if (-not (Get-Command ConvertTo-SbBootEntries -ErrorAction SilentlyContinue) -or -not (Get-Command Resolve-SbCanonicalBootTargets -ErrorAction SilentlyContinue)) { throw 'UI_BOOT_PREVIEW_MODULE_REQUIRED' }
    $canonicalTargets = @(Resolve-SbCanonicalBootTargets -ConsolidatedSystems $systems -Evidence @($DiscoveryResult.Evidence) -Correlations @($DiscoveryResult.Correlations))
    $bootEntries = @(ConvertTo-SbBootEntries -ConsolidatedSystems $systems -CanonicalBootTargets $canonicalTargets)
    $configPreview = New-SbRefindConfigPreview -BootEntries $bootEntries
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add('SBUI1')
    $lines.Add(("STATUS`t{0}" -f (ConvertTo-SbUiSafeValue $DiscoveryResult.Status 'Unknown' 16)))
    $lines.Add(("SUMMARY`t{0}`t{1}`t{2}`t{3}" -f $candidates.Count, $systems.Count, $evidenceCount, $correlationCount))

    foreach ($system in $systems) {
        $family = ConvertTo-SbUiSafeValue $system.Family 'Unknown'
        $distribution = ConvertTo-SbUiSafeValue $system.Distribution 'Unknown'
        $confidence = ConvertTo-SbUiSafeValue $system.Confidence 'Unknown' 32
        $filesystem = ConvertTo-SbUiSafeValue $system.Filesystem 'Unknown' 32
        $detectionStatus = if ($system.NeedsStrongerEvidence -eq $true) { 'Needs stronger evidence' } else { 'Detected' }
        $lines.Add(("SYSTEM`t{0}`t{1}`t{2}`t{3}`t{4}" -f $family, $distribution, $confidence, $filesystem, $detectionStatus))
    }

    $readyCount = @($bootEntries | Where-Object IsBootReady -eq $true).Count
    $lines.Add(("BOOTSUMMARY`t{0}`t{1}`t{2}" -f $readyCount, ($bootEntries.Count - $readyCount), $configPreview.Status))
    foreach ($entry in $bootEntries) {
        $displayName = ConvertTo-SbUiSafeValue $entry.DisplayName 'Unknown system'
        $family = ConvertTo-SbUiSafeValue $entry.Family 'Unknown'
        $confidence = ConvertTo-SbUiSafeValue $entry.Confidence 'Unknown' 32
        $icon = ConvertTo-SbUiSafeValue $entry.IconKind 'Unknown' 16
        $status = if ($entry.IsBootReady -eq $true) { 'Ready' } else { 'Needs boot evidence' }
        $methodValue = if([string]$entry.BootMethod-ceq'AndroidInitrdRuntimeDiscovery'){'Android initrd runtime discovery'}else{$entry.BootMethod}
        $method = ConvertTo-SbUiSafeValue $methodValue 'NotAssigned' 32
        $lines.Add(("BOOTENTRY`t{0}`t{1}`t{2}`t{3}`t{4}`t{5}" -f $displayName, $family, $confidence, $icon, $status, $method))
    }
    if ('DiagnosticReport' -in $DiscoveryResult.PSObject.Properties.Name) {
        $diagnosticBytes = [Text.Encoding]::UTF8.GetBytes([string]$DiscoveryResult.DiagnosticReport)
        if ($diagnosticBytes.Length -gt 262144) { throw 'UI_DIAGNOSTIC_REPORT_CAP_EXCEEDED' }
        $lines.Add('DIAGREPORT' + "`t" + [Convert]::ToBase64String($diagnosticBytes))
    }
    if ('RefindSetupReport' -in $DiscoveryResult.PSObject.Properties.Name) {
        $setupBytes = [Text.Encoding]::UTF8.GetBytes([string]$DiscoveryResult.RefindSetupReport)
        if ($setupBytes.Length -gt 262144) { throw 'UI_REFIND_SETUP_REPORT_CAP_EXCEEDED' }
        $lines.Add('REFINDSETUPREPORT' + "`t" + [Convert]::ToBase64String($setupBytes))
    }
    if ('EndToEndPlan' -in $DiscoveryResult.PSObject.Properties.Name) {
        $planBytes=[Text.Encoding]::UTF8.GetBytes(($DiscoveryResult.EndToEndPlan|ConvertTo-Json -Depth 16 -Compress))
        if($planBytes.Length-gt1048576){throw 'UI_END_TO_END_PLAN_CAP_EXCEEDED'}
        $lines.Add('ENDTOENDPLAN' + "`t" + [Convert]::ToBase64String($planBytes))
        $lines.Add('DEPLOYABLE' + "`t" + $(if($DiscoveryResult.EndToEndPlan.Deployable){'1'}else{'0'}))
        foreach($candidate in @($DiscoveryResult.EndToEndPlan.ManualConfirmationCandidates)){
            $id=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$candidate.CandidateId));$loader=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$candidate.LoaderPath));$guid=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$candidate.PartitionGuid))
            $lines.Add(('MANUALCANDIDATE`t{0}`t{1}`t{2}`t{3}`t{4}`t{5}`t{6}`t{7}`t{8}'-f$id,(ConvertTo-SbUiSafeValue $candidate.FamilyHint 'Unknown' 16),[int]$candidate.DiskNumber,[int]$candidate.PartitionNumber,(ConvertTo-SbUiSafeValue $candidate.Filesystem 'Unknown' 16),[long]$candidate.SizeBytes,$loader,(ConvertTo-SbUiSafeValue $candidate.DisplayName 'Unknown UEFI loader' 80),$guid))
        }
    }

    return $lines.ToArray()
}

Export-ModuleMember -Function ConvertTo-SbConsolidatedSystems, ConvertTo-SbUiDiscoveryProtocol
