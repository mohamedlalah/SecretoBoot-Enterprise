using module ../Common/SecretoBoot.Common.psm1
using module ./SecretoBoot.MultiOsDiscovery.psm1

Set-StrictMode -Version Latest

function Get-SbAndroidEvidenceSuffix([string]$Value){
    $bytes=[Text.Encoding]::UTF8.GetBytes($Value);$hash=[Security.Cryptography.SHA256]::HashData($bytes)
    return [Convert]::ToHexString($hash).Substring(0,20).ToLowerInvariant()
}

function New-SbAndroidEvidenceRecord {
    param([string]$PartitionId,[string]$EvidenceId,[string]$Signal,[string]$RelativePath)
    $trust=if($Signal-in@('android-system-image','android-build-identity','android-tv-identity','google-tv-identity')){'Strong'}else{'Medium'}
    $suffix=Get-SbAndroidEvidenceSuffix "$PartitionId|$EvidenceId|$Signal"
    $subject=[SbEvidenceSubject]::new("node:android.$suffix",[SbEvidenceSubjectType]::OsRootCandidate)
    $reason=[SbEvidenceReason]::new('DISCOVERY_ANDROID_ACCESSIBLE_VOLUME_EVIDENCE','bounded exact-path ordinary-volume evidence')
    return [SbEvidenceRecord]::new("ev:android.$suffix",[SbEvidenceSourceLayer]::OsRootEvidence,[SbEvidenceTrustTier]$trust,[SbEvidencePolarity]::Positive,[SbEvidenceAccessibility]::Accessible,[SbEvidenceFreshness]::Current,$subject,$Signal,'',"android:$RelativePath",@($reason))
}

function ConvertTo-SbMultiOsAndroidEvidenceReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$MvpReport,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$InspectionResults
    )
    if([string]$MvpReport.SchemaVersion-cne'v9multiosmvp1'-or$MvpReport.DynamicCollection-ne$true){throw 'ANDROID_MVP_REPORT_DENIED'}
    $systems=[Collections.Generic.List[object]]::new();foreach($system in @($MvpReport.DetectedSystems)){$systems.Add($system)}
    $evidenceOut=[Collections.Generic.List[object]]::new();$correlations=[Collections.Generic.List[object]]::new();$denied=[Collections.Generic.List[object]]::new()
    $opens=0;$reads=0;$bytes=0
    foreach($result in @($InspectionResults)){
        if('PartitionId'-notin$result.PSObject.Properties.Name-or[string]$result.PartitionId-notmatch'^report:partition:[0-9a-f]{20}$'){throw 'ANDROID_RESULT_PARTITION_IDENTITY_MISSING'}
        $partitionId=[string]$result.PartitionId
        $opens+=[int]$result.NativeOpenOperations;$reads+=[int]$result.BoundedReadOperations;$bytes+=[long]$result.BytesRead
        $matches=@($systems|Where-Object{$_.CandidateKind-eq'PartitionCandidate'-and$_.PartitionId-ceq$partitionId})
        if($matches.Count-ne1){throw 'ANDROID_RESULT_PARTITION_CORRELATION_DENIED'}
        if([string]$result.Status-cne'Complete'){$diagnostic=if('DiagnosticReasonCode'-in$result.PSObject.Properties.Name){[string]$result.DiagnosticReasonCode}else{''};$denied.Add([pscustomobject][ordered]@{PartitionId=$partitionId;ReasonCode=[string]$result.ReasonCode;DiagnosticReasonCode=$diagnostic});continue}
        $records=[Collections.Generic.List[SbEvidenceRecord]]::new()
        foreach($artifact in @($result.Evidence)){
            $safePath=([string]$artifact.RelativePath).Replace('\','/').ToLowerInvariant()
            foreach($signal in @($artifact.Signals|Sort-Object -Unique)){
                $record=New-SbAndroidEvidenceRecord -PartitionId $partitionId -EvidenceId ([string]$artifact.EvidenceId) -Signal ([string]$signal) -RelativePath $safePath
                $records.Add($record)
            }
            $evidenceOut.Add([pscustomobject][ordered]@{EvidenceId=[string]$artifact.EvidenceId;PartitionId=$partitionId;RelativePath=$safePath;Kind=[string]$artifact.Kind;Signals=@($artifact.Signals|Sort-Object -Unique);SizeBytes=[long]$artifact.SizeBytes})
        }
        $decision=Get-SbClassificationDecision -Evidence $records.ToArray()
        if($decision.Family.ToString()-eq'Android'){
            $old=$matches[0];$index=$systems.IndexOf($old)
            $updated=[pscustomobject][ordered]@{
                SystemId=$old.SystemId;CandidateKind=$old.CandidateKind;PartitionId=$old.PartitionId;DiskId=$old.DiskId
                Family=$decision.Family.ToString();Distribution=$decision.Distribution.ToString();Confidence=$decision.Confidence.ToString()
                PartitionType=$old.PartitionType;Filesystem=$old.Filesystem;FilesystemAccessibility='BoundedReadOnlyAndroidEvidence'
                EvidenceBasis=@($evidenceOut|Where-Object PartitionId -CEQ $partitionId|ForEach-Object EvidenceId|Sort-Object -Unique)
                ReasonCodes=@($decision.ReasonCodes);NeedsStrongerEvidence=($decision.Confidence.ToString()-ne'Confirmed')
            }
            $systems[$index]=$updated
            foreach($item in @($evidenceOut|Where-Object PartitionId -CEQ $partitionId)){$correlations.Add([pscustomobject][ordered]@{EvidenceId=$item.EvidenceId;SystemId=$updated.SystemId;Relationship='Corroborates';Confidence=$updated.Confidence;RootPartitionResolved=$true})}
        }
    }
    return [pscustomobject][ordered]@{
        SchemaVersion='v9androidaccessiblemvp1';Status=if($denied.Count){'PARTIAL'}else{'PASS'};DynamicCollection=$true
        DetectedSystems=$systems.ToArray();Evidence=$evidenceOut.ToArray();Correlations=$correlations.ToArray();DeniedInspections=$denied.ToArray()
        Counts=[pscustomobject][ordered]@{DetectedSystems=$systems.Count;Evidence=$evidenceOut.Count;Correlations=$correlations.Count;Inspections=@($InspectionResults).Count}
        SafetyCounters=[pscustomobject][ordered]@{Level1InventoryOperations=6;AccessPathInventoryOperations=1;OrdinaryVolumeNativeOpenOperations=$opens;OrdinaryVolumeBoundedReadOperations=$reads;OrdinaryVolumeBytesRead=$bytes;DirectoryEnumerations=0;EfiOperations=0;BcdOperations=0;NvramOperations=0;SecureBootOperations=0;BootOrderOperations=0;MountOperations=0;DriveLetterAssignments=0;PartitionWrites=0;BootStateWrites=0;NetworkOperations=0;RefindOperations=0}
    }
}

Export-ModuleMember -Function ConvertTo-SbMultiOsAndroidEvidenceReport
