Set-StrictMode -Version Latest

function Test-SbSafeReportMembers {
    param([object]$Value,[string[]]$Allowed)
    return $null-ne$Value-and@($Value.PSObject.Properties.Name|Where-Object{$_ -notin $Allowed}).Count-eq 0
}

function Find-SbUnexpectedGuidValue {
    param([object]$Value,[string]$Path,[string]$GuidPattern)
    $hits=[Collections.Generic.List[string]]::new()
    if($null-eq$Value){return $hits.ToArray()}
    if($Value-is[string]){if($Value-match$GuidPattern-and$Path-notmatch'(\.ReportId|\.PartitionType)$'){$hits.Add($Path)};return $hits.ToArray()}
    if($Value-is[Collections.IDictionary]){foreach($key in $Value.Keys){foreach($hit in Find-SbUnexpectedGuidValue $Value[$key] "$Path.$key" $GuidPattern){$hits.Add($hit)}};return $hits.ToArray()}
    if($Value-is[Collections.IEnumerable]){foreach($item in $Value){foreach($hit in Find-SbUnexpectedGuidValue $item "$Path[]" $GuidPattern){$hits.Add($hit)}};return $hits.ToArray()}
    foreach($property in $Value.PSObject.Properties){foreach($hit in Find-SbUnexpectedGuidValue $property.Value "$Path.$($property.Name)" $GuidPattern){$hits.Add($hit)}};return $hits.ToArray()
}

function Test-SbWindowsLevel1SafeReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Report)
    $diagnostics=[Collections.Generic.List[string]]::new();$guidPattern='(?i)^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$';$pseudonymPattern='^report:(disk|partition):[0-9a-f]{20}$'
    if(-not(Test-SbSafeReportMembers $Report @('ReportId','Platform','OSVersion','Architecture','FirmwareMode','DiskCount','PartitionCount','Disks','Partitions','Warnings'))){$diagnostics.Add('REPORT_UNEXPECTED_FIELD')}
    if([string]$Report.ReportId-notmatch$guidPattern-or$Report.Platform-ne'Windows'){$diagnostics.Add('REPORT_HEADER_INVALID')}
    if(@($Report.Disks).Count-ne[int]$Report.DiskCount-or@($Report.Partitions).Count-ne[int]$Report.PartitionCount){$diagnostics.Add('REPORT_COUNT_MISMATCH')}
    foreach($disk in @($Report.Disks)){if(-not(Test-SbSafeReportMembers $disk @('DiskGuidPseudonym','SizeBytes','OfflineState','ReadOnlyState','RemovableState'))){$diagnostics.Add('REPORT_DISK_SHAPE_INVALID')}elseif([string]$disk.DiskGuidPseudonym-notmatch$pseudonymPattern){$diagnostics.Add('REPORT_RAW_DISK_ID_DENIED')}}
    foreach($partition in @($Report.Partitions)){if(-not(Test-SbSafeReportMembers $partition @('DiskGuidPseudonym','PartitionGuidPseudonym','PartitionType','Filesystem','SizeBytes','MountedState'))){$diagnostics.Add('REPORT_PARTITION_SHAPE_INVALID')}elseif([string]$partition.DiskGuidPseudonym-notmatch$pseudonymPattern-or[string]$partition.PartitionGuidPseudonym-notmatch$pseudonymPattern-or[string]$partition.PartitionType-notmatch$guidPattern){$diagnostics.Add('REPORT_RAW_PARTITION_ID_DENIED')}}
    foreach($warning in @($Report.Warnings)){if(-not(Test-SbSafeReportMembers $warning @('Code','Message','OperationId'))){$diagnostics.Add('REPORT_WARNING_SHAPE_INVALID')}}
    if(@(Find-SbUnexpectedGuidValue $Report '$' $guidPattern).Count){$diagnostics.Add('REPORT_RAW_GUID_VALUE_DENIED')}
    $text=$Report|ConvertTo-Json -Depth 20 -Compress;$forbidden='(?i)(diskGuid"|partitionGuid"|serial(number)?|host(name)?|user(name)?|user(profile)?path|[A-Z]:\\Users\\|/Users/|\\EFI\\|/EFI/|\bBCD\b|\bNVRAM\b|BootOrder|BootNext|Secure\s*Boot)'
    if($text-match$forbidden){$diagnostics.Add('REPORT_PRIVACY_LEAK_DENIED')}
    return [pscustomobject]@{Valid=($diagnostics.Count-eq 0);DiagnosticCodes=@($diagnostics|Sort-Object -Unique)}
}

Export-ModuleMember -Function Test-SbWindowsLevel1SafeReport
