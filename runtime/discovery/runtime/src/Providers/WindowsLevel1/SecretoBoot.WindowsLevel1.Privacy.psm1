using module ./SecretoBoot.WindowsLevel1.Models.psm1

Set-StrictMode -Version Latest

function New-SbLevel1PrivacyContext {
    [CmdletBinding()]
    param([byte[]]$Key)
    if($null -eq $Key){$Key=[byte[]]::new(32);$rng=[Security.Cryptography.RandomNumberGenerator]::Create();try{$rng.GetBytes($Key)}finally{$rng.Dispose()}}
    if($Key.Length -lt 32){throw 'Privacy key must contain at least 256 bits.'}
    return @{Key=[byte[]]$Key.Clone();ReportId=[guid]::NewGuid().ToString('D')}
}

function Protect-SbLevel1ReportValue {
    [CmdletBinding()][OutputType([string])]
    param([Parameter(Mandatory)][hashtable]$Context,[Parameter(Mandatory)][string]$Category,[AllowEmptyString()][string]$Value)
    $hmac=[Security.Cryptography.HMACSHA256]::new([byte[]]$Context.Key)
    try{$bytes=[Text.Encoding]::UTF8.GetBytes(('{0}:{1}' -f $Category.ToLowerInvariant(),$Value));$digest=[BitConverter]::ToString($hmac.ComputeHash($bytes)).Replace('-','').ToLowerInvariant().Substring(0,20)}finally{$hmac.Dispose()}
    return 'report:{0}:{1}' -f $Category.ToLowerInvariant(),$digest
}

function ConvertTo-SbLevel1SafeReport {
    [CmdletBinding()][OutputType([SbLevel1SafeReport])]
    param([Parameter(Mandatory)][SbLevel1Inventory]$Inventory,[hashtable]$PrivacyContext)
    if($null -eq $PrivacyContext){$PrivacyContext=New-SbLevel1PrivacyContext}
    $report=[SbLevel1SafeReport]::new();$report.ReportId=[string]$PrivacyContext.ReportId;$report.Platform=$Inventory.Platform;$report.OSVersion=$Inventory.OSVersion;$report.Architecture=$Inventory.Architecture;$report.FirmwareMode=$Inventory.FirmwareMode
    $report.DiskCount=$Inventory.Disks.Count;$report.PartitionCount=$Inventory.Partitions.Count
    $safeDisks=[Collections.Generic.List[SbLevel1SafeDiskReport]]::new()
    foreach($disk in $Inventory.Disks){$item=[SbLevel1SafeDiskReport]::new();$item.DiskGuidPseudonym=Protect-SbLevel1ReportValue $PrivacyContext 'disk' $disk.DiskGuid;$item.SizeBytes=$disk.SizeBytes;$item.OfflineState=$disk.IsOffline;$item.ReadOnlyState=$disk.IsReadOnly;$item.RemovableState=$disk.IsRemovable;$safeDisks.Add($item)}
    $safePartitions=[Collections.Generic.List[SbLevel1SafePartitionReport]]::new()
    foreach($partition in $Inventory.Partitions){$item=[SbLevel1SafePartitionReport]::new();$item.DiskGuidPseudonym=Protect-SbLevel1ReportValue $PrivacyContext 'disk' $partition.DiskGuid;$item.PartitionGuidPseudonym=Protect-SbLevel1ReportValue $PrivacyContext 'partition' $partition.PartitionGuid;$item.PartitionType=$partition.PartitionTypeGuid;$item.Filesystem=$partition.Filesystem;$item.SizeBytes=$partition.SizeBytes;$item.MountedState=$partition.Mounted;$safePartitions.Add($item)}
    $report.Disks=$safeDisks.ToArray();$report.Partitions=$safePartitions.ToArray();$report.Warnings=$Inventory.Diagnostics
    return $report
}

Export-ModuleMember -Function New-SbLevel1PrivacyContext,Protect-SbLevel1ReportValue,ConvertTo-SbLevel1SafeReport
