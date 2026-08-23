Set-StrictMode -Version Latest
$script:AccessPathInventoryCount=0
function Get-SbAndroidAccessPathInventoryCount{return $script:AccessPathInventoryCount}
function Invoke-SbAndroidAccessPathInventory{
 [CmdletBinding()]param([Parameter(Mandatory)][object]$Manifest)
 if($Manifest.SchemaVersion-cne'v9androidaccessibleexecution1'-or$Manifest.FeatureGateState-ne$true-or$Manifest.ExplicitConsent-ne$true-or$Manifest.OrdinaryVolumeReadAccess-ne$true-or$Manifest.EfiAccess-ne$false-or$Manifest.Mounts-ne$false-or$Manifest.DriveLetterAssignment-ne$false-or$Manifest.Writes-ne$false){throw 'ANDROID_ACCESS_PATH_GATE_DENIED'}
 if(-not[Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)){throw 'ANDROID_ACCESS_PATH_PLATFORM_DENIED'}
 $pipeline=[PowerShell]::Create();$null=$pipeline.AddCommand('Storage\Get-Partition').AddCommand('Microsoft.PowerShell.Utility\Select-Object').AddParameter('First',4097);$script:AccessPathInventoryCount++
 try{$async=$pipeline.BeginInvoke();if(-not$async.AsyncWaitHandle.WaitOne(10000)){$pipeline.Stop();throw 'ANDROID_ACCESS_PATH_TIMEOUT'};$items=@($pipeline.EndInvoke($async));if($pipeline.HadErrors-or$items.Count-gt4096){throw 'ANDROID_ACCESS_PATH_INVENTORY_DENIED'};$results=[Collections.Generic.List[object]]::new();foreach($item in $items){if([string]$item.GptType-match'(?i)C12A7328-F81F-11D2-BA4B-00A0C93EC93B'){continue};[guid]$partition=[guid]::Empty;if(-not[guid]::TryParse([string]$item.Guid,[ref]$partition)){continue};$paths=[Collections.Generic.List[string]]::new();foreach($path in @($item.AccessPaths)){if([string]$path-match'(?i)^\\\\\?\\Volume\{([0-9a-f-]{36})\}\\$'){[guid]$volume=[guid]::Empty;if([guid]::TryParse($Matches[1],[ref]$volume)){$paths.Add($volume.ToString('D').ToLowerInvariant())}}};$results.Add([pscustomobject][ordered]@{PartitionGuid=$partition.ToString('D').ToUpperInvariant();VolumeGuids=@($paths|Sort-Object -Unique)})};return $results.ToArray()}finally{$pipeline.Dispose()}
}
Export-ModuleMember -Function Get-SbAndroidAccessPathInventoryCount,Invoke-SbAndroidAccessPathInventory
