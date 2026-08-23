Set-StrictMode -Version Latest
$script:EfiAccessPathInventoryCount=0

function Get-SbEfiAccessPathInventoryCount{return $script:EfiAccessPathInventoryCount}

function ConvertTo-SbEfiVolumeGuidCandidates {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Objects)
    $results=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($item in $Objects){
        foreach($property in @('AccessPaths','Path','UniqueId','ObjectId')){
            if($null-eq$item-or$property-notin$item.PSObject.Properties.Name){continue}
            foreach($value in @($item.$property)){
                $text=[string]$value
                if($text-match'(?i)^\\\\\?\\Volume\{([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\}\\?$'){
                    $parsed=[guid]::Empty;if([guid]::TryParse($Matches[1],[ref]$parsed)-and$parsed-ne[guid]::Empty){[void]$results.Add($parsed.ToString('D').ToLowerInvariant())}
                }
            }
        }
    }
    return @($results|Sort-Object)
}

function Invoke-SbEfiAccessPathInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Manifest)
    if($Manifest.SchemaVersion-cne'v9multiosefiexecution1'-or$Manifest.FeatureGateState-ne$true-or$Manifest.ExplicitConsent-ne$true-or$Manifest.EfiReadAccess-ne$true-or$Manifest.Mounts-ne$false-or$Manifest.DriveLetterAssignment-ne$false-or$Manifest.EfiWrites-ne$false){throw 'EFI_ACCESS_PATH_GATE_DENIED'}
    if(-not[Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)){throw 'EFI_ACCESS_PATH_PLATFORM_DENIED'}
    $pipeline=[PowerShell]::Create();$null=$pipeline.AddCommand('Storage\Get-Partition').AddCommand('Microsoft.PowerShell.Utility\Select-Object').AddParameter('First',4097);$script:EfiAccessPathInventoryCount++;$timer=[Diagnostics.Stopwatch]::StartNew()
    try{
        $async=$pipeline.BeginInvoke();if(-not$async.AsyncWaitHandle.WaitOne(10000)){$pipeline.Stop();throw 'EFI_ACCESS_PATH_TIMEOUT'};$items=@($pipeline.EndInvoke($async));if($pipeline.HadErrors-or$items.Count-gt4096){throw 'EFI_ACCESS_PATH_INVENTORY_DENIED'}
        $results=[Collections.Generic.List[object]]::new()
        foreach($item in $items){
            if([string]$item.GptType-cne'{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}'-and[string]$item.GptType-cne'C12A7328-F81F-11D2-BA4B-00A0C93EC93B'){continue}
            [guid]$partitionGuid=[guid]::Empty;if(-not[guid]::TryParse([string]$item.Guid,[ref]$partitionGuid)){continue}
            $volumeObjects=[Collections.Generic.List[object]]::new();$volumeObjects.Add($item)
            if(-not@(ConvertTo-SbEfiVolumeGuidCandidates @($item)).Count-and$timer.ElapsedMilliseconds-lt10000){
                $volumePipeline=[PowerShell]::Create();$null=$volumePipeline.AddCommand('Storage\Get-Volume').AddParameter('Partition',$item);$script:EfiAccessPathInventoryCount++
                try{
                    $remaining=[Math]::Max(1,10000-[int]$timer.ElapsedMilliseconds);$volumeAsync=$volumePipeline.BeginInvoke()
                    if($volumeAsync.AsyncWaitHandle.WaitOne($remaining)){$associated=@($volumePipeline.EndInvoke($volumeAsync));if(-not$volumePipeline.HadErrors-and$associated.Count-le4){foreach($volume in $associated){$volumeObjects.Add($volume)}}}else{$volumePipeline.Stop()}
                }catch{}finally{$volumePipeline.Dispose()}
            }
            $paths=@(ConvertTo-SbEfiVolumeGuidCandidates $volumeObjects.ToArray())
            $results.Add([pscustomobject][ordered]@{PartitionGuid=$partitionGuid.ToString('D').ToUpperInvariant();VolumeGuids=$paths})
        }
        return $results.ToArray()
    }finally{$pipeline.Dispose()}
}

Export-ModuleMember -Function Get-SbEfiAccessPathInventoryCount,ConvertTo-SbEfiVolumeGuidCandidates,Invoke-SbEfiAccessPathInventory
