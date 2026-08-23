using module ./SecretoBoot.WindowsLevel1.Models.psm1

Set-StrictMode -Version Latest

function Test-SbExactMembers {
    param([object]$Value,[string[]]$Allowed)
    if($null -eq $Value){return $false}
    return @($Value.PSObject.Properties.Name|Where-Object{$_ -notin $Allowed}).Count -eq 0
}
function Test-SbGuidText { param([object]$Value) [guid]$g=[guid]::Empty; return $null -ne $Value -and [guid]::TryParse([string]$Value,[ref]$g) }
function Format-SbGuidText { param([object]$Value) return ([guid]([string]$Value)).ToString('D').ToUpperInvariant() }

function ConvertFrom-SbWindowsLevel1Payload {
    [CmdletBinding()]
    [OutputType([SbLevel1ParseResult])]
    param([Parameter(Mandatory)][object]$Payload)
    $diagnostics=[Collections.Generic.List[SbLevel1Diagnostic]]::new(); $inventory=[SbLevel1Inventory]::new()
    try{
        if(-not (Test-SbExactMembers $Payload @('platform','osVersion','architecture','firmwareMode','disks','partitions'))){throw 'unexpected payload member'}
        if($Payload.platform -ne 'Windows'){
            $diagnostics.Add([SbLevel1Diagnostic]::new('LEVEL1_PLATFORM_DENIED','Fixture platform is not Windows.','parser'))
            return [SbLevel1ParseResult]::new($inventory,$diagnostics.ToArray(),[SbLevel1ResultStatus]::Rejected)
        }
        $inventory.Platform='Windows';$inventory.OSVersion=[string]$Payload.osVersion;$inventory.Architecture=if($null -eq $Payload.architecture){'Unknown'}else{[string]$Payload.architecture}
        $firmwareProperty=$Payload.PSObject.Properties['firmwareMode'];$inventory.FirmwareMode=if($null-eq$firmwareProperty-or$null-eq$firmwareProperty.Value){'Unknown'}else{[string]$firmwareProperty.Value}
        if([string]::IsNullOrWhiteSpace($inventory.OSVersion) -or $inventory.Architecture -eq 'Unknown'){$diagnostics.Add([SbLevel1Diagnostic]::new('LEVEL1_PLATFORM_METADATA_MISSING','Optional OS version or architecture metadata is unavailable.','parser'))}
        if(-not [string]::IsNullOrWhiteSpace($inventory.OSVersion) -and $inventory.OSVersion -notmatch '^(10|11)\.'){$diagnostics.Add([SbLevel1Diagnostic]::new('LEVEL1_WINDOWS_VERSION_UNSUPPORTED','Windows version is outside the fixture-tested policy.','parser'))}
        $disks=@($Payload.disks);$partitions=@($Payload.partitions)
        if($disks.Count -gt 256 -or $partitions.Count -gt 4096){throw 'inventory exceeds safety limit'}
        $seenDisks=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$diskResults=[Collections.Generic.List[SbLevel1DiskRecord]]::new()
        foreach($raw in $disks){
            if(-not (Test-SbExactMembers $raw @('diskGuid','number','sizeBytes','isOffline','isReadOnly','isRemovable'))){throw 'unexpected disk member'}
            if(-not (Test-SbGuidText $raw.diskGuid)){$diagnostics.Add([SbLevel1Diagnostic]::new('LEVEL1_DISK_GUID_MISSING','Disk lacks a valid GPT identity.','parser'));continue}
            $guid=Format-SbGuidText $raw.diskGuid;if(-not $seenDisks.Add($guid)){$diagnostics.Add([SbLevel1Diagnostic]::new('LEVEL1_DUPLICATE_GUID','Duplicate disk GUID was rejected.','parser'));continue}
            $record=[SbLevel1DiskRecord]::new();$record.DiskGuid=$guid;$record.CanonicalId=$guid
            if($null-ne$raw.number){$record.TransientDiskNumber=[int]$raw.number};if($null-ne$raw.sizeBytes){$record.SizeBytes=[long]$raw.sizeBytes}
            if($null-ne$raw.isOffline){$record.IsOffline=[bool]$raw.isOffline};if($null-ne$raw.isReadOnly){$record.IsReadOnly=[bool]$raw.isReadOnly};if($null-ne$raw.isRemovable){$record.IsRemovable=[bool]$raw.isRemovable}
            $diskResults.Add($record)
        }
        $seenPartitions=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$partitionResults=[Collections.Generic.List[SbLevel1PartitionRecord]]::new()
        foreach($raw in $partitions){
            if(-not (Test-SbExactMembers $raw @('diskGuid','partitionGuid','partitionTypeGuid','diskNumber','partitionNumber','filesystem','label','sizeBytes','mounted','devicePathHint'))){throw 'unexpected partition member'}
            if(-not(Test-SbGuidText $raw.diskGuid)-or-not(Test-SbGuidText $raw.partitionGuid)-or-not(Test-SbGuidText $raw.partitionTypeGuid)){$diagnostics.Add([SbLevel1Diagnostic]::new('LEVEL1_PARTITION_GUID_MISSING','Partition lacks required GPT identity metadata.','parser'));continue}
            $diskGuid=Format-SbGuidText $raw.diskGuid;$partitionGuid=Format-SbGuidText $raw.partitionGuid;$canonical="$diskGuid`:$partitionGuid"
            if(-not $seenPartitions.Add($canonical)){$diagnostics.Add([SbLevel1Diagnostic]::new('LEVEL1_DUPLICATE_GUID','Duplicate partition GUID was rejected.','parser'));continue}
            $record=[SbLevel1PartitionRecord]::new();$record.DiskGuid=$diskGuid;$record.PartitionGuid=$partitionGuid;$record.PartitionTypeGuid=Format-SbGuidText $raw.partitionTypeGuid;$record.CanonicalId=$canonical
            if($null-ne$raw.diskNumber){$record.TransientDiskNumber=[int]$raw.diskNumber};if($null-ne$raw.partitionNumber){$record.TransientPartitionNumber=[int]$raw.partitionNumber}
            $record.Filesystem=[string]$raw.filesystem;$record.DisplayLabel=[string]$raw.label;$deviceProperty=$raw.PSObject.Properties['devicePathHint'];if($null-ne$deviceProperty){$record.TransientDevicePath=[string]$deviceProperty.Value};if($null-ne$raw.sizeBytes){$record.SizeBytes=[long]$raw.sizeBytes};if($null-ne$raw.mounted){$record.Mounted=[bool]$raw.mounted}
            $partitionResults.Add($record)
        }
        $inventory.Disks=$diskResults.ToArray();$inventory.Partitions=$partitionResults.ToArray();$inventory.Diagnostics=$diagnostics.ToArray()
        $status=if($diagnostics.Count){[SbLevel1ResultStatus]::Partial}else{[SbLevel1ResultStatus]::Success};$inventory.Status=$status
        return [SbLevel1ParseResult]::new($inventory,$diagnostics.ToArray(),$status)
    }catch{
        $diagnostics.Add([SbLevel1Diagnostic]::new('LEVEL1_PARSE_FAILURE','Synthetic parser input was malformed or exceeded limits.','parser'))
        return [SbLevel1ParseResult]::new($inventory,$diagnostics.ToArray(),[SbLevel1ResultStatus]::Rejected)
    }
}

function ConvertFrom-SbWindowsLevel1Json {
    [CmdletBinding()][OutputType([SbLevel1ParseResult])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Json)
    try{$payload=$Json|ConvertFrom-Json -Depth 30 -ErrorAction Stop;return ConvertFrom-SbWindowsLevel1Payload $payload}
    catch{return [SbLevel1ParseResult]::new([SbLevel1Inventory]::new(),@([SbLevel1Diagnostic]::new('LEVEL1_PARSE_FAILURE','JSON input was malformed.','parser')),[SbLevel1ResultStatus]::Rejected)}
}

Export-ModuleMember -Function ConvertFrom-SbWindowsLevel1Payload,ConvertFrom-SbWindowsLevel1Json
