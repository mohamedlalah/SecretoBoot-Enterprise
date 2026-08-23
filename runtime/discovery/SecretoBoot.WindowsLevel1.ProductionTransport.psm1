using module ./SecretoBoot.WindowsLevel1.Manifest.psm1

Set-StrictMode -Version Latest
$script:ProviderVersion='3B-A.1'
$script:ExecutionCount=0
$localLimitsPath=Join-Path $PSScriptRoot 'policy/windows-level1-limits.json'
$script:LimitsPath=if([IO.File]::Exists($localLimitsPath)){[IO.Path]::GetFullPath($localLimitsPath)}else{[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../config/windows-level1-limits.json'))}

function Get-SbProductionExecutionCount { return $script:ExecutionCount }
function Get-SbProductionLimits { [IO.File]::ReadAllText($script:LimitsPath)|ConvertFrom-Json -Depth 10 }

function New-SbProductionProvenance {
    param([string]$OperationId,[string]$StartTime)
    return [pscustomobject][ordered]@{OperationId=$OperationId;ProviderVersion=$script:ProviderVersion;AllowedByPolicy=$true;Platform='Windows';AccessLevel='HostMetadata';StartTime=$StartTime;DurationMilliseconds=0;Success=$false;ResultCount=0;Truncated=$false;DiagnosticCodes=@()}
}

function Complete-SbFixedInvocation {
    param([Parameter(Mandatory)][System.Management.Automation.PowerShell]$Pipeline,[Parameter(Mandatory)][IAsyncResult]$AsyncResult,[int]$TimeoutMilliseconds)
    try{
        if(-not $AsyncResult.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)){$Pipeline.Stop();return [pscustomobject]@{Success=$false;Data=@();Code='PRODUCTION_TIMEOUT'}}
        $data=@($Pipeline.EndInvoke($AsyncResult));if($Pipeline.HadErrors){return [pscustomobject]@{Success=$false;Data=@();Code='PRODUCTION_PROVIDER_ERROR'}}
        return [pscustomobject]@{Success=$true;Data=$data;Code=''}
    }catch{return [pscustomobject]@{Success=$false;Data=@();Code='PRODUCTION_PROVIDER_ERROR'}}finally{$Pipeline.Dispose()}
}

function Complete-SbProductionResult {
    param([object]$Provenance,[object[]]$Data,[string[]]$DiagnosticCodes,[datetime]$Started,[int]$MaximumRecords)
    $limits=Get-SbProductionLimits;$items=@($Data);$truncated=$items.Count-gt$MaximumRecords
    if($truncated){$items=@();$DiagnosticCodes=@($DiagnosticCodes+'PRODUCTION_RECORD_LIMIT')}
    $json=$items|ConvertTo-Json -Depth 10 -Compress
    if([Text.Encoding]::UTF8.GetByteCount($json)-gt[int]$limits.maximumSerializedOutputBytes){$items=@();$truncated=$true;$DiagnosticCodes=@($DiagnosticCodes+'PRODUCTION_OUTPUT_LIMIT')}
    $codes=@($DiagnosticCodes|Select-Object -First ([int]$limits.maximumDiagnosticEntries));$Provenance.DurationMilliseconds=[int]([datetime]::UtcNow-$Started).TotalMilliseconds;$Provenance.Success=$codes.Count-eq 0;$Provenance.ResultCount=$items.Count;$Provenance.Truncated=$truncated;$Provenance.DiagnosticCodes=$codes
    return [pscustomobject]@{Status=if($Provenance.Success){'Success'}else{'Failed'};Data=$items;Provenance=$Provenance;Diagnostics=$codes}
}

function Invoke-SbWindowsLevel1ProductionTransport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('platform.runtime','platform.environment','windows.os.cim','storage.disks','storage.partitions','storage.volumes')][string]$OperationId,[Parameter(Mandatory)][object]$ExecutionManifest)
    $started=[datetime]::UtcNow;$provenance=New-SbProductionProvenance $OperationId $started.ToString('o');$gate=Test-SbLevel1ExecutionManifest $ExecutionManifest
    if(-not $gate.Allowed-or$OperationId-notin@($ExecutionManifest.OperationsAllowed)-or$OperationId-notin@($ExecutionManifest.OperationsRequested)){$provenance.AllowedByPolicy=$false;$provenance.DiagnosticCodes=@('PRODUCTION_PREEXECUTION_DENIED');return [pscustomobject]@{Status='Rejected';Data=@();Provenance=$provenance;Diagnostics=$provenance.DiagnosticCodes}}
    if(-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)){$provenance.AllowedByPolicy=$false;$provenance.DiagnosticCodes=@('PRODUCTION_PLATFORM_DENIED');return [pscustomobject]@{Status='Rejected';Data=@();Provenance=$provenance;Diagnostics=$provenance.DiagnosticCodes}}
    $limits=Get-SbProductionLimits;$timeout=[int]$limits.operationTimeoutMilliseconds;$script:ExecutionCount++
    switch($OperationId){
        'platform.runtime'{
            $data=@([pscustomobject][ordered]@{platform='Windows';osDescription=[Runtime.InteropServices.RuntimeInformation]::OSDescription;architecture=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()})
            return Complete-SbProductionResult $provenance $data @() $started 1
        }
        'platform.environment'{
            $data=@([pscustomobject][ordered]@{osVersion=[Environment]::OSVersion.Version.ToString();is64BitOperatingSystem=[Environment]::Is64BitOperatingSystem})
            return Complete-SbProductionResult $provenance $data @() $started 1
        }
        'windows.os.cim'{
            $pipeline=[PowerShell]::Create();$null=$pipeline.AddCommand('CimCmdlets\Get-CimInstance').AddParameter('ClassName','Win32_OperatingSystem').AddParameter('Property',@('Caption','Version','BuildNumber','OSArchitecture')).AddParameter('OperationTimeoutSec',[Math]::Max(1,[int]($timeout/1000))).AddCommand('Microsoft.PowerShell.Utility\Select-Object').AddParameter('First',2)
            $result=Complete-SbFixedInvocation $pipeline $pipeline.BeginInvoke() $timeout;if(-not$result.Success){return Complete-SbProductionResult $provenance @() @($result.Code) $started ([int]$limits.maximumOsRecords)}
            $data=@($result.Data|ForEach-Object{[pscustomobject][ordered]@{caption=[string]$_.Caption;version=[string]$_.Version;buildNumber=[string]$_.BuildNumber;architecture=[string]$_.OSArchitecture}})
            return Complete-SbProductionResult $provenance $data @() $started ([int]$limits.maximumOsRecords)
        }
        'storage.disks'{
            $pipeline=[PowerShell]::Create();$null=$pipeline.AddCommand('Storage\Get-Disk').AddCommand('Microsoft.PowerShell.Utility\Select-Object').AddParameter('First',([int]$limits.maximumDiskRecords+1));$result=Complete-SbFixedInvocation $pipeline $pipeline.BeginInvoke() $timeout
            if(-not$result.Success){return Complete-SbProductionResult $provenance @() @($result.Code) $started ([int]$limits.maximumDiskRecords)}
            $data=@($result.Data|ForEach-Object{[pscustomobject][ordered]@{diskGuid=if($null-eq$_.Guid){$null}else{[string]$_.Guid};number=if($null-eq$_.Number){$null}else{[int]$_.Number};sizeBytes=if($null-eq$_.Size){$null}else{[long]$_.Size};isOffline=if($null-eq$_.IsOffline){$null}else{[bool]$_.IsOffline};isReadOnly=if($null-eq$_.IsReadOnly){$null}else{[bool]$_.IsReadOnly};isRemovable=([string]$_.BusType)-in@('USB','SD','MMC')}})
            return Complete-SbProductionResult $provenance $data @() $started ([int]$limits.maximumDiskRecords)
        }
        'storage.partitions'{
            $pipeline=[PowerShell]::Create();$null=$pipeline.AddCommand('Storage\Get-Partition').AddCommand('Microsoft.PowerShell.Utility\Select-Object').AddParameter('First',([int]$limits.maximumPartitionRecords+1));$result=Complete-SbFixedInvocation $pipeline $pipeline.BeginInvoke() $timeout
            if(-not$result.Success){return Complete-SbProductionResult $provenance @() @($result.Code) $started ([int]$limits.maximumPartitionRecords)}
            $data=@($result.Data|ForEach-Object{[pscustomobject][ordered]@{partitionGuid=if($null-eq$_.Guid){$null}else{[string]$_.Guid};partitionTypeGuid=if($null-eq$_.GptType){$null}else{[string]$_.GptType};diskNumber=if($null-eq$_.DiskNumber){$null}else{[int]$_.DiskNumber};partitionNumber=if($null-eq$_.PartitionNumber){$null}else{[int]$_.PartitionNumber};sizeBytes=if($null-eq$_.Size){$null}else{[long]$_.Size};driveLetter=if($null-eq$_.DriveLetter){$null}else{[string]$_.DriveLetter};mounted=$null-ne$_.DriveLetter}})
            return Complete-SbProductionResult $provenance $data @() $started ([int]$limits.maximumPartitionRecords)
        }
        'storage.volumes'{
            $pipeline=[PowerShell]::Create();$null=$pipeline.AddCommand('Storage\Get-Volume').AddCommand('Microsoft.PowerShell.Utility\Select-Object').AddParameter('First',([int]$limits.maximumVolumeRecords+1));$result=Complete-SbFixedInvocation $pipeline $pipeline.BeginInvoke() $timeout
            if(-not$result.Success){return Complete-SbProductionResult $provenance @() @($result.Code) $started ([int]$limits.maximumVolumeRecords)}
            $data=@($result.Data|ForEach-Object{[pscustomobject][ordered]@{driveLetter=if($null-eq$_.DriveLetter){$null}else{[string]$_.DriveLetter};filesystem=if($null-eq$_.FileSystem){$null}else{[string]$_.FileSystem};label=if($null-eq$_.FileSystemLabel){$null}else{[string]$_.FileSystemLabel};sizeBytes=if($null-eq$_.Size){$null}else{[long]$_.Size};healthStatus=if($null-eq$_.HealthStatus){$null}else{[string]$_.HealthStatus}}})
            return Complete-SbProductionResult $provenance $data @() $started ([int]$limits.maximumVolumeRecords)
        }
    }
}

function ConvertTo-SbProductionParserPayload {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Runtime,[Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Environment,[Parameter(Mandatory)][AllowEmptyCollection()][object[]]$OperatingSystem,[Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Disks,[Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Partitions,[Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Volumes)
    if(@($Runtime).Count-gt 1-or@($Environment).Count-gt 1-or@($OperatingSystem).Count-gt 1){throw 'PRODUCTION_RAW_SHAPE_INVALID'}
    $shapes=@{runtime=@('platform','osDescription','architecture');environment=@('osVersion','is64BitOperatingSystem');os=@('caption','version','buildNumber','architecture');disk=@('diskGuid','number','sizeBytes','isOffline','isReadOnly','isRemovable');partition=@('partitionGuid','partitionTypeGuid','diskNumber','partitionNumber','sizeBytes','driveLetter','mounted');volume=@('driveLetter','filesystem','label','sizeBytes','healthStatus')}
    foreach($entry in @(@('runtime',@($Runtime)),@('environment',@($Environment)),@('os',@($OperatingSystem)),@('disk',@($Disks)),@('partition',@($Partitions)),@('volume',@($Volumes)))){foreach($item in $entry[1]){if(@($item.PSObject.Properties.Name|Where-Object{$_ -notin $shapes[$entry[0]]}).Count){throw 'PRODUCTION_RAW_SHAPE_INVALID'}}}
    $diskMap=@{};foreach($disk in @($Disks)){if($null-ne$disk.number-and$null-ne$disk.diskGuid){$diskMap[[int]$disk.number]=[string]$disk.diskGuid}}
    $volumeMap=@{};foreach($volume in @($Volumes)){if(-not[string]::IsNullOrWhiteSpace([string]$volume.driveLetter)){$volumeMap[[string]$volume.driveLetter]=$volume}}
    $normalizedPartitions=@();foreach($partition in @($Partitions)){$volume=if($null-ne$partition.driveLetter){$volumeMap[[string]$partition.driveLetter]}else{$null};$normalizedPartitions+=[pscustomobject][ordered]@{diskGuid=if($null-ne$partition.diskNumber){$diskMap[[int]$partition.diskNumber]}else{$null};partitionGuid=$partition.partitionGuid;partitionTypeGuid=$partition.partitionTypeGuid;diskNumber=$partition.diskNumber;partitionNumber=$partition.partitionNumber;filesystem=if($null-ne$volume){$volume.filesystem}else{$null};label=if($null-ne$volume){$volume.label}else{$null};sizeBytes=$partition.sizeBytes;mounted=$partition.mounted}}
    $os=$null;$runtimeValue=$null;$environmentValue=$null;if(@($OperatingSystem).Count){$os=$OperatingSystem[0]};if(@($Runtime).Count){$runtimeValue=$Runtime[0]};if(@($Environment).Count){$environmentValue=$Environment[0]}
    return [pscustomobject][ordered]@{platform=if($null-ne$runtimeValue){$runtimeValue.platform}else{'Unsupported'};osVersion=if($null-ne$os){$os.version}elseif($null-ne$environmentValue){$environmentValue.osVersion}else{$null};architecture=if($null-ne$runtimeValue){$runtimeValue.architecture}else{'Unknown'};firmwareMode='Unknown';disks=@($Disks);partitions=$normalizedPartitions}
}

Export-ModuleMember -Function Get-SbProductionExecutionCount,Get-SbProductionLimits,Invoke-SbWindowsLevel1ProductionTransport,ConvertTo-SbProductionParserPayload
