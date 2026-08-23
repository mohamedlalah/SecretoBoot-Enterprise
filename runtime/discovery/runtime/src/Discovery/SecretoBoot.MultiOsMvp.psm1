using module ../Common/SecretoBoot.Common.psm1
using module ../Providers/WindowsLevel1/SecretoBoot.WindowsLevel1.Models.psm1
using module ./SecretoBoot.MultiOsDiscovery.psm1

Set-StrictMode -Version Latest

$script:MaximumPartitionCandidates = 4096
$script:EspType = 'C12A7328-F81F-11D2-BA4B-00A0C93EC93B'
$script:LinuxFilesystemType = '0FC63DAF-8483-4772-8E79-3D69D8477DE4'
$script:LinuxLvmType = 'E6D6D379-F507-44C2-A23C-238F2A3DF928'
$script:ServicePartitionTypes = @(
    '0657FD6D-A4AB-43C4-84E5-0933C84B4F4F', # Linux swap
    'E3C9E316-0B5C-4DB8-817D-F92DF00215AE', # Microsoft reserved
    'DE94BBA4-06D1-4D40-A16A-BFD50179D6AC'  # Windows recovery
)

function Get-SbMvpStableSuffix {
    param([Parameter(Mandatory)][string]$Value)
    $bytes=[Text.Encoding]::UTF8.GetBytes($Value);$hash=[Security.Cryptography.SHA256]::HashData($bytes)
    return [Convert]::ToHexString($hash).Substring(0,20).ToLowerInvariant()
}

function New-SbMvpEvidence {
    param(
        [Parameter(Mandatory)][string]$StableValue,
        [Parameter(Mandatory)][string]$Signal,
        [Parameter(Mandatory)][ValidateSet('Strong','Medium','Weak')][string]$Trust,
        [Parameter(Mandatory)][ValidateSet('Partition','OsInstanceCandidate')][string]$SubjectType,
        [Parameter(Mandatory)][string]$ReasonCode
    )
    $suffix=Get-SbMvpStableSuffix "$StableValue|$Signal"
    $subject=[SbEvidenceSubject]::new("node:mvp.$suffix",[SbEvidenceSubjectType]$SubjectType)
    $reason=[SbEvidenceReason]::new($ReasonCode,'Level 1 host-storage metadata projection')
    return [SbEvidenceRecord]::new("ev:mvp.$suffix",[SbEvidenceSourceLayer]::HostStorageMetadata,[SbEvidenceTrustTier]$Trust,[SbEvidencePolarity]::Positive,[SbEvidenceAccessibility]::Accessible,[SbEvidenceFreshness]::Current,$subject,$Signal,'',"level1:$Signal",@($reason))
}

function Get-SbMvpFilesystemAccessibility {
    param([object]$Partition)
    if($Partition.MountedState-eq$true-and-not[string]::IsNullOrWhiteSpace([string]$Partition.Filesystem)){return 'AccessibleButNotReadByMvp'}
    return 'NotAccessibleViaLevel1'
}

function Get-SbMvpFilesystemName {
    param([AllowNull()][string]$Filesystem)
    if([string]::IsNullOrWhiteSpace($Filesystem)){return 'Unknown'}
    $value=$Filesystem.Trim()
    if($value.Length-gt32-or$value-notmatch'^[A-Za-z0-9._+-]+$'){return 'Unknown'}
    return $value
}

function ConvertTo-SbMultiOsMvpReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Level1Report,
        [bool]$WindowsCimEvidencePresent=$false
    )
    $required=@('ReportId','Platform','OSVersion','Architecture','FirmwareMode','DiskCount','PartitionCount','Disks','Partitions','Warnings')
    if(@($required|Where-Object{$_ -notin$Level1Report.PSObject.Properties.Name}).Count){throw 'MVP_LEVEL1_REPORT_SHAPE_DENIED'}
    $partitions=@($Level1Report.Partitions)
    if($partitions.Count-ne[int]$Level1Report.PartitionCount){throw 'MVP_LEVEL1_REPORT_COUNT_MISMATCH'}
    if($partitions.Count-gt$script:MaximumPartitionCandidates){throw 'MVP_PARTITION_RESOURCE_CAP_EXCEEDED'}

    $systems=[Collections.Generic.List[object]]::new();$bootContainers=[Collections.Generic.List[object]]::new();$excluded=0
    if($WindowsCimEvidencePresent-and[string]$Level1Report.Platform-eq'Windows'){
        $evidence=New-SbMvpEvidence -StableValue 'current-windows-host' -Signal 'windows-host-cim' -Trust Strong -SubjectType OsInstanceCandidate -ReasonCode 'DISCOVERY_WINDOWS_HOST_CONFIRMED'
        $decision=Get-SbClassificationDecision -Evidence @($evidence)
        $systems.Add([pscustomobject][ordered]@{
            SystemId='mvp:host:windows';CandidateKind='CurrentHost';PartitionId=$null;DiskId=$null
            Family=$decision.Family.ToString();Distribution=$decision.Distribution.ToString();Confidence=$decision.Confidence.ToString()
            PartitionType=$null;Filesystem='WindowsLocal';FilesystemAccessibility='CurrentHostMetadataOnly'
            EvidenceBasis=@('platform.runtime','platform.environment','windows.os.cim');ReasonCodes=@($decision.ReasonCodes)
            NeedsStrongerEvidence=$false
        })
    }

    foreach($partition in @($partitions|Sort-Object PartitionGuidPseudonym)){
        $type=([string]$partition.PartitionType).ToUpperInvariant();$partitionId=[string]$partition.PartitionGuidPseudonym;$diskId=[string]$partition.DiskGuidPseudonym
        if($type-eq$script:EspType){
            $bootContainers.Add([pscustomobject][ordered]@{PartitionId=$partitionId;DiskId=$diskId;Role='EfiSystemPartitionContainer';ContentsInspected=$false;OsOwnership='Unknown'})
            continue
        }
        if($type-in$script:ServicePartitionTypes){$excluded++;continue}

        $signal='partition-observed';$trust='Weak';$reason='DISCOVERY_UNKNOWN_BOOTABLE'
        if($type-eq$script:LinuxFilesystemType-or$type-eq$script:LinuxLvmType){$signal='linux-partition-type';$trust='Medium';$reason='DISCOVERY_LINUX_PARTITION_CANDIDATE'}
        elseif($type-eq'EBD0A0A2-B9E5-4433-87C0-68B6B72699C7'){$signal='microsoft-basic-data';$reason='DISCOVERY_WINDOWS_WEAK_EVIDENCE'}
        $evidence=New-SbMvpEvidence -StableValue $partitionId -Signal $signal -Trust $trust -SubjectType Partition -ReasonCode $reason
        $decision=Get-SbClassificationDecision -Evidence @($evidence)
        $systems.Add([pscustomobject][ordered]@{
            SystemId=('mvp:partition:'+(Get-SbMvpStableSuffix $partitionId));CandidateKind='PartitionCandidate';PartitionId=$partitionId;DiskId=$diskId
            Family=$decision.Family.ToString();Distribution=$decision.Distribution.ToString();Confidence=$decision.Confidence.ToString()
            PartitionType=$type;Filesystem=Get-SbMvpFilesystemName ([string]$partition.Filesystem);FilesystemAccessibility=Get-SbMvpFilesystemAccessibility $partition
            EvidenceBasis=@('storage.disks','storage.partitions','storage.volumes');ReasonCodes=@($decision.ReasonCodes)
            NeedsStrongerEvidence=$true
        })
    }

    return [pscustomobject][ordered]@{
        SchemaVersion='v9multiosmvp1';Status='PARTIAL';Source='WindowsLevel1SafeMetadata';DynamicCollection=$true
        ResourceCaps=[pscustomobject][ordered]@{MaximumPartitionCandidates=$script:MaximumPartitionCandidates;HardCodedOsCount=$false}
        DetectedSystems=$systems.ToArray();DetectedSystemsCount=$systems.Count
        PartitionCandidatesCount=@($systems|Where-Object{$_.CandidateKind-eq'PartitionCandidate'}).Count
        ExcludedServicePartitionCount=$excluded;BootEvidenceCandidates=$bootContainers.ToArray()
        EvidenceSeparation=[pscustomobject][ordered]@{PartitionCandidateDiscovery='Completed';FilesystemAccessibility='ReportedOnly';OsIdentification='Conservative';BootloaderEfiEvidence='NotCollected'}
        ClassifierRules=[pscustomobject][ordered]@{Windows='Current host only, confirmed by reviewed local runtime/CIM evidence';Linux='Possible from Linux GPT type; distribution requires bounded os-release';Android='Not named without system/build evidence plus two independent Android indicators';Unknown='Retained as a separate partition candidate'}
        SafetyCounters=[pscustomobject][ordered]@{Level1InventoryOperations=6;NativeTargetReads=0;OsIdentificationReads=0;EfiOperations=0;BcdOperations=0;NvramOperations=0;SecureBootOperations=0;MountOperations=0;DriveLetterAssignments=0;PartitionWrites=0;BootStateWrites=0;NetworkOperations=0;RefindOperations=0}
    }
}

Export-ModuleMember -Function ConvertTo-SbMultiOsMvpReport
