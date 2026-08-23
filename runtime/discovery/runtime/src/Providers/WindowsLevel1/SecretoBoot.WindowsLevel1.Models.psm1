using module ../../Common/SecretoBoot.Common.psm1

Set-StrictMode -Version Latest

enum SbLevel1ResultStatus { Success; Partial; Rejected; Failed }

class SbWindowsLevel1ProviderPackage {
    [string] $ProviderName = 'WindowsLevel1ProviderPackage'
    [SbInventoryAccessLevel] $AccessLevel = [SbInventoryAccessLevel]::HostMetadata
    [bool] $IsReadOnly = $true
    [bool] $HostExecutionEnabled = $false
    [bool] $RequiresMount = $false
    [string[]] $Capabilities = @('PlatformMetadata','OperatingSystemMetadata','StorageInventory')
}

class SbLevel1Diagnostic {
    [string] $Code
    [string] $Message
    [string] $OperationId
    SbLevel1Diagnostic([string]$code,[string]$message,[string]$operationId){$this.Code=$code;$this.Message=$message;$this.OperationId=$operationId}
}

class SbLevel1GateDecision {
    [bool] $Allowed
    [SbLevel1Diagnostic[]] $Diagnostics
    SbLevel1GateDecision([bool]$allowed,[SbLevel1Diagnostic[]]$diagnostics){$this.Allowed=$allowed;$this.Diagnostics=$diagnostics}
}

class SbLevel1ExecutionRequest {
    [string] $OperationId
    [hashtable] $Arguments
    [int] $TimeoutMilliseconds
    [int] $MaximumOutputBytes
    SbLevel1ExecutionRequest([string]$operationId,[hashtable]$arguments,[int]$timeoutMilliseconds,[int]$maximumOutputBytes){
        $this.OperationId=$operationId;$this.Arguments=if($null -eq $arguments){@{}}else{$arguments}
        $this.TimeoutMilliseconds=$timeoutMilliseconds;$this.MaximumOutputBytes=$maximumOutputBytes
    }
}

class SbLevel1ExecutionResult {
    [SbLevel1ResultStatus] $Status
    [string] $Payload
    [SbLevel1Diagnostic[]] $Diagnostics
    [string[]] $Provenance
    SbLevel1ExecutionResult([SbLevel1ResultStatus]$status,[string]$payload,[SbLevel1Diagnostic[]]$diagnostics,[string[]]$provenance){
        $this.Status=$status;$this.Payload=$payload;$this.Diagnostics=$diagnostics;$this.Provenance=$provenance
    }
}

class SbLevel1DiskRecord {
    [string] $DiskGuid
    [Nullable[int]] $TransientDiskNumber
    [Nullable[long]] $SizeBytes
    [Nullable[bool]] $IsOffline
    [Nullable[bool]] $IsReadOnly
    [Nullable[bool]] $IsRemovable
    [string] $CanonicalId
}

class SbLevel1PartitionRecord {
    [string] $DiskGuid
    [string] $PartitionGuid
    [string] $PartitionTypeGuid
    [Nullable[int]] $TransientDiskNumber
    [Nullable[int]] $TransientPartitionNumber
    [string] $Filesystem
    [string] $DisplayLabel
    [Nullable[long]] $SizeBytes
    [Nullable[bool]] $Mounted
    [string] $TransientDevicePath
    [string] $CanonicalId
}

class SbLevel1Inventory {
    [string] $Platform
    [string] $OSVersion
    [string] $Architecture
    [string] $FirmwareMode
    [SbLevel1DiskRecord[]] $Disks = @()
    [SbLevel1PartitionRecord[]] $Partitions = @()
    [SbLevel1Diagnostic[]] $Diagnostics = @()
    [SbLevel1ResultStatus] $Status = [SbLevel1ResultStatus]::Success
}

class SbLevel1ParseResult {
    [SbLevel1Inventory] $Inventory
    [SbLevel1Diagnostic[]] $Diagnostics
    [SbLevel1ResultStatus] $Status
    SbLevel1ParseResult([SbLevel1Inventory]$inventory,[SbLevel1Diagnostic[]]$diagnostics,[SbLevel1ResultStatus]$status){$this.Inventory=$inventory;$this.Diagnostics=$diagnostics;$this.Status=$status}
}

class SbLevel1SafeDiskReport {
    [string] $DiskGuidPseudonym
    [Nullable[long]] $SizeBytes
    [Nullable[bool]] $OfflineState
    [Nullable[bool]] $ReadOnlyState
    [Nullable[bool]] $RemovableState
}

class SbLevel1SafePartitionReport {
    [string] $DiskGuidPseudonym
    [string] $PartitionGuidPseudonym
    [string] $PartitionType
    [string] $Filesystem
    [Nullable[long]] $SizeBytes
    [Nullable[bool]] $MountedState
}

class SbLevel1SafeReport {
    [string] $ReportId
    [string] $Platform
    [string] $OSVersion
    [string] $Architecture
    [string] $FirmwareMode
    [int] $DiskCount
    [int] $PartitionCount
    [SbLevel1SafeDiskReport[]] $Disks
    [SbLevel1SafePartitionReport[]] $Partitions
    [SbLevel1Diagnostic[]] $Warnings
}

class SbLevel1DryRunPlan {
    [string] $Title
    [string] $Platform
    [SbInventoryAccessLevel] $RequestedAccess
    [string[]] $WouldQuery
    [string[]] $WouldNotQuery
    [hashtable] $RequiresAdmin
    [bool] $MountRequired
    [string] $Writes
    [bool] $Executable
}
