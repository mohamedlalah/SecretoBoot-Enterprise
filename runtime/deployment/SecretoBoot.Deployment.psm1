Set-StrictMode -Version Latest

function Test-SbDeploymentEnvelope {
    [CmdletBinding()]param([Parameter(Mandatory)][object]$Envelope)
    $reasons=[Collections.Generic.List[string]]::new()
    foreach($name in 'SchemaVersion','Revision','PlanCoreJson','PlanDigest','Deployable','DeploymentAuthorized'){if($name-notin$Envelope.PSObject.Properties.Name){$reasons.Add('PLAN_REQUIRED_FIELD_MISSING')}}
    if([string]$Envelope.SchemaVersion-cne'v9-end-to-end-envelope-1'){$reasons.Add('PLAN_SCHEMA_INVALID')}
    if([string]$Envelope.Revision-cne'Windows-Desktop-V9-FinalRelease.1-WindowsFirstCompatibilityPreflightFix.1'){$reasons.Add('PLAN_REVISION_MISMATCH')}
    if([string]$Envelope.PlanDigest-notmatch'^[0-9a-f]{64}$'){$reasons.Add('PLAN_DIGEST_DENIED')}
    try{$actual=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes([string]$Envelope.PlanCoreJson))).ToLowerInvariant();if($actual-cne[string]$Envelope.PlanDigest){$reasons.Add('PLAN_TAMPERED')}}catch{$reasons.Add('PLAN_PARSE_DENIED')}
    try{$core=[string]$Envelope.PlanCoreJson|ConvertFrom-Json;foreach($name in 'SchemaVersion','Revision','HybridResolutionRequired','PartitionInventory','InstallDirectory','BootEntries','DeploymentAuthorized','NoDriveLetters'){if($name-notin$core.PSObject.Properties.Name){$reasons.Add('PLAN_REQUIRED_FIELD_MISSING')}};if([string]$core.SchemaVersion-cne'v9-end-to-end-plan-1'){$reasons.Add('PLAN_SCHEMA_INVALID')};if([string]$core.Revision-cne'Windows-Desktop-V9-FinalRelease.1-WindowsFirstCompatibilityPreflightFix.1'){$reasons.Add('PLAN_REVISION_MISMATCH')};if([string]$core.InstallDirectory-cne'\EFI\SecretoBoot\'-or$core.NoDriveLetters-ne$true-or$core.DeploymentAuthorized-ne$false-or$core.HybridResolutionRequired-ne$true){$reasons.Add('PLAN_SCOPE_DENIED')};if(@($core.PartitionInventory).Count-lt1-or@($core.PartitionInventory).Count-gt4096){$reasons.Add('PARTITION_INVENTORY_DENIED')};foreach($partition in @($core.PartitionInventory)){if([string]$partition.PartitionGuid-notmatch'^[0-9A-Fa-f-]{36}$'-or[string]$partition.DiskGuid-notmatch'^[0-9A-Fa-f-]{36}$'){$reasons.Add('PARTITION_INVENTORY_DENIED')}};foreach($entry in @($core.BootEntries)){if([string]$entry.LoaderPath-notmatch'^\\EFI\\[A-Za-z0-9._ -]+(?:\\[A-Za-z0-9._ -]+)*\.efi$'-or[string]$entry.PartitionGuid-notmatch'^[0-9A-Fa-f-]{36}$'){$reasons.Add('BOOT_ENTRY_DENIED')}}}catch{$reasons.Add('PLAN_PARSE_DENIED')}
    return [pscustomobject]@{Valid=($reasons.Count-eq0);Reasons=@($reasons|Sort-Object -Unique);Core=if($reasons.Count){$null}else{$core}}
}

function Test-SbResolvedDeploymentCore {
    [CmdletBinding()]param([Parameter(Mandatory)][object]$Core,[bool]$RequireBliss=$true)
    $reasons=[Collections.Generic.List[string]]::new()
    if('HybridResolutionCompleted'-notin$Core.PSObject.Properties.Name-or$Core.HybridResolutionCompleted-ne$true){$reasons.Add('PLAN_HYBRID_RESOLUTION_NOT_RUN')}
    if([string]$Core.TargetEspPartitionGuid-notmatch'^[0-9A-Fa-f-]{36}$'){$reasons.Add('PLAN_TARGET_ESP_UNRESOLVED')}
    $windows=@($Core.BootEntries|Where-Object{[string]$_.Family-ceq'Windows'-and[string]$_.LoaderPath-ieq'\EFI\Microsoft\Boot\bootmgfw.efi'});if($windows.Count-ne1){$reasons.Add('PLAN_WINDOWS_TARGET_UNRESOLVED')}
    $bliss=@($Core.BootEntries|Where-Object{[string]$_.Family-ceq'Android'-and[string]$_.LoaderPath-ieq'\EFI\BOOT\BOOTX64.EFI'});if($RequireBliss-and$bliss.Count-ne1){$reasons.Add('PLAN_BLISS_TARGET_UNRESOLVED')}
    foreach($entry in @($Core.BootEntries)){if([string]$entry.PartitionGuid-notmatch'^[0-9A-Fa-f-]{36}$'-or[string]$entry.LoaderPath-notmatch'^\\EFI\\[A-Za-z0-9._ -]+(?:\\[A-Za-z0-9._ -]+)*\.efi$'-or$entry.BootReady-ne$true){$reasons.Add('PLAN_SCHEMA_INVALID')}}
    [pscustomobject]@{Valid=($reasons.Count-eq0);Reasons=@($reasons|Sort-Object -Unique)}
}

function New-SbDeploymentTransaction {
    param([Parameter(Mandatory)][object]$Envelope)
    [pscustomobject][ordered]@{SchemaVersion='v9-deployment-transaction-1';PlanDigest=[string]$Envelope.PlanDigest;Stage='Preflight';StartedUtc=[DateTime]::UtcNow.ToString('o');CompletedUtc=$null;InstalledFiles=@();FirmwareEntry=$null;PreviousBootOrderBase64=$null;TargetEspPartitionGuid=$null;RollbackRequired=$false;LastReasonCode='TRANSACTION_CREATED'}
}

function Invoke-SbDeploymentTransaction {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Envelope,[Parameter(Mandatory)][object]$Provider,[Parameter(Mandatory)][ValidateSet('INSTALL_SECRETOBOOT_EXPERIMENTAL')][string]$FinalConsent)
    $validation=Test-SbDeploymentEnvelope $Envelope;if(-not$validation.Valid){throw ($validation.Reasons[0])};$core=$validation.Core;$tx=New-SbDeploymentTransaction $Envelope
    foreach($required in @('Preflight','PrepareBackup','InstallFiles','VerifyFiles','CreateFirmwareEntry','PersistTransaction','Rollback')){if($required-notin$Provider.PSObject.Properties.Name-or$Provider.$required-isnot[scriptblock]){throw 'DEPLOYMENT_PROVIDER_CONTRACT_DENIED'}}
    try{
        & $Provider.Preflight $core;$tx.TargetEspPartitionGuid=[string]$core.TargetEspPartitionGuid;& $Provider.PersistTransaction $tx
        $backup=& $Provider.PrepareBackup $core;$tx.Stage='BackupPrepared';$tx.LastReasonCode='BACKUP_PREPARED';& $Provider.PersistTransaction $tx
        $files=@(& $Provider.InstallFiles $core $backup);$tx.Stage='FilesInstalled';$tx.InstalledFiles=$files;$tx.RollbackRequired=$true;& $Provider.PersistTransaction $tx
        & $Provider.VerifyFiles $core $files;$tx.Stage='FilesVerified';$tx.LastReasonCode='FILES_VERIFIED';& $Provider.PersistTransaction $tx
        $firmware=& $Provider.CreateFirmwareEntry $core;$tx.Stage='FirmwareEntryCreated';$tx.FirmwareEntry=$firmware.EntryName;$tx.PreviousBootOrderBase64=[Convert]::ToBase64String([byte[]]$firmware.PreviousBootOrder);& $Provider.PersistTransaction $tx
        $tx.Stage='DeploymentComplete';$tx.CompletedUtc=[DateTime]::UtcNow.ToString('o');$tx.RollbackRequired=$false;$tx.LastReasonCode='DEPLOYMENT_COMPLETE';& $Provider.PersistTransaction $tx
        return $tx
    }catch{$reason=[string]$_.Exception.Message;$tx.LastReasonCode=if($reason-match'^[A-Z0-9_]{3,120}$'){$reason}else{'DEPLOYMENT_FAILED'};if($tx.RollbackRequired){try{& $Provider.Rollback $tx}catch{$tx.LastReasonCode='DEPLOYMENT_AND_ROLLBACK_FAILED'}};throw $tx.LastReasonCode}
}

function Invoke-SbOwnedUninstall {
    [CmdletBinding()]param([Parameter(Mandatory)][object]$OwnershipManifest,[Parameter(Mandatory)][object]$Provider,[Parameter(Mandatory)][ValidateSet('UNINSTALL_SECRETOBOOT_EXPERIMENTAL')][string]$FinalConsent)
    if([string]$OwnershipManifest.SchemaVersion-cne'v9-ownership-manifest-1'-or$OwnershipManifest.OwnershipVerified-ne$true){throw 'UNINSTALL_OWNERSHIP_DENIED'}
    foreach($required in @('VerifyOwnership','RemoveFirmwareEntry','RemoveOwnedFiles','VerifyForeignFilesUnchanged')){if($required-notin$Provider.PSObject.Properties.Name-or$Provider.$required-isnot[scriptblock]){throw 'UNINSTALL_PROVIDER_CONTRACT_DENIED'}}
    & $Provider.VerifyOwnership $OwnershipManifest;& $Provider.RemoveFirmwareEntry $OwnershipManifest;& $Provider.RemoveOwnedFiles $OwnershipManifest;& $Provider.VerifyForeignFilesUnchanged $OwnershipManifest
    return [pscustomobject]@{Status='Uninstalled';RemovedOnlyManifestOwnedState=$true}
}

Export-ModuleMember -Function Test-SbDeploymentEnvelope,Test-SbResolvedDeploymentCore,New-SbDeploymentTransaction,Invoke-SbDeploymentTransaction,Invoke-SbOwnedUninstall
