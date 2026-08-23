Set-StrictMode -Version Latest

$script:SbEspType = 'C12A7328-F81F-11D2-BA4B-00A0C93EC93B'

function Get-SbSetupValue {
    param([AllowNull()][object]$Object,[Parameter(Mandatory)][string]$Name)
    if($null-eq$Object-or$Name-notin$Object.PSObject.Properties.Name){return $null}
    return $Object.$Name
}

function ConvertTo-SbSetupGuid {
    param([AllowNull()][object]$Value)
    $parsed=[guid]::Empty
    if(-not[guid]::TryParse([string]$Value,[ref]$parsed)-or$parsed-eq[guid]::Empty){return $null}
    return $parsed.ToString('D').ToUpperInvariant()
}

function Test-SbSetupCanonicalEfiEvidence {
    param([object]$Evidence,[string]$ExpectedPath)
    $path=([string](Get-SbSetupValue $Evidence 'RelativePath')).Replace('/','\').TrimStart('\')
    return [string](Get-SbSetupValue $Evidence 'Kind')-ceq'EfiLoader' -and
        [string](Get-SbSetupValue $Evidence 'ValidationStatus')-ceq'Validated' -and
        [string](Get-SbSetupValue $Evidence 'ContainmentStatus')-ceq'Passed' -and
        (Get-SbSetupValue $Evidence 'IsRegularFile')-eq$true -and
        [long](Get-SbSetupValue $Evidence 'SizeBytes')-gt0 -and
        $path-ieq$ExpectedPath -and
        $null-ne(ConvertTo-SbSetupGuid (Get-SbSetupValue $Evidence 'PartitionId')) -and
        $null-ne(ConvertTo-SbSetupGuid (Get-SbSetupValue $Evidence 'DiskId'))
}

function Test-SbSetupBlissChain {
    param([object]$Chain)
    $signals=@(Get-SbSetupValue $Chain 'Signals')
    return [string](Get-SbSetupValue $Chain 'ValidationStatus')-ceq'Validated' -and
        [string](Get-SbSetupValue $Chain 'ContainmentStatus')-ceq'Passed' -and
        ([string](Get-SbSetupValue $Chain 'LoaderPath')).Replace('\','/').TrimStart('/')-ieq'EFI/BOOT/BOOTX64.EFI' -and
        'valid-efi-loader'-in$signals -and 'android-canonical-boot-chain'-in$signals -and
        $null-ne(ConvertTo-SbSetupGuid (Get-SbSetupValue $Chain 'BootPartitionId')) -and
        $null-ne(ConvertTo-SbSetupGuid (Get-SbSetupValue $Chain 'DiskId'))
}

function Resolve-SbBlissEfiChainloadCandidates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$InspectionResults,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$PartitionInventory
    )
    if($InspectionResults.Count-gt256-or$PartitionInventory.Count-gt4096){throw 'REFIND_SETUP_BLISS_RESOURCE_CAP_EXCEEDED'}
    $inventory=@{};foreach($item in $PartitionInventory){$opaque=[string](Get-SbSetupValue $item 'OpaquePartitionId');$raw=ConvertTo-SbSetupGuid (Get-SbSetupValue $item 'RawPartitionId');$disk=ConvertTo-SbSetupGuid (Get-SbSetupValue $item 'RawDiskId');$filesystem=[string](Get-SbSetupValue $item 'Filesystem');if($opaque-and$raw-and$disk-and$filesystem-ceq'FAT32'){$inventory[$opaque]=[pscustomobject]@{Partition=$raw;Disk=$disk;Filesystem=$filesystem}}}
    $output=[Collections.Generic.List[object]]::new()
    foreach($inspection in $InspectionResults){
        $opaque=[string](Get-SbSetupValue $inspection 'PartitionId');if([string](Get-SbSetupValue $inspection 'Status')-cne'Complete'-or-not$inventory.ContainsKey($opaque)){continue}
        $items=@(Get-SbSetupValue $inspection 'Evidence')
        $loader=@($items|Where-Object{[string](Get-SbSetupValue $_ 'Kind')-ceq'EfiLoader'-and(Get-SbSetupValue $_ 'ValidPeX64')-eq$true-and([string](Get-SbSetupValue $_ 'RelativePath')).Replace('\','/').TrimStart('/')-ieq'EFI/BOOT/BOOTX64.EFI'-and'valid-efi-loader'-in@(Get-SbSetupValue $_ 'Signals')})
        $config=@($items|Where-Object{[string](Get-SbSetupValue $_ 'Kind')-ceq'BootConfig'-and(Get-SbSetupValue $_ 'CanonicalConfigValidated')-eq$true-and([string](Get-SbSetupValue $_ 'RelativePath')).Replace('\','/').TrimStart('/')-ieq'EFI/BOOT/android.cfg'-and([string](Get-SbSetupValue $_ 'LoaderPath')).Replace('\','/').TrimStart('/')-ieq'EFI/BOOT/BOOTX64.EFI'-and[string](Get-SbSetupValue $_ 'Distribution')-match'^BlissOS [0-9]+(?:\.[0-9]+){1,3}$'})
        $dispatcher=@($items|Where-Object{[string](Get-SbSetupValue $_ 'Kind')-ceq'BootConfig'-and'android-config-dispatcher'-in@(Get-SbSetupValue $_ 'Signals')-and([string](Get-SbSetupValue $_ 'RelativePath')).Replace('\','/').TrimStart('/')-ieq'boot/grub/grub.cfg'})
        $kernel=@($items|Where-Object{[string](Get-SbSetupValue $_ 'Kind')-ceq'Kernel'-and([string](Get-SbSetupValue $_ 'RelativePath')).Replace('\','/').TrimStart('/')-ieq'kernel'-and'android-kernel'-in@(Get-SbSetupValue $_ 'Signals')})
        $initrd=@($items|Where-Object{[string](Get-SbSetupValue $_ 'Kind')-ceq'Initrd'-and([string](Get-SbSetupValue $_ 'RelativePath')).Replace('\','/').TrimStart('/')-ieq'initrd.img'-and'android-initrd'-in@(Get-SbSetupValue $_ 'Signals')})
        if($loader.Count-ne1-or$config.Count-ne1-or$dispatcher.Count-ne1-or$kernel.Count-ne1-or$initrd.Count-ne1){continue}
        $output.Add([pscustomobject][ordered]@{Kind='BlissKnownWorkingEfiChainload';ValidationStatus='Validated';ContainmentStatus='Passed';LoaderPath='EFI/BOOT/BOOTX64.EFI';BootPartitionId=$inventory[$opaque].Partition;DiskId=$inventory[$opaque].Disk;SourcePartitionToken=$opaque;Signals=@('valid-efi-loader','android-canonical-boot-chain','bliss-known-working-efi-chainload');ComponentEvidenceIds=@($loader[0].EvidenceId,$config[0].EvidenceId,$dispatcher[0].EvidenceId,$kernel[0].EvidenceId,$initrd[0].EvidenceId|Sort-Object -Unique)})
    }
    return $output.ToArray()
}

function Test-SbRefindAssetManifest {
    param([Parameter(Mandatory)][object]$AssetManifest)
    if([string]$AssetManifest.SchemaVersion-cne'v9-refind-assets-1'-or[string]$AssetManifest.RefindVersion-cne'0.14.2'){return $false}
    $required=@('refind_x64.efi','LICENSE.txt','COPYING.txt','CREDITS.txt','themes/SecretoBootV9/theme.conf','themes/SecretoBootV9/background.png','themes/SecretoBootV9/branding.png','themes/SecretoBootV9/selector.png','themes/SecretoBootV9/selector-small.png','themes/SecretoBootV9/icons/windows.png','themes/SecretoBootV9/icons/android.png','themes/SecretoBootV9/icons/bliss.png','themes/SecretoBootV9/icons/linux.png','themes/SecretoBootV9/icons/reboot.png','themes/SecretoBootV9/icons/shutdown.png','themes/SecretoBootV9/icons/func_reset.png','themes/SecretoBootV9/icons/func_shutdown.png')
    $actual=@($AssetManifest.Files.PSObject.Properties.Name)
    if(@($required|Where-Object{$_-notin$actual}).Count){return $false}
    foreach($name in $actual){if($name-notmatch'^[A-Za-z0-9._/-]+$'-or[string]$AssetManifest.Files.$name-notmatch'^[0-9a-f]{64}$'){return $false}}
    return $true
}

function New-SbRefindResolutionDiagnostics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$WindowsCandidates,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$BlissCandidates,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$BlissCanonicalBootChains
    )
    if($WindowsCandidates.Count-gt64-or$BlissCandidates.Count-gt256-or$BlissCanonicalBootChains.Count-gt256){throw 'REFIND_RESOLUTION_DIAGNOSTIC_CAP_EXCEEDED'}
    $allowedReasons=@('NONE','NO_VOLUME_GUID_ACCESS_PATH','OPEN_FAILED','NOT_FOUND','CONTAINMENT_DENIED','NOT_REGULAR_FILE','PE_VALIDATION_FAILED','ARCHITECTURE_MISMATCH','CONFIG_VALIDATION_FAILED','CHAIN_INCOMPLETE','AMBIGUOUS_MATCH')
    $allowedPaths=@('EFI/Microsoft/Boot/bootmgfw.efi','kernel','initrd.img','EFI/BOOT/BOOTX64.EFI','EFI/BOOT/android.cfg','boot/grub/grub.cfg')
    $output=[Collections.Generic.List[object]]::new()
    foreach($candidate in $WindowsCandidates){
        $id=[string](Get-SbSetupValue $candidate 'CandidateId');if($id-notmatch'^report:partition:[0-9a-f]{20}$'){continue}
        $details=@(Get-SbSetupValue $candidate 'PathDiagnostics'|Where-Object{[string](Get-SbSetupValue $_ 'RelativePath')-ceq'EFI/Microsoft/Boot/bootmgfw.efi'})
        $detail=if($details.Count){$details[0]}else{$null};$usable=(Get-SbSetupValue $candidate 'UsableVolumeGuidAccessPath')-eq$true
        $reason=if(-not$usable){if([int](Get-SbSetupValue $candidate 'VolumeGuidCount')-gt1){'AMBIGUOUS_MATCH'}else{'NO_VOLUME_GUID_ACCESS_PATH'}}elseif($null-ne$detail){[string](Get-SbSetupValue $detail 'FailureReason')}else{[string](Get-SbSetupValue $candidate 'FailureReason')}
        if($reason-notin$allowedReasons){$reason='OPEN_FAILED'}
        $output.Add([pscustomobject][ordered]@{CandidateKind='WindowsEsp';CandidateId=$id;Filesystem=[string](Get-SbSetupValue $candidate 'Filesystem');UsableVolumeGuidAccessPath=$usable;PathDiagnostics=@([pscustomobject][ordered]@{RelativePath='EFI/Microsoft/Boot/bootmgfw.efi';OpenAttempted=($null-ne$detail-and(Get-SbSetupValue $detail 'OpenAttempted')-eq$true);Exists=($null-ne$detail-and(Get-SbSetupValue $detail 'Exists')-eq$true);ContainmentResult=if($null-ne$detail){[string](Get-SbSetupValue $detail 'ContainmentResult')}else{'NotEvaluated'};RegularFileResult=if($null-ne$detail){[string](Get-SbSetupValue $detail 'RegularFileResult')}else{'NotEvaluated'};ValidationResult=if($null-ne$detail){[string](Get-SbSetupValue $detail 'PeX64Result')}else{'NotEvaluated'};FailureReason=$reason});IdentityParserResult='NOT_APPLICABLE';FailureReason=$reason})
    }
    $chainTokens=@($BlissCanonicalBootChains|ForEach-Object{[string](Get-SbSetupValue $_ 'SourcePartitionToken')}|Where-Object{$_-match'^report:partition:[0-9a-f]{20}$'}|Sort-Object -Unique)
    foreach($candidate in $BlissCandidates){
        $id=[string](Get-SbSetupValue $candidate 'CandidateId');if($id-notmatch'^report:partition:[0-9a-f]{20}$'){continue};$usable=(Get-SbSetupValue $candidate 'UsableVolumeGuidAccessPath')-eq$true
        $source=@(Get-SbSetupValue $candidate 'PathDiagnostics');$paths=[Collections.Generic.List[object]]::new()
        foreach($path in $allowedPaths|Where-Object{$_-cne'EFI/Microsoft/Boot/bootmgfw.efi'}){$found=@($source|Where-Object{[string](Get-SbSetupValue $_ 'RelativePath')-ceq$path}|Select-Object -First 1);$reason=if($found.Count){[string](Get-SbSetupValue $found[0] 'FailureReason')}elseif(-not$usable){'NO_VOLUME_GUID_ACCESS_PATH'}else{'NOT_FOUND'};if($reason-notin$allowedReasons){$reason='OPEN_FAILED'};$paths.Add([pscustomobject][ordered]@{RelativePath=$path;OpenAttempted=($found.Count-and(Get-SbSetupValue $found[0] 'OpenAttempted')-eq$true);Exists=($found.Count-and(Get-SbSetupValue $found[0] 'Exists')-eq$true);ContainmentResult=if($found.Count){[string](Get-SbSetupValue $found[0] 'ContainmentResult')}else{'NotEvaluated'};ValidationResult=if($found.Count){[string](Get-SbSetupValue $found[0] 'ValidationResult')}else{'NotEvaluated'};FailureReason=$reason})}
        $config=@($paths|Where-Object{[string]$_.RelativePath-ceq'EFI/BOOT/android.cfg'}|Select-Object -First 1);$identity=if($config.Count-and$config[0].ValidationResult-ceq'Validated'){'ValidatedBlissIdentity'}elseif($config.Count-and$config[0].Exists){'CONFIG_VALIDATION_FAILED'}else{'NotEvaluated'}
        $reason=if(-not$usable){if([int](Get-SbSetupValue $candidate 'VolumeGuidCount')-gt1){'AMBIGUOUS_MATCH'}else{'NO_VOLUME_GUID_ACCESS_PATH'}}elseif($id-in$chainTokens){'NONE'}else{@($paths|Where-Object{[string]$_.FailureReason-cne'NONE'}|Select-Object -First 1).FailureReason};if([string]::IsNullOrWhiteSpace([string]$reason)){$reason='CHAIN_INCOMPLETE'}
        $output.Add([pscustomobject][ordered]@{CandidateKind='BlissFat32';CandidateId=$id;Filesystem='FAT32';UsableVolumeGuidAccessPath=$usable;PathDiagnostics=$paths.ToArray();IdentityParserResult=$identity;FailureReason=[string]$reason})
    }
    return $output.ToArray()
}

function New-SbRefindSetupPreview {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$RawPartitions,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$CanonicalEfiEvidence,
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$AndroidCanonicalBootChains,
        [Parameter(Mandatory)][object]$AssetManifest,
        [AllowEmptyCollection()][object[]]$ResolutionDiagnostics=@()
    )
    $normalizedAndroidCanonicalBootChains=@($AndroidCanonicalBootChains)
    if($RawPartitions.Count-gt4096-or$CanonicalEfiEvidence.Count-gt4096-or$normalizedAndroidCanonicalBootChains.Count-gt256){throw 'REFIND_SETUP_RESOURCE_CAP_EXCEEDED'}
    if(-not(Test-SbRefindAssetManifest $AssetManifest)){throw 'REFIND_SETUP_ASSET_MANIFEST_DENIED'}

    $esp=@($RawPartitions|Where-Object{([string](Get-SbSetupValue $_ 'PartitionTypeGuid')).Trim('{}').ToUpperInvariant()-ceq$script:SbEspType -and $null-ne(ConvertTo-SbSetupGuid (Get-SbSetupValue $_ 'PartitionGuid'))})
    $windows=@($CanonicalEfiEvidence|Where-Object{Test-SbSetupCanonicalEfiEvidence $_ 'EFI\Microsoft\Boot\bootmgfw.efi'}|Group-Object{ConvertTo-SbSetupGuid (Get-SbSetupValue $_ 'PartitionId')}|ForEach-Object{$_.Group[0]})
    $bliss=@($normalizedAndroidCanonicalBootChains|Where-Object{Test-SbSetupBlissChain $_}|Group-Object{ConvertTo-SbSetupGuid (Get-SbSetupValue $_ 'BootPartitionId')}|ForEach-Object{$_.Group[0]})
    $blissFat32Candidates=@($RawPartitions|Where-Object{[string](Get-SbSetupValue $_ 'Filesystem')-ceq'FAT32'-and$null-ne(ConvertTo-SbSetupGuid (Get-SbSetupValue $_ 'PartitionGuid'))})

    $windowsResolved=$windows.Count-eq1
    $blissResolved=$bliss.Count-eq1
    $targetEsp=if($windowsResolved){ConvertTo-SbSetupGuid $windows[0].PartitionId}else{$null}
    $windowsDisk=if($windowsResolved){ConvertTo-SbSetupGuid $windows[0].DiskId}else{$null}
    $blissPartition=if($blissResolved){ConvertTo-SbSetupGuid $bliss[0].BootPartitionId}else{$null}
    $blissDisk=if($blissResolved){ConvertTo-SbSetupGuid $bliss[0].DiskId}else{$null}
    if($windowsResolved-and-not@($esp|Where-Object{(ConvertTo-SbSetupGuid $_.PartitionGuid)-ceq$targetEsp}).Count){$windowsResolved=$false;$targetEsp=$null;$windowsDisk=$null}
    if($blissResolved-and$null-ne(Get-SbSetupValue $bliss[0] 'SourcePartitionToken')){
        $bootPartition=@($RawPartitions|Where-Object{(ConvertTo-SbSetupGuid $_.PartitionGuid)-ceq$blissPartition})
        if($bootPartition.Count-ne1){$blissResolved=$false;$blissPartition=$null;$blissDisk=$null}
    }

    $config=[Collections.Generic.List[string]]::new()
    foreach($line in @('# SecretoBoot V9 generated rEFInd configuration',' # PREVIEW ONLY - NOT DEPLOYED','timeout 10','default_selection "Windows"','scanfor manual','showtools reboot,shutdown','include themes/SecretoBootV9/theme.conf','')){$config.Add($line.TrimStart())}
    if($windowsResolved){
        foreach($line in @('menuentry "Windows" {','    icon \EFI\SecretoBoot\themes\SecretoBootV9\icons\windows.png',('    volume {0}'-f$targetEsp),'    loader \EFI\Microsoft\Boot\bootmgfw.efi','    ostype Windows','}')){$config.Add($line)}
    }else{$config.Add('# Windows entry withheld: canonical Microsoft loader not uniquely validated.')}
    $config.Add('')
    if($blissResolved){
        foreach($line in @('menuentry "Bliss OS" {','    icon \EFI\SecretoBoot\themes\SecretoBootV9\icons\bliss.png',('    volume {0}'-f$blissPartition),'    loader \EFI\BOOT\BOOTX64.EFI','}')){$config.Add($line)}
    }else{$config.Add('# Bliss OS entry withheld: known-working FAT32 EFI loader not uniquely validated.')}

    $entries=@(
        [pscustomobject][ordered]@{DisplayName='Windows';Status=if($windowsResolved){'Generated'}else{'NeedsEvidence'};VolumePartitionGuid=$targetEsp;LoaderPath='\EFI\Microsoft\Boot\bootmgfw.efi'},
        [pscustomobject][ordered]@{DisplayName='Bliss OS';Status=if($blissResolved){'Generated'}else{'NeedsEvidence'};VolumePartitionGuid=$blissPartition;LoaderPath='\EFI\BOOT\BOOTX64.EFI'}
    )
    $planned=@($AssetManifest.Files.PSObject.Properties.Name|ForEach-Object{'EFI\SecretoBoot\'+$_.Replace('/','\')})+@('EFI\SecretoBoot\refind.conf','EFI\SecretoBoot\ownership-manifest.json')
    return [pscustomobject][ordered]@{
        SchemaVersion='v9-refind-fast-path-preview-1';Status=if($windowsResolved-and$blissResolved){'PASS'}else{'PARTIAL'}
        RefindStatus='BundledVerifiedPreviewOnly';RefindVersion='0.14.2';EspCandidatesConsidered=$esp.Count;WindowsCanonicalLoaderMatches=$windows.Count;ResolvedWindowsEsp=$windowsResolved;TargetEspStatus=if($windowsResolved){'ResolvedByCanonicalWindowsLoader'}elseif($windows.Count-gt1){'AmbiguousCandidates'}else{'NeedsCanonicalEvidence'}
        TargetEspReasonCode=if($windowsResolved){'REFIND_WINDOWS_ESP_RESOLVED'}elseif($windows.Count-gt1){'REFIND_WINDOWS_CANONICAL_LOADER_AMBIGUOUS'}else{'REFIND_WINDOWS_CANONICAL_LOADER_NOT_FOUND'};TargetEspPartitionGuid=$targetEsp;TargetEspDiskGuid=$windowsDisk;WindowsLoaderStatus=if($windowsResolved){'Resolved'}elseif($windows.Count-gt1){'AmbiguousCandidates'}else{'NeedsCanonicalEvidence'};WindowsLoaderPath='\EFI\Microsoft\Boot\bootmgfw.efi'
        BlissFat32CandidatesConsidered=$blissFat32Candidates.Count;BlissCanonicalChainMatches=$bliss.Count;ResolvedBlissBootVolume=$blissResolved;BlissBootVolumeStatus=if($blissResolved){'ResolvedByCanonicalBlissChain'}elseif($bliss.Count-gt1){'AmbiguousCandidates'}else{'NeedsCanonicalEvidence'};BlissReasonCode=if($blissResolved){'REFIND_BLISS_BOOT_VOLUME_RESOLVED'}elseif($bliss.Count-gt1){'REFIND_BLISS_CANONICAL_CHAIN_AMBIGUOUS'}else{'REFIND_BLISS_CANONICAL_CHAIN_NOT_FOUND'};BlissBootPartitionGuid=$blissPartition;BlissBootDiskGuid=$blissDisk;BlissLoaderStatus=if($blissResolved){'Resolved'}elseif($bliss.Count-gt1){'AmbiguousCandidates'}else{'NeedsCanonicalEvidence'};BlissLoaderPath='\EFI\BOOT\BOOTX64.EFI'
        PlannedEfiDirectory='\EFI\SecretoBoot\';MenuEntries=$entries;ConfigText=$config.ToArray()-join"`r`n";PlannedFiles=@($planned|Sort-Object -Unique);ResolutionDiagnostics=@($ResolutionDiagnostics)
        BackupPlan=@('Refuse an existing unowned EFI\SecretoBoot directory.','Before writes, back up only colliding SecretoBoot-owned paths and record SHA-256 values.','Capture the existing firmware entry inventory read-only before any proposed change.','Never overwrite EFI\Microsoft or EFI\BOOT.');RollbackPlan=@('Restore only manifest-backed SecretoBoot-owned files.','Remove only a newly created SecretoBoot firmware entry by its recorded identity.','Preserve every pre-existing firmware entry and its order.','Verify Windows and Bliss source loaders remain byte-identical.')
        FirmwarePlan=@('Create one new SecretoBoot firmware entry for \EFI\SecretoBoot\refind_x64.efi only after separate approval.','Do not delete or reorder existing entries.','Do not change BootOrder or BootNext in this preview.')
        DeploymentStatus='NOT DEPLOYED';DeploymentAuthorized=$false;DeploymentExecutorIncluded=$false;SecureBootCompatibility='MustBeValidatedBeforeDeploy'
        SafetyCounters=[pscustomobject][ordered]@{EfiReadsAdded=0;EfiWrites=0;BcdWrites=0;NvramWrites=0;BootOrderChanges=0;PartitionWrites=0;Mounts=0;DriveLetterAssignments=0;RefindInstallations=0;Reboots=0;Network=0}
    }
}

function New-SbUnavailableRefindSetupPreview {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('REFIND_SETUP_PREVIEW_FAILED','REFIND_SETUP_ASSET_MANIFEST_DENIED','REFIND_SETUP_RESOURCE_CAP_EXCEEDED','REFIND_SETUP_BLISS_RESOURCE_CAP_EXCEEDED')][string]$ReasonCode,
        [AllowNull()][string]$ExceptionType='Unavailable',
        [AllowNull()][string]$SafeMessage='Preview planning failed closed.',
        [AllowNull()][string]$DependencyAvailability='RefindSetupPreview=Present; RefindAssets=Unknown'
    )
    $safeType=if($ExceptionType-match'^[A-Za-z0-9._+]{1,160}$'){$ExceptionType}else{'Unavailable'}
    $safeText=([string]$SafeMessage)-replace'[\x00-\x1f\x7f]',' '
    $safeText=$safeText-replace'(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}','[REDACTED-GUID]'
    $safeText=$safeText-replace'(?i)(?:[A-Z]:\\|\\\\\?\\)[^\r\n;]+','[REDACTED-PATH]'
    if($safeText.Length-gt240){$safeText=$safeText.Substring(0,240)}
    if($DependencyAvailability-notmatch'^[A-Za-z0-9=; ]{1,240}$'){$DependencyAvailability='RefindSetupPreview=Present; RefindAssets=Unknown'}
    return [pscustomobject][ordered]@{
        SchemaVersion='v9-refind-fast-path-preview-1';Status='PARTIAL';RefindStatus='PreviewUnavailableFailClosed';RefindVersion='0.14.2';FailureReasonCode=$ReasonCode;FailureExceptionType=$safeType;FailureSafeMessage=$safeText;FailureComponent='RefindSetupPreview';DependencyAvailability=$DependencyAvailability
        EspCandidatesConsidered=0;WindowsCanonicalLoaderMatches=0;ResolvedWindowsEsp=$false;TargetEspStatus='NotEvaluated';TargetEspReasonCode='REFIND_SETUP_NOT_EVALUATED';TargetEspPartitionGuid=$null;TargetEspDiskGuid=$null;WindowsLoaderStatus='NotEvaluated';WindowsLoaderPath='\EFI\Microsoft\Boot\bootmgfw.efi'
        BlissFat32CandidatesConsidered=0;BlissCanonicalChainMatches=0;ResolvedBlissBootVolume=$false;BlissBootVolumeStatus='NotEvaluated';BlissReasonCode='REFIND_SETUP_NOT_EVALUATED';BlissBootPartitionGuid=$null;BlissBootDiskGuid=$null;BlissLoaderStatus='NotEvaluated';BlissLoaderPath='\EFI\BOOT\BOOTX64.EFI'
        PlannedEfiDirectory='\EFI\SecretoBoot\';MenuEntries=@();ConfigText='# rEFInd setup preview unavailable; deployment remains denied.';PlannedFiles=@();ResolutionDiagnostics=@();BackupPlan=@('No deployment plan is valid while preview generation is unavailable.');RollbackPlan=@('No deployment occurred.');FirmwarePlan=@('No firmware change is authorized.')
        DeploymentStatus='NOT DEPLOYED';DeploymentAuthorized=$false;DeploymentExecutorIncluded=$false;SecureBootCompatibility='MustBeValidatedBeforeDeploy'
        SafetyCounters=[pscustomobject][ordered]@{EfiReadsAdded=0;EfiWrites=0;BcdWrites=0;NvramWrites=0;BootOrderChanges=0;PartitionWrites=0;Mounts=0;DriveLetterAssignments=0;RefindInstallations=0;Reboots=0;Network=0}
    }
}

function Format-SbRefindSetupPreview {
    param([Parameter(Mandatory)][object]$Preview)
    $lines=[Collections.Generic.List[string]]::new()
    foreach($line in @('SecretoBoot V9 - rEFInd Setup Preview',("Deployment status: {0}"-f$Preview.DeploymentStatus),("rEFInd status: {0} ({1})"-f$Preview.RefindStatus,$Preview.RefindVersion),("ESP candidates considered: {0}"-f$Preview.EspCandidatesConsidered),("Windows canonical-loader matches: {0}"-f$Preview.WindowsCanonicalLoaderMatches),("Resolved Windows ESP: {0}"-f$Preview.ResolvedWindowsEsp),("Windows resolution reason: {0}"-f$Preview.TargetEspReasonCode),("Target ESP: {0}"-f$Preview.TargetEspStatus),("Target ESP stable partition GUID: {0}"-f$(if($Preview.TargetEspPartitionGuid){$Preview.TargetEspPartitionGuid}else{'UNRESOLVED'})),("Windows loader: {0} {1}"-f$Preview.WindowsLoaderStatus,$Preview.WindowsLoaderPath),("Bliss FAT32 candidates considered: {0}"-f$Preview.BlissFat32CandidatesConsidered),("Bliss canonical-chain matches: {0}"-f$Preview.BlissCanonicalChainMatches),("Resolved Bliss boot volume: {0}"-f$Preview.ResolvedBlissBootVolume),("Bliss resolution reason: {0}"-f$Preview.BlissReasonCode),("Bliss boot volume: {0}"-f$Preview.BlissBootVolumeStatus),("Bliss stable partition GUID: {0}"-f$(if($Preview.BlissBootPartitionGuid){$Preview.BlissBootPartitionGuid}else{'UNRESOLVED'})),("Bliss EFI loader: {0} {1}"-f$Preview.BlissLoaderStatus,$Preview.BlissLoaderPath),("Planned directory: {0}"-f$Preview.PlannedEfiDirectory),'','Generated refind.conf:','-------------------------',$Preview.ConfigText,'','Files that would be installed:')){$lines.Add([string]$line)}
    foreach($file in $Preview.PlannedFiles){$lines.Add('  '+$file)}
    $lines.Add('');$lines.Add('rEFInd Resolution Diagnostics (read-only observations):')
    foreach($candidate in @($Preview.ResolutionDiagnostics)){$lines.Add(("[{0}] {1}"-f$candidate.CandidateKind,$candidate.CandidateId));$lines.Add(("  Filesystem: {0}"-f$candidate.Filesystem));$lines.Add(("  Usable Volume-GUID access path: {0}"-f$candidate.UsableVolumeGuidAccessPath));foreach($path in @($candidate.PathDiagnostics)){$lines.Add(("  Path: {0}"-f$path.RelativePath));$lines.Add(("    Open attempted: {0}; Exists: {1}; Containment: {2}; Regular file: {3}; Validation: {4}; Reason: {5}"-f$path.OpenAttempted,$path.Exists,$path.ContainmentResult,$(if('RegularFileResult'-in$path.PSObject.Properties.Name){$path.RegularFileResult}else{'NotReported'}),$path.ValidationResult,$path.FailureReason))};$lines.Add(("  Bliss identity/parser: {0}"-f$candidate.IdentityParserResult));$lines.Add(("  Stable failure reason: {0}"-f$candidate.FailureReason))}
    $lines.Add('');$lines.Add('Backup plan:');foreach($item in $Preview.BackupPlan){$lines.Add('  - '+$item)}
    $lines.Add('Rollback plan:');foreach($item in $Preview.RollbackPlan){$lines.Add('  - '+$item)}
    $lines.Add('Firmware plan:');foreach($item in $Preview.FirmwarePlan){$lines.Add('  - '+$item)}
    $lines.Add('Secure Boot: '+$Preview.SecureBootCompatibility);$lines.Add('Deployment authorization: False')
    if('FailureReasonCode'-in$Preview.PSObject.Properties.Name){$lines.Add('');$lines.Add('Safe preview failure diagnostic:');$lines.Add('  Exception type: '+$Preview.FailureExceptionType);$lines.Add('  Safe exception message: '+$Preview.FailureSafeMessage);$lines.Add('  Failing stage/component: '+$Preview.FailureComponent);$lines.Add('  Required packaged dependencies/resources: '+$Preview.DependencyAvailability);$lines.Add('  Reason code: '+$Preview.FailureReasonCode)}
    return $lines.ToArray()-join"`r`n"
}

Export-ModuleMember -Function Test-SbRefindAssetManifest,Resolve-SbBlissEfiChainloadCandidates,New-SbRefindResolutionDiagnostics,New-SbRefindSetupPreview,New-SbUnavailableRefindSetupPreview,Format-SbRefindSetupPreview
