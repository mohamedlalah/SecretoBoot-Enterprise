Set-StrictMode -Version Latest

function Get-SbE2EValue {
    param([AllowNull()][object]$Object,[Parameter(Mandatory)][string]$Name)
    if($null-eq$Object-or$Name-notin$Object.PSObject.Properties.Name){return $null}
    return $Object.$Name
}

function ConvertTo-SbE2EGuid {
    param([AllowNull()][object]$Value)
    $parsed=[guid]::Empty
    if(-not[guid]::TryParse([string]$Value,[ref]$parsed)-or$parsed-eq[guid]::Empty){return $null}
    return $parsed.ToString('D').ToUpperInvariant()
}

function Get-SbLinuxDisplayName {
    param([Parameter(Mandatory)][string]$Vendor)
    # An EFI vendor directory alone is not distribution proof.
    return 'Linux'
}

function Resolve-SbGenericLinuxEfiTargets {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$CanonicalEfiEvidence)
    if($CanonicalEfiEvidence.Count-gt4096){throw 'E2E_LINUX_RESOURCE_CAP_EXCEEDED'}
    $reserved=@('microsoft','boot','secretoboot','tools')
    $valid=[Collections.Generic.List[object]]::new()
    foreach($item in $CanonicalEfiEvidence){
        $path=([string](Get-SbE2EValue $item 'RelativePath')).Replace('\','/').TrimStart('/')
        if($path-notmatch'(?i)^EFI/([^/]+)/([^/]+\.efi)$'){continue}
        $vendor=$Matches[1];$file=$Matches[2]
        if($vendor.ToLowerInvariant()-in$reserved){continue}
        $signals=@(Get-SbE2EValue $item 'Signals')
        $linuxShape=$file-match'(?i)^(?:shimx64|grubx64|systemd-bootx64|loaderx64)\.efi$'-or'linux-loader'-in$signals
        if(-not$linuxShape-or[string](Get-SbE2EValue $item 'Kind')-cne'EfiLoader'-or[string](Get-SbE2EValue $item 'ValidationStatus')-cne'Validated'-or[string](Get-SbE2EValue $item 'ContainmentStatus')-cne'Passed'-or(Get-SbE2EValue $item 'IsRegularFile')-ne$true-or[long](Get-SbE2EValue $item 'SizeBytes')-le0){continue}
        $partition=ConvertTo-SbE2EGuid (Get-SbE2EValue $item 'PartitionId');$disk=ConvertTo-SbE2EGuid (Get-SbE2EValue $item 'DiskId')
        if($null-eq$partition-or$null-eq$disk){continue}
        $priority=switch -Regex($file){'(?i)^shimx64\.efi$'{0;break};'(?i)^grubx64\.efi$'{1;break};default{2}}
        $valid.Add([pscustomobject][ordered]@{TargetId=('linux:{0}:{1}'-f$partition,$path.ToLowerInvariant());Family='Linux';DisplayName=Get-SbLinuxDisplayName $vendor;DistributionEvidence=if($vendor.ToLowerInvariant()-in@('ubuntu','fedora','debian','opensuse','arch','linuxmint','zorin')){'EfiVendorCompatible'}else{'GenericValidatedEfiLoader'};Confidence='Probable';PartitionGuid=$partition;DiskGuid=$disk;LoaderPath=('\'+$path.Replace('/','\'));BootMethod='LinuxEfiChainload';Vendor=$vendor;Priority=$priority;EvidenceId=[string](Get-SbE2EValue $item 'EvidenceId');UserConfirmed=$false;BootReady=$true})
    }
    $output=[Collections.Generic.List[object]]::new()
    foreach($group in @($valid|Group-Object PartitionGuid)){
        $preferred=@($group.Group|Sort-Object Priority,LoaderPath|Select-Object -First 1)
        if($preferred.Count){$output.Add($preferred[0])}
    }
    return $output.ToArray()
}

function New-SbEndToEndExperimentalPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$RefindSetupPreview,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$CanonicalEfiEvidence,
        [AllowEmptyCollection()][object[]]$AndroidCanonicalBootChains=@(),
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$RawPartitions,
        [Parameter(Mandatory)][object]$AssetManifest
    )
    if($RawPartitions.Count-gt4096){throw 'E2E_PARTITION_RESOURCE_CAP_EXCEEDED'}
    $entries=[Collections.Generic.List[object]]::new()
    if((Get-SbE2EValue $RefindSetupPreview 'ResolvedWindowsEsp')-eq$true){$entries.Add([pscustomobject][ordered]@{EntryId='windows';DisplayName='Windows';Family='Windows';BootMethod='WindowsEfiChainload';PartitionGuid=[string]$RefindSetupPreview.TargetEspPartitionGuid;DiskGuid=[string]$RefindSetupPreview.TargetEspDiskGuid;LoaderPath='\EFI\Microsoft\Boot\bootmgfw.efi';IconPath='\EFI\SecretoBoot\themes\SecretoBootV9\icons\windows.png';Evidence='Canonical Microsoft PE/x64 loader';UserConfirmed=$false;BootReady=$true})}
    if((Get-SbE2EValue $RefindSetupPreview 'ResolvedBlissBootVolume')-eq$true){$entries.Add([pscustomobject][ordered]@{EntryId='android';DisplayName='Bliss OS';Family='Android';BootMethod='AndroidExistingEfiChainload';PartitionGuid=[string]$RefindSetupPreview.BlissBootPartitionGuid;DiskGuid=[string]$RefindSetupPreview.BlissBootDiskGuid;LoaderPath='\EFI\BOOT\BOOTX64.EFI';IconPath='\EFI\SecretoBoot\themes\SecretoBootV9\icons\bliss.png';Evidence='Validated supported-layout EFI chain';UserConfirmed=$false;BootReady=$true})}
    foreach($linux in @(Resolve-SbGenericLinuxEfiTargets $CanonicalEfiEvidence)){$entries.Add([pscustomobject][ordered]@{EntryId=$linux.TargetId;DisplayName=$linux.DisplayName;Family='Linux';BootMethod='LinuxEfiChainload';PartitionGuid=$linux.PartitionGuid;DiskGuid=$linux.DiskGuid;LoaderPath=$linux.LoaderPath;IconPath='\EFI\SecretoBoot\themes\SecretoBootV9\icons\linux.png';Evidence=$linux.DistributionEvidence;UserConfirmed=$false;BootReady=$true})}
    $deduped=@($entries|Group-Object {([string]$_.PartitionGuid).ToUpperInvariant()+'|'+([string]$_.LoaderPath).ToLowerInvariant()}|ForEach-Object{$_.Group[0]}|Sort-Object Family,DisplayName)
    $targetEsp=ConvertTo-SbE2EGuid (Get-SbE2EValue $RefindSetupPreview 'TargetEspPartitionGuid')
    $config=[Collections.Generic.List[string]]::new();foreach($line in @('# SecretoBoot V9 - generated explicit boot menu','timeout 10','default_selection "Windows"','scanfor manual','showtools reboot,shutdown','include themes/SecretoBootV9/theme.conf','')){$config.Add($line)}
    foreach($entry in $deduped){$safeName=([string]$entry.DisplayName)-replace'["\r\n]','';foreach($line in @(('menuentry "{0}" {{'-f$safeName),('    icon {0}'-f$entry.IconPath),('    volume {0}'-f$entry.PartitionGuid),('    loader {0}'-f$entry.LoaderPath),'}','')){$config.Add($line)}}
    $manual=[Collections.Generic.List[object]]::new()
    foreach($item in $CanonicalEfiEvidence){$path=([string](Get-SbE2EValue $item 'RelativePath')).Replace('/','\').TrimStart('\');if([string](Get-SbE2EValue $item 'ValidationStatus')-cne'Validated'-or[string](Get-SbE2EValue $item 'ContainmentStatus')-cne'Passed'-or(Get-SbE2EValue $item 'IsRegularFile')-ne$true-or$path-notmatch'(?i)^EFI\\.+\.efi$'){continue};$partition=ConvertTo-SbE2EGuid (Get-SbE2EValue $item 'PartitionId');if($partition){$raw=@($RawPartitions|Where-Object{(ConvertTo-SbE2EGuid (Get-SbE2EValue $_ 'PartitionGuid'))-ceq$partition}|Select-Object -First 1);$family=if($path-ieq'EFI\Microsoft\Boot\bootmgfw.efi'){'Windows'}elseif($path-match'(?i)^EFI\\(?!BOOT\\)(?!Microsoft\\)(?!SecretoBoot\\).+\\(?:shimx64|grubx64|systemd-bootx64|loaderx64)\.efi$'){'Linux'}else{'Unknown'};$manual.Add([pscustomobject][ordered]@{CandidateId=[string](Get-SbE2EValue $item 'EvidenceId');FamilyHint=$family;DisplayName=if($family-ceq'Windows'){'Windows'}elseif($family-ceq'Linux'){'Linux (EFI loader)'}else{'Unknown UEFI loader'};PartitionGuid=$partition;DiskGuid=ConvertTo-SbE2EGuid (Get-SbE2EValue $item 'DiskId');DiskNumber=if($raw.Count){Get-SbE2EValue $raw[0] 'DiskNumber'}else{$null};PartitionNumber=if($raw.Count){Get-SbE2EValue $raw[0] 'PartitionNumber'}else{$null};Filesystem=if($raw.Count){[string](Get-SbE2EValue $raw[0] 'Filesystem')}else{'Unknown'};SizeBytes=if($raw.Count){[long](Get-SbE2EValue $raw[0] 'SizeBytes')}else{0};LoaderPath=('\'+$path);Evidence='Validated readable regular PE/x64 EFI loader';ArbitraryPathAllowed=$false})}}
    foreach($chain in $AndroidCanonicalBootChains){if([string](Get-SbE2EValue $chain 'ValidationStatus')-cne'Validated'-or[string](Get-SbE2EValue $chain 'ContainmentStatus')-cne'Passed'-or([string](Get-SbE2EValue $chain 'LoaderPath')).Replace('/','\').TrimStart('\')-ine'EFI\BOOT\BOOTX64.EFI'){continue};$partition=ConvertTo-SbE2EGuid (Get-SbE2EValue $chain 'BootPartitionId');$disk=ConvertTo-SbE2EGuid (Get-SbE2EValue $chain 'DiskId');if($partition-and$disk){$raw=@($RawPartitions|Where-Object{(ConvertTo-SbE2EGuid (Get-SbE2EValue $_ 'PartitionGuid'))-ceq$partition}|Select-Object -First 1);$manual.Add([pscustomobject][ordered]@{CandidateId=[string](Get-SbE2EValue $chain 'EvidenceId');FamilyHint='Android';DisplayName='Bliss OS';PartitionGuid=$partition;DiskGuid=$disk;DiskNumber=if($raw.Count){Get-SbE2EValue $raw[0] 'DiskNumber'}else{$null};PartitionNumber=if($raw.Count){Get-SbE2EValue $raw[0] 'PartitionNumber'}else{$null};Filesystem='FAT32';SizeBytes=if($raw.Count){[long](Get-SbE2EValue $raw[0] 'SizeBytes')}else{0};LoaderPath='\EFI\BOOT\BOOTX64.EFI';Evidence='Validated supported-layout chain: kernel, initrd.img, BOOTX64.EFI, android.cfg, grub.cfg';ArbitraryPathAllowed=$false})}}
    $partitionInventory=@($RawPartitions|ForEach-Object{[pscustomobject][ordered]@{PartitionGuid=ConvertTo-SbE2EGuid (Get-SbE2EValue $_ 'PartitionGuid');DiskGuid=ConvertTo-SbE2EGuid (Get-SbE2EValue $_ 'DiskGuid');PartitionTypeGuid=ConvertTo-SbE2EGuid (Get-SbE2EValue $_ 'PartitionTypeGuid');DiskNumber=[int](Get-SbE2EValue $_ 'TransientDiskNumber');PartitionNumber=[int](Get-SbE2EValue $_ 'TransientPartitionNumber');Filesystem=[string](Get-SbE2EValue $_ 'Filesystem');SizeBytes=[long](Get-SbE2EValue $_ 'SizeBytes')}}|Where-Object{$_.PartitionGuid-and$_.DiskGuid})
    $hybridEligible=$partitionInventory.Count-gt0
    $core=[ordered]@{SchemaVersion='v9-end-to-end-plan-1';Revision='Windows-Desktop-V9-FinalRelease.1-WindowsFirstCompatibilityPreflightFix.1';HybridResolutionRequired=$true;TargetEspPartitionGuid=$targetEsp;TargetEspDiskGuid=ConvertTo-SbE2EGuid (Get-SbE2EValue $RefindSetupPreview 'TargetEspDiskGuid');PartitionInventory=$partitionInventory;InstallDirectory='\EFI\SecretoBoot\';RefindVersion='0.14.2';RefindConfig=($config.ToArray()-join"`r`n");BootEntries=$deduped;ManualConfirmationCandidates=$manual.ToArray();AssetManifestSha256='a818cc7c8d4ac49b2d228cbb1d06ea584fe356c629b7cb73d1ca66c1a95233d9';DeploymentAuthorized=$false;SecureBootRequirement='Disabled';BitLockerRequirement='ProtectionSuspendedByUserOrConfirmedUnaffected';NoDriveLetters=$true;ForbiddenForeignRoots=@('\EFI\Microsoft\','\EFI\BOOT\','Linux vendor directories');AllowedActions=@('Install','InstallAndTestNextBoot','UpgradeAndTestNextBoot','RepairFirmwareEntry','TestNextBoot','MakeDefault','EnableWindowsFirstCompatibility','RestoreNativeWindowsBoot','RestorePreviousDefault','Rollback','Uninstall','Recover')}
    $json=$core|ConvertTo-Json -Depth 12 -Compress;$digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($json))).ToLowerInvariant()
    return [pscustomobject][ordered]@{SchemaVersion='v9-end-to-end-envelope-1';Status=if($targetEsp-and$deduped.Count){'ReadyForSecurityPreflight'}elseif($hybridEligible){'ReadyForElevatedHybridResolution'}else{'ManualConfirmationRequired'};Revision='Windows-Desktop-V9-FinalRelease.1-WindowsFirstCompatibilityPreflightFix.1';Deployable=$hybridEligible;PlanCoreJson=$json;PlanDigest=$digest;BootEntries=$deduped;ManualConfirmationCandidates=$manual.ToArray();DeploymentAuthorized=$false;EfiWrites=0;FirmwareWrites=0;BcdWrites=0}
}

Export-ModuleMember -Function Resolve-SbGenericLinuxEfiTargets,New-SbEndToEndExperimentalPlan
