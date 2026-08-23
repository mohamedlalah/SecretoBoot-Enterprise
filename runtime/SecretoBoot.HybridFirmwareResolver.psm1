Set-StrictMode -Version Latest

function Get-SbHybridValue {
    param([AllowNull()][object]$Object,[Parameter(Mandatory)][string]$Name)
    if($null-eq$Object-or$Name-notin$Object.PSObject.Properties.Name){return $null}
    return $Object.$Name
}

function ConvertTo-SbHybridGuid {
    param([AllowNull()][object]$Value)
    $parsed=[guid]::Empty
    if(-not[guid]::TryParse([string]$Value,[ref]$parsed)-or$parsed-eq[guid]::Empty){return $null}
    return $parsed.ToString('D').ToUpperInvariant()
}

function Normalize-SbHybridEfiPath {
    param([AllowNull()][object]$Value)
    $path=([string]$Value).Replace('/','\')
    if($path-notmatch'^\\EFI\\[A-Za-z0-9._ -]+(?:\\[A-Za-z0-9._ -]+)*\.efi$'){return $null}
    return '\'+$path.TrimStart('\')
}

function Get-SbHybridFriendlyName {
    param([Parameter(Mandatory)][string]$Role,[AllowNull()][string]$Description)
    if($Role-ceq'Windows'){return 'Windows'}
    if($Role-ceq'Bliss'){return 'Bliss OS'}
    switch -Regex (([string]$Description).Trim()){
        '^(?i:zorin(?: os)?)$' {return 'Zorin OS'}
        '^(?i:ubuntu)$' {return 'Ubuntu'}
        '^(?i:fedora)$' {return 'Fedora'}
        '^(?i:debian)$' {return 'Debian'}
        default {return 'Linux'}
    }
}

function Resolve-SbHybridFirmwareCandidates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FirmwareEntries,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$PartitionInventory
    )
    if($FirmwareEntries.Count-gt4096-or$PartitionInventory.Count-gt4096){throw 'HYBRID_RESOLUTION_RESOURCE_CAP_EXCEEDED'}
    $partitions=@{};foreach($partition in $PartitionInventory){$guid=ConvertTo-SbHybridGuid (Get-SbHybridValue $partition 'PartitionGuid');$disk=ConvertTo-SbHybridGuid (Get-SbHybridValue $partition 'DiskGuid');if($guid-and$disk-and-not$partitions.ContainsKey($guid)){$partitions[$guid]=$partition}}
    $result=[Collections.Generic.List[object]]::new()
    foreach($firmware in $FirmwareEntries){
        if([string](Get-SbHybridValue $firmware 'ValidationState')-cne'FirmwareLoadOptionValidated'){continue}
        $guid=ConvertTo-SbHybridGuid (Get-SbHybridValue $firmware 'StablePartitionGuid');$path=Normalize-SbHybridEfiPath (Get-SbHybridValue $firmware 'EfiPath');if(-not$guid-or-not$path-or-not$partitions.ContainsKey($guid)){continue}
        $description=([string](Get-SbHybridValue $firmware 'Description')).Trim();$role=$null;$display=$description;$method=$null
        if($description-ieq'Windows EFI Boot Manager'-and$path-ieq'\EFI\Microsoft\Boot\bootmgfw.efi'){$role='Windows';$display='Windows';$method='WindowsEfiChainload'}
        elseif($description-ieq'UEFI OS'-and$path-ieq'\EFI\BOOT\BOOTX64.EFI'){$role='Bliss';$display='Bliss OS';$method='AndroidExistingEfiChainload'}
        elseif($path-match'(?i)^\\EFI\\(?!Microsoft\\|BOOT\\|SecretoBoot\\)([A-Za-z0-9._ -]+)\\(?:shimx64|grubx64|systemd-bootx64|loaderx64)\.efi$'){$role='Linux';$method='LinuxEfiChainload';if(-not$display){$display='Linux ('+$Matches[1]+')'}}
        if(-not$role){continue};$display=Get-SbHybridFriendlyName $role $display;$partition=$partitions[$guid]
        $result.Add([pscustomobject][ordered]@{FirmwareIdentifier=[string](Get-SbHybridValue $firmware 'FirmwareIdentifier');FirmwareEntryNumber=[int](Get-SbHybridValue $firmware 'EntryNumber');FirmwareDescription=$description;DeviceReference=[string](Get-SbHybridValue $firmware 'DeviceReference');EfiPath=$path;PartitionGuid=$guid;DiskGuid=ConvertTo-SbHybridGuid (Get-SbHybridValue $partition 'DiskGuid');DiskNumber=[int](Get-SbHybridValue $partition 'DiskNumber');PartitionNumber=[int](Get-SbHybridValue $partition 'PartitionNumber');Filesystem=[string](Get-SbHybridValue $partition 'Filesystem');SizeBytes=[long](Get-SbHybridValue $partition 'SizeBytes');Role=$role;DisplayName=$display;BootMethod=$method;ValidationState='FirmwareAndStorageMapped';UserConfirmed=$false})
    }
    return @($result|Group-Object{([string]$_.PartitionGuid).ToUpperInvariant()+'|'+([string]$_.EfiPath).ToLowerInvariant()}|ForEach-Object{$_.Group[0]}|Sort-Object Role,DisplayName)
}

function Resolve-SbHybridStorageCorrelation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid]$FirmwarePartitionGuid,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$StoragePartitions,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$CimPartitions
    )
    if($FirmwarePartitionGuid-eq[guid]::Empty){return [pscustomobject]@{Status='Denied';Reason='INVALID_FIRMWARE_DEVICE_PATH';Backend='None';Matches=0;Partition=$null}}
    if($StoragePartitions.Count-gt4096-or$CimPartitions.Count-gt4096){return [pscustomobject]@{Status='Denied';Reason='STORAGE_QUERY_FAILED';Backend='ResourceCap';Matches=0;Partition=$null}}
    $wanted=$FirmwarePartitionGuid.ToString('D').ToUpperInvariant();$storage=@($StoragePartitions|Where-Object{(ConvertTo-SbHybridGuid (Get-SbHybridValue $_ 'Guid'))-ceq$wanted})
    if($storage.Count-gt1){return [pscustomobject]@{Status='Denied';Reason='AMBIGUOUS';Backend='TrustedStorage.GetPartition';Matches=$storage.Count;Partition=$null}}
    if($storage.Count-eq1){return [pscustomobject]@{Status='Resolved';Reason='RESOLVED';Backend='TrustedStorage.GetPartition';Matches=1;Partition=$storage[0]}}
    $cim=@($CimPartitions|Where-Object{(ConvertTo-SbHybridGuid (Get-SbHybridValue $_ 'Guid'))-ceq$wanted})
    if($cim.Count-gt1){return [pscustomobject]@{Status='Denied';Reason='AMBIGUOUS';Backend='TrustedCim.MSFT_Partition';Matches=$cim.Count;Partition=$null}}
    if($cim.Count-eq1){return [pscustomobject]@{Status='Resolved';Reason='RESOLVED';Backend='TrustedCim.MSFT_Partition';Matches=1;Partition=$cim[0]}}
    return [pscustomobject]@{Status='Denied';Reason='NOT_FOUND';Backend='TrustedStorage+TrustedCim';Matches=0;Partition=$null}
}

function New-SbHybridRefindConfig {
    [CmdletBinding()]param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ValidatedTargets)
    if($ValidatedTargets.Count-gt256){throw 'HYBRID_CONFIG_RESOURCE_CAP_EXCEEDED'}
    $lines=[Collections.Generic.List[string]]::new();foreach($line in @('# SecretoBoot V9 - generated explicit hybrid firmware/storage menu','timeout 10','default_selection "Windows"','scanfor manual','showtools reboot,shutdown','include themes/SecretoBootV9/theme.conf','')){$lines.Add($line)}
    foreach($target in @($ValidatedTargets|Sort-Object Role,DisplayName)){$guid=ConvertTo-SbHybridGuid $target.PartitionGuid;$path=Normalize-SbHybridEfiPath $target.EfiPath;$name=([string]$target.DisplayName)-replace'["\r\n]','';if(-not$guid-or-not$path-or-not$name){throw 'HYBRID_CONFIG_TARGET_DENIED'};$icon=switch([string]$target.Role){'Windows'{'windows.png'};'Bliss'{'bliss.png'};default{'linux.png'}};foreach($line in @(('menuentry "{0}" {{'-f$name),('    icon \EFI\SecretoBoot\themes\SecretoBootV9\icons\{0}'-f$icon),('    volume {0}'-f$guid),('    loader {0}'-f$path),'}','')){$lines.Add($line)}}
    return $lines.ToArray()-join"`r`n"
}

Export-ModuleMember -Function Resolve-SbHybridFirmwareCandidates,Resolve-SbHybridStorageCorrelation,New-SbHybridRefindConfig
