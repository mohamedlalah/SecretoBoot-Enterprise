Set-StrictMode -Version Latest

function Get-SbCanonicalValue([object]$Object, [string]$Name) {
    if ($null -eq $Object -or $Name -notin $Object.PSObject.Properties.Name) { return $null }
    return $Object.$Name
}

function Test-SbCanonicalGuid([object]$Value) {
    $parsed = [guid]::Empty
    return [guid]::TryParse([string]$Value, [ref]$parsed) -and $parsed -ne [guid]::Empty
}

function Test-SbCanonicalEvidence([object]$Evidence) {
    $size = [long](Get-SbCanonicalValue $Evidence 'SizeBytes')
    return (Get-SbCanonicalValue $Evidence 'ValidationStatus') -ceq 'Validated' -and
        (Get-SbCanonicalValue $Evidence 'ContainmentStatus') -ceq 'Passed' -and
        (Get-SbCanonicalValue $Evidence 'IsRegularFile') -eq $true -and
        $size -gt 0 -and $size -le 17179869184
}

function Test-SbCanonicalSignals([object]$Evidence, [string[]]$Required) {
    $signals = @((Get-SbCanonicalValue $Evidence 'Signals'))
    return @($Required | Where-Object { $_ -notin $signals }).Count -eq 0
}

function Get-SbCanonicalTargetId([string]$Value) {
    $hash = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Value))
    return 'target:' + [Convert]::ToHexString($hash).Substring(0, 20).ToLowerInvariant()
}

function New-SbCanonicalTarget {
    param([object]$System,[string]$BootMethod,[AllowNull()][string]$LoaderPath,[AllowNull()][string]$KernelPath,[AllowNull()][string]$InitrdPath,[AllowNull()][string]$RootReference,[AllowNull()][string]$BootArguments,[string]$PartitionId,[string]$DiskId,[object[]]$Evidence)
    $source = [string]$System.ConsolidatedSystemId
    return [pscustomobject][ordered]@{
        TargetId = Get-SbCanonicalTargetId ($source + '|' + $BootMethod + '|' + $PartitionId)
        SourceSystemId = $source
        Family = [string]$System.Family
        BootMethod = $BootMethod
        LoaderPath = $LoaderPath
        KernelPath = $KernelPath
        InitrdPath = $InitrdPath
        RootReference = $RootReference
        BootArguments = $BootArguments
        SourcePartitionId = $PartitionId
        SourceDiskId = $DiskId
        EvidenceIds = @($Evidence | ForEach-Object { [string]$_.EvidenceId } | Sort-Object -Unique)
        Confidence = 'Confirmed'
        ValidationStatus = 'Validated'
        ReasonCodes = @('BOOT_TARGET_CANONICAL_EVIDENCE_VALIDATED')
    }
}

function Resolve-SbCanonicalBootTargets {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ConsolidatedSystems,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Evidence,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Correlations
    )
    if ($ConsolidatedSystems.Count -gt 4096 -or $Evidence.Count -gt 16384 -or $Correlations.Count -gt 32768) { throw 'BOOT_TARGET_RESOURCE_CAP_EXCEEDED' }
    $targets = [Collections.Generic.List[object]]::new()
    foreach ($system in $ConsolidatedSystems) {
        $candidateIds = @($system.CandidateReferences | ForEach-Object { [string]$_.SystemId })
        $evidenceIds = @($Correlations | Where-Object {
            [string]$_.SystemId -in $candidateIds -and $_.Relationship -ceq 'Corroborates' -and $_.RootPartitionResolved -eq $true
        } | ForEach-Object { [string]$_.EvidenceId } | Sort-Object -Unique)
        $items = @($Evidence | Where-Object { [string]$_.EvidenceId -in $evidenceIds })

        if ($system.Family -ceq 'Windows' -and $system.Confidence -ceq 'Confirmed') {
            $loaders = @($items | Where-Object {
                (Get-SbCanonicalValue $_ 'Kind') -ceq 'EfiLoader' -and
                ([string](Get-SbCanonicalValue $_ 'RelativePath')).Replace('\','/').ToLowerInvariant() -ceq 'efi/microsoft/boot/bootmgfw.efi' -and
                (Test-SbCanonicalEvidence $_) -and
                (Test-SbCanonicalSignals $_ @('valid-efi-loader','microsoft-vendor-path','windows-installation-related','esp-partition-related')) -and
                (Test-SbCanonicalGuid (Get-SbCanonicalValue $_ 'PartitionId')) -and (Test-SbCanonicalGuid (Get-SbCanonicalValue $_ 'DiskId'))
            })
            if ($loaders.Count -eq 1) { $targets.Add((New-SbCanonicalTarget $system 'UefiLoader' '/EFI/Microsoft/Boot/bootmgfw.efi' $null $null $null $null ([string]$loaders[0].PartitionId) ([string]$loaders[0].DiskId) $loaders)) }
            continue
        }

        if ($system.Family -ceq 'Linux') {
            $loaders = @($items | Where-Object {
                (Get-SbCanonicalValue $_ 'Kind') -ceq 'EfiLoader' -and ([string](Get-SbCanonicalValue $_ 'RelativePath')) -match '(?i)^efi/[a-z0-9._+-]+/[a-z0-9._+-]+\.efi$' -and
                (Test-SbCanonicalEvidence $_) -and (Test-SbCanonicalSignals $_ @('valid-efi-loader','linux-loader','linux-system-related','root-reference-validated')) -and
                (Test-SbCanonicalGuid (Get-SbCanonicalValue $_ 'PartitionId')) -and (Test-SbCanonicalGuid (Get-SbCanonicalValue $_ 'DiskId')) -and
                -not [string]::IsNullOrWhiteSpace([string](Get-SbCanonicalValue $_ 'RootReference'))
            })
            if ($loaders.Count -eq 1) {
                $path = '/' + ([string]$loaders[0].RelativePath).Replace('\','/')
                $targets.Add((New-SbCanonicalTarget $system 'UefiLoader' $path $null $null ([string]$loaders[0].RootReference) $null ([string]$loaders[0].PartitionId) ([string]$loaders[0].DiskId) $loaders))
            }
            continue
        }

        if ($system.Family -ceq 'Android') {
            $valid = @($items | Where-Object { Test-SbCanonicalEvidence $_ })
            $bootChains = @($items | Where-Object {
                (Get-SbCanonicalValue $_ 'Kind') -ceq 'AndroidCanonicalBootChain' -and
                (Get-SbCanonicalValue $_ 'ValidationStatus') -ceq 'Validated' -and
                (Get-SbCanonicalValue $_ 'ContainmentStatus') -ceq 'Passed' -and
                (Get-SbCanonicalValue $_ 'BootMethod') -ceq 'AndroidInitrdRuntimeDiscovery' -and
                (Get-SbCanonicalValue $_ 'RuntimeSystemDiscovery') -ceq 'Proven' -and
                (Get-SbCanonicalValue $_ 'SrcBehavior') -ceq 'Runtime' -and
                (Get-SbCanonicalValue $_ 'SystemPartitionRequiredAtGrubStage') -eq $false -and
                (Test-SbCanonicalSignals $_ @('android-canonical-boot-chain','approved-source-reference','android-config-canonical','valid-efi-loader','android-kernel','android-initrd','initrd-runtime-system-discovery','initrd-system-image-search','initrd-local-filesystem-scan')) -and
                (Test-SbCanonicalGuid (Get-SbCanonicalValue $_ 'BootPartitionId')) -and
                (Test-SbCanonicalGuid (Get-SbCanonicalValue $_ 'DiskId')) -and
                @((Get-SbCanonicalValue $_ 'ComponentEvidenceIds')).Count -eq 5 -and
                ([string](Get-SbCanonicalValue $_ 'LoaderPath')).Replace('\','/') -ieq 'EFI/BOOT/BOOTX64.EFI' -and
                ([string](Get-SbCanonicalValue $_ 'DispatcherPath')).Replace('\','/') -ieq 'boot/grub/grub.cfg' -and
                ([string](Get-SbCanonicalValue $_ 'CanonicalConfigPath')).Replace('\','/') -ieq 'EFI/BOOT/android.cfg' -and
                ([string](Get-SbCanonicalValue $_ 'KernelPath')).Replace('\','/') -ieq 'kernel' -and
                ([string](Get-SbCanonicalValue $_ 'InitrdPath')).Replace('\','/') -ieq 'initrd.img' -and
                [string](Get-SbCanonicalValue $_ 'Distribution') -match '^BlissOS [0-9]+(?:\.[0-9]+){1,3}$'
            })
            if($bootChains.Count-eq1){$chain=$bootChains[0];$targets.Add((New-SbCanonicalTarget $system 'AndroidInitrdRuntimeDiscovery' '/EFI/BOOT/BOOTX64.EFI' '/kernel' '/initrd.img' $null $null ([string]$chain.BootPartitionId) ([string]$chain.DiskId) @($chain)));continue}
            $relationships = @($items | Where-Object {
                (Get-SbCanonicalValue $_ 'Kind') -ceq 'AndroidInstallationRelationship' -and
                (Get-SbCanonicalValue $_ 'ValidationStatus') -ceq 'Validated' -and
                (Get-SbCanonicalValue $_ 'ContainmentStatus') -ceq 'Passed' -and
                (Get-SbCanonicalValue $_ 'BootArgumentsValidated') -eq $true -and
                (Test-SbCanonicalSignals $_ @('android-installation-relationship','android-boot-chain-validated','root-reference-validated','valid-efi-loader')) -and
                (Test-SbCanonicalGuid (Get-SbCanonicalValue $_ 'BootPartitionId')) -and
                (Test-SbCanonicalGuid (Get-SbCanonicalValue $_ 'SystemPartitionId')) -and
                (Test-SbCanonicalGuid (Get-SbCanonicalValue $_ 'DiskId')) -and
                [string](Get-SbCanonicalValue $_ 'BootPartitionId') -cne [string](Get-SbCanonicalValue $_ 'SystemPartitionId') -and
                @((Get-SbCanonicalValue $_ 'ComponentEvidenceIds')).Count -ge 5 -and
                ([string](Get-SbCanonicalValue $_ 'LoaderPath')).Replace('\','/') -match '(?i)^EFI/BOOT/[A-Za-z0-9._+-]+\.EFI$' -and
                ([string](Get-SbCanonicalValue $_ 'KernelPath')).Replace('\','/') -match '^[A-Za-z0-9._+/-]+$' -and
                ([string](Get-SbCanonicalValue $_ 'InitrdPath')).Replace('\','/') -match '^[A-Za-z0-9._+/-]+$' -and
                ([string](Get-SbCanonicalValue $_ 'SystemImagePath')).Replace('\','/') -match '^[A-Za-z0-9._+/-]+$' -and
                [string](Get-SbCanonicalValue $_ 'RootReferenceType') -in @('PARTUUID','UUID','LABEL') -and
                -not [string]::IsNullOrWhiteSpace([string](Get-SbCanonicalValue $_ 'RootReference'))
            })
            if($relationships.Count -eq 1){
                $relationship=$relationships[0];$arguments=[string]$relationship.BootArguments
                if($arguments.Length-le2048-and$arguments-notmatch'[\x00-\x1f\x7f"]'){
                    $targets.Add((New-SbCanonicalTarget $system 'UefiLoader' ('/'+([string]$relationship.LoaderPath).Replace('\','/')) ('/'+([string]$relationship.KernelPath).Replace('\','/')) ('/'+([string]$relationship.InitrdPath).Replace('\','/')) ([string]$relationship.RootReference) $arguments ([string]$relationship.BootPartitionId) ([string]$relationship.DiskId) @($relationship)))
                }
                continue
            }
            $configs = @($valid | Where-Object {
                (Get-SbCanonicalValue $_ 'Kind') -ceq 'BootConfig' -and
                (Test-SbCanonicalSignals $_ @('android-boot-config','android-boot-arguments','root-reference-validated')) -and
                -not [string]::IsNullOrWhiteSpace([string](Get-SbCanonicalValue $_ 'BootArguments')) -and
                -not [string]::IsNullOrWhiteSpace([string](Get-SbCanonicalValue $_ 'RootReference'))
            })
            if ($configs.Count -ne 1) { continue }
            $partition = [string]$configs[0].PartitionId; $disk = [string](Get-SbCanonicalValue $configs[0] 'DiskId')
            if (-not (Test-SbCanonicalGuid $partition) -or -not (Test-SbCanonicalGuid $disk)) { continue }
            $prefix = ([string]$configs[0].RelativePath).Replace('\','/'); $slash = $prefix.LastIndexOf('/'); $prefix = if ($slash -ge 0) { $prefix.Substring(0,$slash+1) } else { '' }
            $kernel = @($valid | Where-Object { [string]$_.PartitionId -ceq $partition -and ([string]$_.RelativePath).Replace('\','/').ToLowerInvariant() -ceq ($prefix+'kernel').ToLowerInvariant() -and (Test-SbCanonicalSignals $_ @('android-kernel')) })
            $initrd = @($valid | Where-Object { [string]$_.PartitionId -ceq $partition -and ([string]$_.RelativePath).Replace('\','/').ToLowerInvariant() -in @(($prefix+'initrd.img').ToLowerInvariant(),($prefix+'ramdisk.img').ToLowerInvariant()) -and (Test-SbCanonicalSignals $_ @('android-initrd')) })
            $systemImage = @($valid | Where-Object { [string]$_.PartitionId -ceq $partition -and ([string]$_.RelativePath).Replace('\','/').ToLowerInvariant() -in @(($prefix+'system.sfs').ToLowerInvariant(),($prefix+'system.img').ToLowerInvariant()) -and (Test-SbCanonicalSignals $_ @('android-system-image')) })
            $arguments = [string]$configs[0].BootArguments
            if ($kernel.Count -eq 1 -and $initrd.Count -eq 1 -and $systemImage.Count -eq 1 -and $arguments.Length -le 2048 -and $arguments -notmatch '[\x00-\x1f\x7f"]') {
                $all = @($configs[0],$kernel[0],$initrd[0],$systemImage[0])
                $targets.Add((New-SbCanonicalTarget $system 'KernelInitrd' $null ('/'+([string]$kernel[0].RelativePath).Replace('\','/')) ('/'+([string]$initrd[0].RelativePath).Replace('\','/')) ([string]$configs[0].RootReference) $arguments $partition $disk $all))
            }
        }
    }
    $reusedEvidence = @($targets | ForEach-Object EvidenceIds | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
    if ($reusedEvidence.Count) { return @($targets | Where-Object { @($_.EvidenceIds | Where-Object { $_ -in $reusedEvidence }).Count -eq 0 }) }
    return $targets.ToArray()
}

Export-ModuleMember -Function Resolve-SbCanonicalBootTargets
