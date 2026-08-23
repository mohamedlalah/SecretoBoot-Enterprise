Set-StrictMode -Version Latest

function Get-SbRelationshipValue {
    param([AllowNull()][object]$Object,[Parameter(Mandatory)][string]$Name)
    if($null-eq$Object-or$Name-notin$Object.PSObject.Properties.Name){return $null}
    return $Object.$Name
}

function Normalize-SbRelationshipIdentifier {
    param([AllowNull()][string]$Value)
    return ([string]$Value).Trim().Trim('{}').Replace('-','').ToUpperInvariant()
}

function Get-SbRelationshipId {
    param([string]$BootId,[string]$SystemId,[string]$ConfigId)
    $bytes=[Text.Encoding]::UTF8.GetBytes("$BootId|$SystemId|$ConfigId")
    return 'relationship:android:'+[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).Substring(0,20).ToLowerInvariant()
}

function Resolve-SbAndroidInstallationRelationships {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$DetectedSystems,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$InspectionResults,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$PartitionInventory
    )
    if($DetectedSystems.Count-gt4096-or$InspectionResults.Count-gt256-or$PartitionInventory.Count-gt4096){throw 'ANDROID_RELATIONSHIP_RESOURCE_CAP_EXCEEDED'}
    $systemByPartition=@{};foreach($system in $DetectedSystems){if([string]$system.CandidateKind-ceq'PartitionCandidate' -and -not[string]::IsNullOrWhiteSpace([string]$system.PartitionId)){$systemByPartition[[string]$system.PartitionId]=$system}}
    $inventoryByOpaque=@{};foreach($partition in $PartitionInventory){if([string]$partition.OpaquePartitionId-notmatch'^report:partition:[0-9a-f]{20}$'-or[string]$partition.RawPartitionId-notmatch'^[0-9a-fA-F-]{36}$'-or[string]$partition.RawDiskId-notmatch'^[0-9a-fA-F-]{36}$'){throw 'ANDROID_RELATIONSHIP_INVENTORY_DENIED'};$inventoryByOpaque[[string]$partition.OpaquePartitionId]=$partition}
    $inspectionByPartition=@{};foreach($inspection in $InspectionResults){$id=[string]$inspection.PartitionId;if($inspectionByPartition.ContainsKey($id)){throw 'ANDROID_RELATIONSHIP_INSPECTION_AMBIGUOUS'};$inspectionByPartition[$id]=$inspection}
    $relationships=[Collections.Generic.List[object]]::new();$bootChains=[Collections.Generic.List[object]]::new();$evidence=[Collections.Generic.List[object]]::new();$correlations=[Collections.Generic.List[object]]::new();$provenMembers=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$identifiedDistributions=@{}
    foreach($bootSystem in @($DetectedSystems|Where-Object{$_.Family-ceq'Android'-and$_.Filesystem-ceq'FAT32'})){
        $bootId=[string]$bootSystem.PartitionId;$reasons=[Collections.Generic.List[string]]::new();if(-not$inspectionByPartition.ContainsKey($bootId)-or[string]$inspectionByPartition[$bootId].Status-cne'Complete'){$reasons.Add('ANDROID_RELATIONSHIP_BOOT_ACCESS_UNAVAILABLE')}
        $bootInspection=if($inspectionByPartition.ContainsKey($bootId)){$inspectionByPartition[$bootId]}else{$null};$bootArtifacts=@(if($null-ne$bootInspection){$bootInspection.Evidence}else{@()})
        $loaders=@($bootArtifacts|Where-Object{$_.Kind-ceq'EfiLoader'-and$_.ValidPeX64-eq$true-and'valid-efi-loader'-in@($_.Signals)})
        $configs=@($bootArtifacts|Where-Object{$_.Kind-ceq'BootConfig'-and$_.BootArgumentsValidated-eq$true-and'root-reference-validated'-in@($_.Signals)})
        $kernels=@($bootArtifacts|Where-Object{$_.Kind-ceq'Kernel'-and'android-kernel'-in@($_.Signals)})
        $initrds=@($bootArtifacts|Where-Object{$_.Kind-ceq'Initrd'-and'android-initrd'-in@($_.Signals)})
        $dispatchers=@($bootArtifacts|Where-Object{$_.Kind-ceq'BootConfig'-and'android-config-dispatcher'-in@($_.Signals)-and'approved-source-reference'-in@($_.Signals)})
        $canonicalConfigs=@($bootArtifacts|Where-Object{$_.Kind-ceq'BootConfig'-and(Get-SbRelationshipValue $_ 'CanonicalConfigValidated')-eq$true-and'android-config-canonical'-in@($_.Signals)})
        if($dispatchers.Count-eq1-and$canonicalConfigs.Count-eq1-and$loaders.Count-eq1-and$inventoryByOpaque.ContainsKey($bootId)){
            $dispatcher=$dispatchers[0];$canonicalConfig=$canonicalConfigs[0];$source=([string]$dispatcher.SourcePath).Replace('\','/').TrimStart('/');$configPath=([string]$canonicalConfig.RelativePath).Replace('\','/').TrimStart('/');$loaderPath=([string]$canonicalConfig.LoaderPath).Replace('\','/').TrimStart('/');$kernelPath=([string]$canonicalConfig.KernelPath).Replace('\','/').TrimStart('/');$initrdPath=([string]$canonicalConfig.InitrdPath).Replace('\','/').TrimStart('/')
            $chainLoader=@($loaders|Where-Object{([string]$_.RelativePath).Replace('\','/').TrimStart('/')-ieq$loaderPath});$chainKernel=@($kernels|Where-Object{([string]$_.RelativePath).Replace('\','/').TrimStart('/')-ieq$kernelPath});$chainInitrd=@($initrds|Where-Object{([string]$_.RelativePath).Replace('\','/').TrimStart('/')-ieq$initrdPath});$configRelationshipValid=$source-ieq'EFI/BOOT/android.cfg'-and$configPath-ieq$source-and[string]$canonicalConfig.Distribution-match'^BlissOS [0-9]+(?:\.[0-9]+){1,3}$';if($configRelationshipValid){$identifiedDistributions[[string]$bootSystem.SystemId]=[string]$canonicalConfig.Distribution}
            $runtimeInitrd=@($chainInitrd|Where-Object{[string](Get-SbRelationshipValue $_ 'InitrdInspectionStatus')-ceq'Validated'-and[string](Get-SbRelationshipValue $_ 'RuntimeDiscoveryStatus')-ceq'Proven'-and[string](Get-SbRelationshipValue $_ 'SrcBehavior')-ceq'Runtime'-and(Get-SbRelationshipValue $_ 'SystemPartitionRequiredAtGrubStage')-eq$false-and'initrd-runtime-system-discovery'-in@($_.Signals)})
            if($configRelationshipValid-and$chainLoader.Count-eq1-and$chainKernel.Count-eq1-and$runtimeInitrd.Count-eq1){
                $chainId=Get-SbRelationshipId $bootId $bootId ([string]$canonicalConfig.EvidenceId);$components=@([string]$chainLoader[0].EvidenceId,[string]$dispatcher.EvidenceId,[string]$canonicalConfig.EvidenceId,[string]$chainKernel[0].EvidenceId,[string]$runtimeInitrd[0].EvidenceId)|Sort-Object -Unique
                $chain=[pscustomobject][ordered]@{EvidenceId=$chainId;EvidenceKind='AndroidCanonicalBootChain';Kind='AndroidCanonicalBootChain';BootMethod='AndroidInitrdRuntimeDiscovery';SourcePartitionToken=$bootId;BootPartitionId=[string]$inventoryByOpaque[$bootId].RawPartitionId;PartitionId=[string]$inventoryByOpaque[$bootId].RawPartitionId;DiskId=[string]$inventoryByOpaque[$bootId].RawDiskId;LoaderPath=$loaderPath;DispatcherPath=([string]$dispatcher.RelativePath).Replace('\','/');CanonicalConfigPath=$configPath;KernelPath=$kernelPath;InitrdPath=$initrdPath;Distribution=[string]$canonicalConfig.Distribution;InitrdInspected=$true;RuntimeSystemDiscovery='Proven';SrcBehavior='Runtime';SystemPartitionRequiredAtGrubStage=$false;RuntimeStorageCorrelationStatus='NeedsRuntimeDiscovery';ComponentEvidenceIds=$components;Signals=@('android-canonical-boot-chain','approved-source-reference','android-config-canonical','valid-efi-loader','android-kernel','android-initrd','initrd-runtime-system-discovery','initrd-system-image-search','initrd-local-filesystem-scan');ValidationStatus='Validated';ContainmentStatus='Passed';IsRegularFile=$false;SizeBytes=1}
                $bootChains.Add($chain);$evidence.Add($chain);$correlations.Add([pscustomobject][ordered]@{EvidenceId=$chainId;SystemId=[string]$bootSystem.SystemId;Relationship='Corroborates';Confidence='Confirmed';RootPartitionResolved=$true});[void]$provenMembers.Add([string]$bootSystem.SystemId)
            }
        }
        if($loaders.Count-ne1){$loaderReason=if($loaders.Count){'ANDROID_RELATIONSHIP_LOADER_AMBIGUOUS'}else{'ANDROID_RELATIONSHIP_LOADER_INVALID'};$reasons.Add($loaderReason)}
        if(-not$configs.Count){$configReason=if($canonicalConfigs.Count){'ANDROID_RUNTIME_STORAGE_UNPROVEN_AT_PREBOOT'}else{'ANDROID_RELATIONSHIP_CONFIG_MISSING'};$reasons.Add($configReason)}
        if(-not$kernels.Count){$reasons.Add('ANDROID_RELATIONSHIP_KERNEL_MISSING')};if(-not$initrds.Count){$reasons.Add('ANDROID_RELATIONSHIP_INITRD_MISSING')}
        $proofs=[Collections.Generic.List[object]]::new()
        foreach($config in $configs){
            $kernelPath=([string]$config.KernelPath).Replace('\','/').TrimStart('/');$initrdPath=([string]$config.InitrdPath).Replace('\','/').TrimStart('/')
            $kernel=@($kernels|Where-Object{([string]$_.RelativePath).Replace('\','/').TrimStart('/')-ceq$kernelPath});$initrd=@($initrds|Where-Object{([string]$_.RelativePath).Replace('\','/').TrimStart('/')-ceq$initrdPath})
            if($kernel.Count-ne1-or$initrd.Count-ne1){continue}
            $matches=[Collections.Generic.List[object]]::new();$type=[string]$config.RootReferenceType;$reference=Normalize-SbRelationshipIdentifier ([string]$config.RootReference)
            foreach($candidate in @($DetectedSystems|Where-Object{$_.Family-ceq'Android'-and$_.PartitionId-cne$bootId})){
                $candidateId=[string]$candidate.PartitionId;if(-not$inventoryByOpaque.ContainsKey($candidateId)-or-not$inspectionByPartition.ContainsKey($candidateId)){continue};$candidateInspection=$inspectionByPartition[$candidateId];if([string]$candidateInspection.Status-cne'Complete'){continue}
                $identity=$inventoryByOpaque[$candidateId];$matched=$false
                if($type-ceq'PARTUUID'){$matched=$reference-ceq(Normalize-SbRelationshipIdentifier ([string]$identity.RawPartitionId))}
                elseif($type-ceq'UUID'){$matched=$reference-ceq(Normalize-SbRelationshipIdentifier ([string](Get-SbRelationshipValue $candidateInspection 'FilesystemIdentity')))}
                elseif($type-ceq'LABEL'){$same=@($PartitionInventory|Where-Object{[string]$_.DisplayLabel-ceq[string]$config.RootReference});$matched=$same.Count-eq1-and[string]$identity.DisplayLabel-ceq[string]$config.RootReference}
                if(-not$matched){continue};$images=@($candidateInspection.Evidence|Where-Object{$_.Kind-ceq'SystemImage'-and'android-system-image'-in@($_.Signals)});if($images.Count-ne1){continue};if([string]$identity.RawDiskId-cne[string]$inventoryByOpaque[$bootId].RawDiskId){continue}
                $matches.Add([pscustomobject]@{System=$candidate;Inventory=$identity;Inspection=$candidateInspection;SystemImage=$images[0];Kernel=$kernel[0];Initrd=$initrd[0];Config=$config})
            }
            if($matches.Count-eq1){$proofs.Add($matches[0])}elseif($matches.Count-gt1){$reasons.Add('ANDROID_RELATIONSHIP_TARGET_AMBIGUOUS')}
        }
        $uniqueTargets=@($proofs|Group-Object{$_.System.PartitionId})
        if($uniqueTargets.Count-ne1-or$loaders.Count-ne1){if(-not$reasons.Count){$unprovenReason=if($configs.Count){'ANDROID_RELATIONSHIP_ROOT_REFERENCE_NOT_MATCHED'}else{'ANDROID_RELATIONSHIP_UNPROVEN'};$reasons.Add($unprovenReason)};$relationships.Add([pscustomobject][ordered]@{RelationshipId='';BootPartitionId=$bootId;SystemPartitionId='';LoaderEvidenceIds=@($loaders|ForEach-Object EvidenceId);ConfigEvidenceIds=@($configs|ForEach-Object EvidenceId);KernelEvidenceId='';InitrdEvidenceId='';SystemImageEvidenceId='';DataImageEvidenceIds=@();RootReferenceFound=($configs.Count-gt0);ReferencedPartitionMatched=$false;BootArgumentsValidated=$false;RelationshipStatus=if($canonicalConfigs.Count){'UnprovenAtPreboot'}else{'Unproven'};Confidence='Unknown';ReasonCodes=@($reasons|Sort-Object -Unique)});continue}
        $proof=$uniqueTargets[0].Group[0];$systemId=[string]$proof.System.PartitionId;$relationshipId=Get-SbRelationshipId $bootId $systemId ([string]$proof.Config.EvidenceId);$bliss='bliss-os-identity'-in@($proof.Config.Signals);$data=@($proof.Inspection.Evidence|Where-Object{$_.Kind-ceq'DataImage'-and'android-data-image'-in@($_.Signals)})
        $componentIds=@([string]$loaders[0].EvidenceId,[string]$proof.Config.EvidenceId,[string]$proof.Kernel.EvidenceId,[string]$proof.Initrd.EvidenceId,[string]$proof.SystemImage.EvidenceId)|Sort-Object -Unique
        $item=[pscustomobject][ordered]@{EvidenceId=$relationshipId;EvidenceKind='AndroidInstallationRelationship';Kind='AndroidInstallationRelationship';RelationshipId=$relationshipId;BootPartitionId=[string]$inventoryByOpaque[$bootId].RawPartitionId;SystemPartitionId=[string]$proof.Inventory.RawPartitionId;PartitionId=[string]$inventoryByOpaque[$bootId].RawPartitionId;DiskId=[string]$proof.Inventory.RawDiskId;LoaderPath=([string]$loaders[0].RelativePath).Replace('\','/');KernelPath=([string]$proof.Kernel.RelativePath).Replace('\','/');InitrdPath=([string]$proof.Initrd.RelativePath).Replace('\','/');SystemImagePath=([string]$proof.SystemImage.RelativePath).Replace('\','/');RootReference=[string]$proof.Config.RootReference;RootReferenceType=[string]$proof.Config.RootReferenceType;BootArguments=[string]$proof.Config.BootArguments;BootArgumentsValidated=$true;ComponentEvidenceIds=$componentIds;OptionalDataImageEvidenceIds=@($data|ForEach-Object EvidenceId);Distribution=if($bliss){'BlissOS'}else{'UnknownAndroidLike'};Signals=@('android-installation-relationship','android-boot-chain-validated','root-reference-validated','valid-efi-loader');ValidationStatus='Validated';ContainmentStatus='Passed';IsRegularFile=$false;SizeBytes=1}
        $evidence.Add($item);foreach($candidateSystemId in @([string]$bootSystem.SystemId,[string]$proof.System.SystemId)){$correlations.Add([pscustomobject][ordered]@{EvidenceId=$relationshipId;SystemId=$candidateSystemId;Relationship='Corroborates';Confidence='Confirmed';RootPartitionResolved=$true});[void]$provenMembers.Add($candidateSystemId)}
        $relationships.Add([pscustomobject][ordered]@{RelationshipId=$relationshipId;BootPartitionId=$bootId;SystemPartitionId=$systemId;LoaderEvidenceIds=@([string]$loaders[0].EvidenceId);ConfigEvidenceIds=@([string]$proof.Config.EvidenceId);KernelEvidenceId=[string]$proof.Kernel.EvidenceId;InitrdEvidenceId=[string]$proof.Initrd.EvidenceId;SystemImageEvidenceId=[string]$proof.SystemImage.EvidenceId;DataImageEvidenceIds=@($data|ForEach-Object EvidenceId);RootReferenceFound=$true;ReferencedPartitionMatched=$true;BootArgumentsValidated=$true;RelationshipStatus='Proven';Confidence='Confirmed';ReasonCodes=@('ANDROID_INSTALLATION_RELATIONSHIP_PROVEN')})
    }
    $updated=[Collections.Generic.List[object]]::new();foreach($system in $DetectedSystems){$copy=$system|Select-Object *;if($identifiedDistributions.ContainsKey([string]$system.SystemId)){$copy.Distribution=[string]$identifiedDistributions[[string]$system.SystemId]};if($provenMembers.Contains([string]$system.SystemId)){$copy.Confidence='Confirmed';$copy.NeedsStrongerEvidence=$false};$updated.Add($copy)}
    return [pscustomobject][ordered]@{SchemaVersion='v9-android-installation-relationship-1';DetectedSystems=$updated.ToArray();Relationships=$relationships.ToArray();CanonicalBootChains=$bootChains.ToArray();Evidence=$evidence.ToArray();Correlations=$correlations.ToArray();SafetyCounters=[pscustomobject]@{AdditionalFilesystemOperations=0;EfiWrites=0;BcdWrites=0;NvramWrites=0;BootOrderChanges=0;PartitionWrites=0;FilesystemWrites=0;Mounts=0;DriveLetterAssignments=0;ElevationAttempts=0;RefindInstallations=0;Reboots=0;NetworkOperations=0}}
}

Export-ModuleMember -Function Resolve-SbAndroidInstallationRelationships
