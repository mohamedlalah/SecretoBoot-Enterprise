using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace SecretoBoot.V9.WindowsEfiEvidence
{
    internal static class NativeMethods
    {
        internal const uint FILE_READ_ATTRIBUTES=0x80, GENERIC_READ=0x80000000, FILE_SHARE_READ=1, OPEN_EXISTING=3;
        internal const uint OPEN_REPARSE=0x00200000, BACKUP_SEMANTICS=0x02000000, ATTR_DIRECTORY=0x10, ATTR_REPARSE=0x400;
        internal const uint ATTR_SPARSE=0x200, ATTR_OFFLINE=0x1000, ATTR_ENCRYPTED=0x4000, VOLUME_NAME_GUID=1, TOKEN_QUERY=8;
        internal const int TOKEN_ELEVATION=20;
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] internal static extern SafeFileHandle CreateFileW(string n,uint a,uint s,IntPtr sec,uint c,uint f,IntPtr t);
        [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool GetFileInformationByHandleEx(SafeFileHandle h,InfoClass c,IntPtr b,uint z);
        [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool GetFileInformationByHandle(SafeFileHandle h,out ByHandleInfo i);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] internal static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder p,uint z,uint f);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool GetVolumeInformationByHandleW(SafeFileHandle h,StringBuilder n,uint nz,out uint serial,out uint max,out uint flags,StringBuilder fs,uint fsz);
        [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool GetFileSizeEx(SafeFileHandle h,out long size);
        [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool ReadFile(SafeFileHandle h,byte[] b,uint z,out uint read,IntPtr o);
        [DllImport("kernel32.dll")] internal static extern IntPtr GetCurrentProcess();
        [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool OpenProcessToken(IntPtr p,uint a,out SafeFileHandle t);
        [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool GetTokenInformation(SafeFileHandle t,int c,IntPtr b,uint z,out uint r);
    }
    internal enum InfoClass { FileBasicInfo=0,FileStandardInfo=1,FileAttributeTagInfo=9,FileIdInfo=18 }
    [StructLayout(LayoutKind.Sequential)] internal struct TagInfo { internal uint Attributes,Tag; }
    [StructLayout(LayoutKind.Sequential)] internal struct FileTime { internal uint Low,High; }
    [StructLayout(LayoutKind.Sequential)] internal struct ByHandleInfo { internal uint Attributes;internal FileTime CreationTime,LastAccessTime,LastWriteTime;internal uint VolumeSerial,FileSizeHigh,FileSizeLow,Links,FileIndexHigh,FileIndexLow; }
    [StructLayout(LayoutKind.Sequential)] internal struct IdInfo { internal ulong VolumeSerial;[MarshalAs(UnmanagedType.ByValArray,SizeConst=16)]internal byte[] FileId; }
    [StructLayout(LayoutKind.Sequential)] internal struct StandardInfo { internal long AllocationSize,EndOfFile;internal uint Links;[MarshalAs(UnmanagedType.U1)]internal bool DeletePending;[MarshalAs(UnmanagedType.U1)]internal bool Directory; }
    internal sealed class Snapshot { internal uint Attributes,Tag,VolumeSerial,HandleVolumeSerial,Links;internal ulong IdVolumeSerial,CreationTime,LastAccessTime,LastWriteTime;internal byte[] Id=Array.Empty<byte>();internal bool Directory;internal long Size;internal string FinalPath="",Filesystem="",IdentitySource=""; }
    internal sealed class IdentityResolution { internal string Source="";internal ulong VolumeSerial;internal byte[] Id=Array.Empty<byte>(); }

    public sealed class EspInspectionRequest
    {
        public bool FeatureEnabled{get;set;} public bool ExplicitConsent{get;set;} public bool RequireNonElevated{get;set;}
        public string VolumeGuid{get;set;}=""; public string EspToken{get;set;}="";
        public int MaximumVendorDirectories{get;set;}=64; public int MaximumLoaderFiles{get;set;}=256; public int MaximumConfigFiles{get;set;}=64;
        public int MaximumLoaderBytes{get;set;}=33554432; public int MaximumConfigBytes{get;set;}=16384; public int TimeoutMilliseconds{get;set;}=10000;
    }
    public sealed class EspArtifact
    {
        public string EvidenceId{get;internal set;}=""; public string EspToken{get;internal set;}=""; public string RelativePath{get;internal set;}="";
        public string VendorDirectory{get;internal set;}=""; public string Kind{get;internal set;}=""; public string[] Signals{get;internal set;}=Array.Empty<string>();
        public long SizeBytes{get;internal set;} public bool ValidPeX64{get;internal set;}
    }
    public sealed class EspPathDiagnostic
    {
        public string RelativePath{get;internal set;}="EFI/Microsoft/Boot/bootmgfw.efi";public bool OpenAttempted{get;internal set;}public bool Exists{get;internal set;}
        public string ContainmentResult{get;internal set;}="NotEvaluated";public string RegularFileResult{get;internal set;}="NotEvaluated";public string PeX64Result{get;internal set;}="NotEvaluated";public string FailureReason{get;internal set;}="NOT_FOUND";
    }
    public sealed class EspInspectionResult
    {
        public string Status{get;internal set;}="Denied"; public string ReasonCode{get;internal set;}="EFI_EVIDENCE_GATE_DENIED";
        public EspArtifact[] Evidence{get;internal set;}=Array.Empty<EspArtifact>(); public EspPathDiagnostic[] PathDiagnostics{get;internal set;}=Array.Empty<EspPathDiagnostic>(); public int DirectoryEnumerations{get;internal set;}
        public int NativeOpenOperations{get;internal set;} public int BoundedReadOperations{get;internal set;} public long BytesRead{get;internal set;}
        public int MountOperations{get;internal set;} public int DriveLetterAssignments{get;internal set;} public int WriteOperations{get;internal set;}
    }

    public static class EspEvidenceAdapter
    {
        private static readonly Regex SafeName=new Regex("^[A-Za-z0-9._-]{1,64}$",RegexOptions.CultureInvariant);
        private static readonly Regex VolumeGuid=new Regex("^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$",RegexOptions.CultureInvariant);
        public static string[] ParseSyntheticGrub(byte[] data)=>ParseGrub(data??Array.Empty<byte>());
        public static bool ValidateSyntheticPeX64(byte[] data)=>ValidPeX64(data??Array.Empty<byte>());
        public static EspInspectionResult Inspect(EspInspectionRequest request)
        {
            if(!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))return Denied("EFI_EVIDENCE_PLATFORM_DENIED",0,0,0);
            if(request==null||!request.FeatureEnabled||!request.ExplicitConsent||!request.RequireNonElevated)return Denied("EFI_EVIDENCE_GATE_DENIED",0,0,0);
            if(IsElevated())return Denied("EFI_EVIDENCE_ELEVATION_DENIED",0,0,0);
            if(!VolumeGuid.IsMatch(request.VolumeGuid)||!Regex.IsMatch(request.EspToken,"^report:partition:[0-9a-f]{20}$")||request.MaximumVendorDirectories!=64||request.MaximumLoaderFiles!=256||request.MaximumConfigFiles!=64||request.MaximumLoaderBytes!=33554432||request.MaximumConfigBytes!=16384||request.TimeoutMilliseconds!=10000)
                return Denied("EFI_EVIDENCE_MANIFEST_DENIED",0,0,0);
            string root="\\\\?\\Volume{"+request.VolumeGuid.ToLowerInvariant()+"}\\";var timer=Stopwatch.StartNew();int opens=0,reads=0,enums=0;long bytes=0;var windowsDiagnostic=new EspPathDiagnostic();
            var evidence=new List<EspArtifact>();
            try
            {
                using(var rootHandle=OpenChecked(root,true,ref opens,out Snapshot rootSnapshot))
                {
                    if(!IsFat(rootSnapshot.Filesystem)||!SamePath(rootSnapshot.FinalPath,root.TrimEnd('\\')))return Denied("EFI_EVIDENCE_VOLUME_DENIED",opens,reads,bytes);
                    string efi=root+"EFI";
                    using(var efiHandle=OpenChecked(efi,true,ref opens,out Snapshot efiSnapshot))
                    {
                        if(!SameVolume(rootSnapshot,efiSnapshot)||!SamePath(efiSnapshot.FinalPath,efi))return Denied("EFI_EVIDENCE_CONTAINMENT_DENIED",opens,reads,bytes);
                        string microsoftBoot=efi+"\\Microsoft\\Boot",windowsLoader=microsoftBoot+"\\bootmgfw.efi";
                        if(Directory.Exists(microsoftBoot))
                        {
                            using(var bootHandle=OpenChecked(microsoftBoot,true,ref opens,out Snapshot bootSnapshot))
                            {
                                if(!SameVolume(rootSnapshot,bootSnapshot)||!SamePath(bootSnapshot.FinalPath,microsoftBoot))return Denied("EFI_EVIDENCE_CONTAINMENT_DENIED",opens,reads,bytes);
                                if(File.Exists(windowsLoader))
                                {
                                    windowsDiagnostic.Exists=true;windowsDiagnostic.OpenAttempted=true;EspArtifact windows=ReadArtifact(windowsLoader,"Microsoft/Boot",true,request,rootSnapshot,windowsDiagnostic,ref opens,ref reads,ref bytes);
                                    if(windows!=null){windows.EspToken=request.EspToken;windows.EvidenceId="boot:"+request.EspToken.Substring(request.EspToken.Length-20)+":"+(evidence.Count+1).ToString("D3");evidence.Add(windows);}
                                }
                            }
                        }
                        string[] vendors=Directory.EnumerateDirectories(efi,"*",SearchOption.TopDirectoryOnly).OrderBy(x=>x,StringComparer.OrdinalIgnoreCase).Take(request.MaximumVendorDirectories+1).ToArray();enums++;
                        if(vendors.Length>request.MaximumVendorDirectories)return Denied("EFI_EVIDENCE_RESOURCE_LIMIT",opens,reads,bytes);
                        foreach(string vendor in vendors)
                        {
                            if(timer.ElapsedMilliseconds>request.TimeoutMilliseconds)return Denied("EFI_EVIDENCE_TIMEOUT",opens,reads,bytes);
                            string vendorName=Path.GetFileName(vendor);if(!SafeName.IsMatch(vendorName)||!SamePath(Path.GetDirectoryName(vendor),efi))continue;
                            using(var vendorHandle=OpenChecked(vendor,true,ref opens,out Snapshot vendorSnapshot))
                            {
                                if(!SameVolume(rootSnapshot,vendorSnapshot)||!SamePath(vendorSnapshot.FinalPath,vendor))continue;
                                string[] files=Directory.EnumerateFiles(vendor,"*",SearchOption.TopDirectoryOnly).OrderBy(x=>x,StringComparer.OrdinalIgnoreCase).Take(request.MaximumLoaderFiles+request.MaximumConfigFiles+1).ToArray();enums++;
                                foreach(string file in files)
                                {
                                    string name=Path.GetFileName(file);if(!SafeName.IsMatch(name)||!SamePath(Path.GetDirectoryName(file),vendor))continue;
                                    bool loader=name.EndsWith(".efi",StringComparison.OrdinalIgnoreCase),config=name.Equals("grub.cfg",StringComparison.OrdinalIgnoreCase);
                                    if(!loader&&!config)continue;
                                    if(loader&&evidence.Count(x=>x.Kind=="EfiLoader")>=request.MaximumLoaderFiles)return Denied("EFI_EVIDENCE_RESOURCE_LIMIT",opens,reads,bytes);
                                    if(config&&evidence.Count(x=>x.Kind=="GrubConfig")>=request.MaximumConfigFiles)return Denied("EFI_EVIDENCE_RESOURCE_LIMIT",opens,reads,bytes);
                                    EspArtifact artifact=ReadArtifact(file,vendorName,loader,request,rootSnapshot,null,ref opens,ref reads,ref bytes);
                                    if(artifact!=null){artifact.EspToken=request.EspToken;artifact.EvidenceId="boot:"+request.EspToken.Substring(request.EspToken.Length-20)+":"+(evidence.Count+1).ToString("D3");evidence.Add(artifact);}
                                }
                            }
                        }
                    }
                }
                return new EspInspectionResult{Status="Complete",ReasonCode="EFI_EVIDENCE_OK",Evidence=evidence.ToArray(),PathDiagnostics=new[]{windowsDiagnostic},DirectoryEnumerations=enums,NativeOpenOperations=opens,BoundedReadOperations=reads,BytesRead=bytes};
            }
            catch(UnauthorizedAccessException){windowsDiagnostic.FailureReason="OPEN_FAILED";return Denied("EFI_EVIDENCE_ACCESS_DENIED",opens,reads,bytes,windowsDiagnostic);}
            catch(IOException){if(windowsDiagnostic.FailureReason=="NOT_FOUND")windowsDiagnostic.FailureReason="CONTAINMENT_DENIED";return Denied("EFI_EVIDENCE_IO_DENIED",opens,reads,bytes,windowsDiagnostic);}
            catch{windowsDiagnostic.FailureReason="OPEN_FAILED";return Denied("EFI_EVIDENCE_NATIVE_AMBIGUOUS",opens,reads,bytes,windowsDiagnostic);}
        }

        private static EspArtifact ReadArtifact(string path,string vendor,bool loader,EspInspectionRequest request,Snapshot root,EspPathDiagnostic diagnostic,ref int opens,ref int reads,ref long bytes)
        {
            using(var handle=OpenChecked(path,false,ref opens,out Snapshot before))
            {
                if(!SameVolume(root,before)||!SamePath(before.FinalPath,path)){if(diagnostic!=null){diagnostic.ContainmentResult="Denied";diagnostic.FailureReason="CONTAINMENT_DENIED";}return null;}if(diagnostic!=null)diagnostic.ContainmentResult="Passed";
                if(before.Directory){if(diagnostic!=null){diagnostic.RegularFileResult="Denied";diagnostic.FailureReason="NOT_REGULAR_FILE";}return null;}if(before.Links!=1){if(diagnostic!=null)diagnostic.FailureReason="CONTAINMENT_DENIED";return null;}if(diagnostic!=null)diagnostic.RegularFileResult="Passed";
                long limit=loader?request.MaximumLoaderBytes:request.MaximumConfigBytes;if(before.Size<1||before.Size>limit){if(diagnostic!=null)diagnostic.FailureReason="PE_VALIDATION_FAILED";return null;}
                int length=loader?(int)Math.Min(before.Size,4096):(int)before.Size;byte[] data=new byte[length];uint got;reads++;
                if(!NativeMethods.ReadFile(handle,data,(uint)data.Length,out got,IntPtr.Zero)||got!=data.Length)return null;bytes+=got;
                Snapshot after=GetSnapshot(handle);if(!SameSnapshot(before,after)){if(diagnostic!=null){diagnostic.ContainmentResult="Denied";diagnostic.FailureReason="CONTAINMENT_DENIED";}return null;}
                string relative="EFI/"+vendor+"/"+Path.GetFileName(path);var signals=new List<string>();bool valid=false;
                if(loader)
                {
                    string peFailure=GetPeFailureReason(data);valid=peFailure=="NONE";if(!valid){if(diagnostic!=null){diagnostic.PeX64Result="Denied";diagnostic.FailureReason=peFailure;}return null;}if(diagnostic!=null){diagnostic.PeX64Result="Passed";diagnostic.FailureReason="NONE";}signals.Add("valid-efi-loader");string lower=relative.ToLowerInvariant();
                    if(lower=="efi/microsoft/boot/bootmgfw.efi")signals.Add("microsoft-vendor-path");
                    if(lower.EndsWith("/shimx64.efi"))signals.Add("shim-loader");if(lower.EndsWith("/grubx64.efi"))signals.Add("grub-loader");
                    if(lower.StartsWith("efi/ubuntu/"))signals.Add("ubuntu-vendor-path");if(Regex.IsMatch(lower,"^efi/(android|androidtv|googletv)/"))signals.Add("android-vendor-path");
                }
                else signals.AddRange(ParseGrub(data));
                Array.Clear(data,0,data.Length);
                return new EspArtifact{RelativePath=relative,VendorDirectory=vendor.ToLowerInvariant(),Kind=loader?"EfiLoader":"GrubConfig",Signals=signals.Distinct(StringComparer.Ordinal).OrderBy(x=>x,StringComparer.Ordinal).ToArray(),SizeBytes=before.Size,ValidPeX64=valid};
            }
        }

        private static string[] ParseGrub(byte[] data)
        {
            string text;try{text=new UTF8Encoding(false,true).GetString(data);}catch{return Array.Empty<string>();}
            if(text.Length==0||text.IndexOf('\0')>=0||text.Any(c=>(c<0x20&&c!='\r'&&c!='\n'&&c!='\t')||c==0x7f))return Array.Empty<string>();
            string[] lines=text.Replace("\r\n","\n").Split('\n');if(lines.Length>256||lines.Any(x=>x.Length>512))return Array.Empty<string>();
            string[] active=lines.Where(x=>!x.TrimStart().StartsWith("#",StringComparison.Ordinal)).ToArray();string lower=string.Join("\n",active).ToLowerInvariant();bool marker=Regex.IsMatch(lower,@"\b(android-x86|androidboot\.|system\.(img|sfs)|src=/android)",RegexOptions.CultureInvariant);
            var signals=new List<string>{"grub-config"};if(marker)signals.Add("android-boot-config");
            if(marker&&active.Any(x=>Regex.IsMatch(x,@"^\s*linux(?:efi)?\s+\S*(?:/|\\)?kernel(?:\s|$)",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant)))signals.Add("android-kernel");
            if(marker&&active.Any(x=>Regex.IsMatch(x,@"^\s*initrd(?:efi)?\s+\S*(?:/|\\)?initrd(?:\.img)?(?:\s|$)",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant)))signals.Add("android-initrd");
            if(marker&&(lower.Contains("androidboot.")||Regex.IsMatch(lower,@"\bsrc=/android",RegexOptions.CultureInvariant)))signals.Add("android-boot-arguments");
            return signals.ToArray();
        }

        private static SafeFileHandle OpenChecked(string path,bool directory,ref int opens,out Snapshot snapshot)
        {
            uint flags=NativeMethods.OPEN_REPARSE|(directory?NativeMethods.BACKUP_SEMANTICS:0u);var h=NativeMethods.CreateFileW(path,directory?NativeMethods.FILE_READ_ATTRIBUTES:NativeMethods.GENERIC_READ,NativeMethods.FILE_SHARE_READ,IntPtr.Zero,NativeMethods.OPEN_EXISTING,flags,IntPtr.Zero);opens++;
            if(h.IsInvalid){int error=Marshal.GetLastWin32Error();h.Dispose();if(error==5)throw new UnauthorizedAccessException();throw new IOException("OPEN_DENIED");}
            snapshot=GetSnapshot(h);if((snapshot.Attributes&NativeMethods.ATTR_REPARSE)!=0||snapshot.Tag!=0||snapshot.Directory!=directory){h.Dispose();throw new IOException("TYPE_OR_REPARSE_DENIED");}return h;
        }
        private static T Query<T>(SafeFileHandle h,InfoClass c)where T:struct{int z=Marshal.SizeOf<T>();IntPtr b=Marshal.AllocHGlobal(z);try{if(!NativeMethods.GetFileInformationByHandleEx(h,c,b,(uint)z))throw new IOException("QUERY_DENIED");return Marshal.PtrToStructure<T>(b);}finally{Marshal.FreeHGlobal(b);}}
        private static bool TryQueryTag(SafeFileHandle h,out TagInfo value,out int error){value=default(TagInfo);error=0;int z=Marshal.SizeOf<TagInfo>();IntPtr b=Marshal.AllocHGlobal(z);try{if(!NativeMethods.GetFileInformationByHandleEx(h,InfoClass.FileAttributeTagInfo,b,(uint)z)){error=Marshal.GetLastWin32Error();return false;}value=Marshal.PtrToStructure<TagInfo>(b);return true;}finally{Marshal.FreeHGlobal(b);}}
        private static bool TryQueryId(SafeFileHandle h,out IdInfo value,out int error){value=default(IdInfo);error=0;int z=Marshal.SizeOf<IdInfo>();IntPtr b=Marshal.AllocHGlobal(z);try{if(!NativeMethods.GetFileInformationByHandleEx(h,InfoClass.FileIdInfo,b,(uint)z)){error=Marshal.GetLastWin32Error();return false;}value=Marshal.PtrToStructure<IdInfo>(b);return true;}finally{Marshal.FreeHGlobal(b);}}
        private static Snapshot GetSnapshot(SafeFileHandle h){ByHandleInfo basic;if(!NativeMethods.GetFileInformationByHandle(h,out basic))throw new IOException("ATTRIBUTE_QUERY_DENIED");StandardInfo s=Query<StandardInfo>(h,InfoClass.FileStandardInfo);long size=0;if(!s.Directory&&!NativeMethods.GetFileSizeEx(h,out size))throw new IOException("SIZE_DENIED");var p=new StringBuilder(32768);uint n=NativeMethods.GetFinalPathNameByHandleW(h,p,(uint)p.Capacity,NativeMethods.VOLUME_NAME_GUID);if(n==0||n>=p.Capacity)throw new IOException("PATH_DENIED");var vn=new StringBuilder(261);var fs=new StringBuilder(261);uint serial,max,flags;if(!NativeMethods.GetVolumeInformationByHandleW(h,vn,(uint)vn.Capacity,out serial,out max,out flags,fs,(uint)fs.Capacity))throw new IOException("VOLUME_DENIED");TagInfo tag;int tagError;bool tagOk=TryQueryTag(h,out tag,out tagError);if(!TagPolicyAllows(fs.ToString(),basic.Attributes,tagOk,tag.Attributes,tag.Tag,tagError))throw new IOException("REPARSE_QUERY_DENIED");IdInfo id;int idError;bool idOk=TryQueryId(h,out id,out idError);IdentityResolution identity=ResolveIdentity(fs.ToString(),idOk,id,idError,basic);return new Snapshot{Attributes=tagOk?tag.Attributes:basic.Attributes,Tag=tagOk?tag.Tag:0,VolumeSerial=serial,HandleVolumeSerial=basic.VolumeSerial,IdVolumeSerial=identity.VolumeSerial,Id=identity.Id,IdentitySource=identity.Source,CreationTime=PackTime(basic.CreationTime),LastAccessTime=PackTime(basic.LastAccessTime),LastWriteTime=PackTime(basic.LastWriteTime),Links=s.Links,Directory=s.Directory,Size=s.Directory?0:size,FinalPath=p.ToString().TrimEnd('\\'),Filesystem=fs.ToString()};}
        private static bool TagPolicyAllows(string filesystem,uint basicAttributes,bool tagOk,uint tagAttributes,uint tag,int error){if((basicAttributes&NativeMethods.ATTR_REPARSE)!=0)return false;if(tagOk)return(tagAttributes&NativeMethods.ATTR_REPARSE)==0&&tag==0;return string.Equals(filesystem,"FAT32",StringComparison.OrdinalIgnoreCase)&&(error==1||error==50||error==87);}
        private static IdentityResolution ResolveIdentity(string filesystem,bool idOk,IdInfo id,int error,ByHandleInfo basic){if(idOk){byte[] value=id.FileId??Array.Empty<byte>();if(id.VolumeSerial==0||value.Length==0||value.All(x=>x==0))throw new IOException("FILE_ID_DENIED");return new IdentityResolution{Source="FILE_ID_INFO",VolumeSerial=id.VolumeSerial,Id=value};}if(!string.Equals(filesystem,"FAT32",StringComparison.OrdinalIgnoreCase)||(error!=1&&error!=50&&error!=87))throw new IOException("FILE_ID_DENIED");ulong index=((ulong)basic.FileIndexHigh<<32)|basic.FileIndexLow;if(basic.VolumeSerial!=0&&index!=0)return new IdentityResolution{Source="BY_HANDLE_FILE_INFORMATION",VolumeSerial=basic.VolumeSerial,Id=BitConverter.GetBytes(index)};return new IdentityResolution{Source="SAME_RETAINED_HANDLE",VolumeSerial=0,Id=Array.Empty<byte>()};}
        private static bool SameIdentity(Snapshot a,Snapshot b){if(!string.Equals(a.IdentitySource,b.IdentitySource,StringComparison.Ordinal))return false;if(a.IdentitySource=="SAME_RETAINED_HANDLE")return true;return a.IdVolumeSerial==b.IdVolumeSerial&&a.Id.SequenceEqual(b.Id);}
        private static ulong PackTime(FileTime value)=>((ulong)value.High<<32)|value.Low;
        private static bool SameVolume(Snapshot a,Snapshot b)=>a.VolumeSerial==b.VolumeSerial&&a.HandleVolumeSerial==b.HandleVolumeSerial&&string.Equals(a.Filesystem,b.Filesystem,StringComparison.OrdinalIgnoreCase);
        private static bool SameSnapshot(Snapshot a,Snapshot b)=>SameVolume(a,b)&&SameIdentity(a,b)&&a.Attributes==b.Attributes&&a.Tag==b.Tag&&a.Links==b.Links&&a.Directory==b.Directory&&a.Size==b.Size&&a.CreationTime==b.CreationTime&&a.LastAccessTime==b.LastAccessTime&&a.LastWriteTime==b.LastWriteTime&&SamePath(a.FinalPath,b.FinalPath);
        private static bool SamePath(string a,string b)=>string.Equals(a.TrimEnd('\\'),b.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase);
        private static bool IsFat(string fs)=>string.Equals(fs,"FAT",StringComparison.OrdinalIgnoreCase)||string.Equals(fs,"FAT32",StringComparison.OrdinalIgnoreCase);
        private static string GetPeFailureReason(byte[] b){if(b.Length<128||b[0]!='M'||b[1]!='Z')return "PE_VALIDATION_FAILED";int o=BitConverter.ToInt32(b,0x3c);if(o<0||o+6>b.Length||b[o]!='P'||b[o+1]!='E'||b[o+2]!=0||b[o+3]!=0)return "PE_VALIDATION_FAILED";return BitConverter.ToUInt16(b,o+4)==0x8664?"NONE":"ARCHITECTURE_MISMATCH";}
        private static bool ValidPeX64(byte[] b)=>GetPeFailureReason(b)=="NONE";
        private static bool IsElevated(){SafeFileHandle t;if(!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(),NativeMethods.TOKEN_QUERY,out t))return true;using(t){IntPtr b=Marshal.AllocHGlobal(4);try{uint r;if(!NativeMethods.GetTokenInformation(t,NativeMethods.TOKEN_ELEVATION,b,4,out r)||r!=4)return true;return Marshal.ReadInt32(b)!=0;}finally{Marshal.FreeHGlobal(b);}}}
        private static EspInspectionResult Denied(string code,int opens,int reads,long bytes,EspPathDiagnostic diagnostic=null)=>new EspInspectionResult{Status="Denied",ReasonCode=code,PathDiagnostics=diagnostic==null?Array.Empty<EspPathDiagnostic>():new[]{diagnostic},NativeOpenOperations=opens,BoundedReadOperations=reads,BytesRead=bytes};
    }
}
