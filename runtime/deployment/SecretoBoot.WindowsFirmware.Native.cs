using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace SecretoBoot.V9.WindowsFirmware
{
    internal static class Native
    {
        internal const string Global="{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";
        internal const uint Attributes=7,TokenAdjust=0x20,TokenQuery=8,Enabled=2;
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]internal static extern uint GetFirmwareEnvironmentVariableExW(string n,string g,byte[] b,uint z,out uint a);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]internal static extern bool SetFirmwareEnvironmentVariableExW(string n,string g,byte[] b,uint z,uint a);
        [DllImport("kernel32.dll")]internal static extern IntPtr GetCurrentProcess();
        [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]internal static extern bool OpenProcessToken(IntPtr p,uint a,out SafeFileHandle t);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]internal static extern bool LookupPrivilegeValueW(string s,string n,out Luid l);
        [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]internal static extern bool AdjustTokenPrivileges(SafeFileHandle t,bool d,ref TokenPrivileges n,uint z,IntPtr p,IntPtr r);
    }
    [StructLayout(LayoutKind.Sequential)]internal struct Luid{internal uint Low;internal int High;}
    [StructLayout(LayoutKind.Sequential)]internal struct TokenPrivileges{internal uint Count;internal Luid Luid;internal uint Attributes;}
    public sealed class FirmwareEntryResult
    {
        public bool Success{get;internal set;}public bool ExistingExact{get;internal set;}public ushort EntryNumber{get;internal set;}public string EntryName{get;internal set;}="";public byte[] PreviousBootOrder{get;internal set;}=Array.Empty<byte>();public byte[] LoadOption{get;internal set;}=Array.Empty<byte>();public string ReasonCode{get;internal set;}="FIRMWARE_OPERATION_DENIED";
    }
    public sealed class FirmwareBootEntry
    {
        public ushort EntryNumber{get;internal set;}public string FirmwareIdentifier{get;internal set;}="";public string Description{get;internal set;}="";public string DeviceReference{get;internal set;}="";public string EfiPath{get;internal set;}="";public Guid StablePartitionGuid{get;internal set;}=Guid.Empty;public string EntryType{get;internal set;}="Unknown";public string ValidationState{get;internal set;}="Denied";
    }
    public static class FirmwareAdapter
    {
        private static void RequireWindows(){if(Environment.OSVersion.Platform!=PlatformID.Win32NT)throw new PlatformNotSupportedException("WINDOWS_REQUIRED");}
        private static void EnablePrivilege(){SafeFileHandle token;if(!Native.OpenProcessToken(Native.GetCurrentProcess(),Native.TokenAdjust|Native.TokenQuery,out token))throw new InvalidOperationException("FIRMWARE_PRIVILEGE_DENIED");using(token){Luid luid;if(!Native.LookupPrivilegeValueW(null,"SeSystemEnvironmentPrivilege",out luid))throw new InvalidOperationException("FIRMWARE_PRIVILEGE_DENIED");var value=new TokenPrivileges{Count=1,Luid=luid,Attributes=Native.Enabled};if(!Native.AdjustTokenPrivileges(token,false,ref value,0,IntPtr.Zero,IntPtr.Zero)||Marshal.GetLastWin32Error()==1300)throw new InvalidOperationException("FIRMWARE_PRIVILEGE_DENIED");}}
        public static byte[] ReadVariable(string name){RequireWindows();EnablePrivilege();var buffer=new byte[1048576];uint attributes;uint count=Native.GetFirmwareEnvironmentVariableExW(name,Native.Global,buffer,(uint)buffer.Length,out attributes);if(count==0){int error=Marshal.GetLastWin32Error();if(error==203)return Array.Empty<byte>();throw new InvalidOperationException("FIRMWARE_READ_DENIED_"+error);}Array.Resize(ref buffer,(int)count);return buffer;}
        public static bool ReadSecureBootEnabled(){byte[] value=ReadVariable("SecureBoot");if(value.Length!=1||(value[0]!=0&&value[0]!=1))throw new InvalidOperationException("SECURE_BOOT_STATE_AMBIGUOUS");return value[0]==1;}
        private static void WriteVariable(string name,byte[] value){if(value==null)throw new ArgumentNullException(nameof(value));if(!Native.SetFirmwareEnvironmentVariableExW(name,Native.Global,value,(uint)value.Length,Native.Attributes))throw new InvalidOperationException("FIRMWARE_WRITE_DENIED_"+Marshal.GetLastWin32Error());}
        private static byte[] U16(IEnumerable<ushort> values){var list=values.ToArray();var b=new byte[list.Length*2];for(int i=0;i<list.Length;i++){b[i*2]=(byte)list[i];b[i*2+1]=(byte)(list[i]>>8);}return b;}
        private static ushort[] ParseU16(byte[] value){if(value.Length%2!=0)throw new InvalidOperationException("FIRMWARE_ORDER_MALFORMED");var result=new ushort[value.Length/2];for(int i=0;i<result.Length;i++)result[i]=(ushort)(value[i*2]|value[i*2+1]<<8);return result;}
        private static string Description(byte[] option){if(option==null||option.Length<8)return "";int end=6;while(end+1<option.Length&&(option[end]!=0||option[end+1]!=0))end+=2;if(end+1>=option.Length)return "";return Encoding.Unicode.GetString(option,6,end-6);}
        private static FirmwareBootEntry ParseBootEntry(ushort number,byte[] option)
        {
            var result=new FirmwareBootEntry{EntryNumber=number,FirmwareIdentifier="Boot"+number.ToString("X4"),Description=Description(option)};
            if(option==null||option.Length<12)return result;ushort pathLength=BitConverter.ToUInt16(option,4);int descriptionEnd=6;while(descriptionEnd+1<option.Length&&(option[descriptionEnd]!=0||option[descriptionEnd+1]!=0))descriptionEnd+=2;if(descriptionEnd+1>=option.Length)return result;int cursor=descriptionEnd+2,end=cursor+pathLength;if(end>option.Length)return result;
            Guid partition=Guid.Empty;string path="";
            while(cursor+4<=end){byte type=option[cursor],subtype=option[cursor+1];ushort length=BitConverter.ToUInt16(option,cursor+2);if(length<4||cursor+length>end)return result;if(type==4&&subtype==1&&length==42&&option[cursor+41]==2)partition=new Guid(option.Skip(cursor+24).Take(16).ToArray());else if(type==4&&subtype==4&&length>=6){int bytes=length-4;if((bytes&1)!=0)return result;path=Encoding.Unicode.GetString(option,cursor+4,bytes).TrimEnd('\0');}cursor+=length;}
            if(cursor!=end||partition==Guid.Empty||string.IsNullOrWhiteSpace(path)||path[0]!='\\')return result;result.StablePartitionGuid=partition;result.DeviceReference="HD(GPT,"+partition.ToString("D").ToUpperInvariant()+")";result.EfiPath=path;result.EntryType="UefiApplication";result.ValidationState="FirmwareLoadOptionValidated";return result;
        }
        public static FirmwareBootEntry ParseBootEntryForValidation(ushort number,byte[] option){return ParseBootEntry(number,option);}
        public static FirmwareBootEntry[] ReadBootInventory()
        {
            RequireWindows();EnablePrivilege();ushort[] order=ParseU16(ReadVariable("BootOrder"));if(order.Length>4096)throw new InvalidOperationException("FIRMWARE_INVENTORY_RESOURCE_CAP_EXCEEDED");var entries=new List<FirmwareBootEntry>();var seen=new HashSet<ushort>();foreach(ushort number in order.Concat(Enumerable.Range(0,4096).Select(x=>(ushort)x))){if(!seen.Add(number))continue;byte[] option=ReadVariable("Boot"+number.ToString("X4"));if(option.Length==0)continue;entries.Add(ParseBootEntry(number,option));}return entries.ToArray();
        }
        public static FirmwareBootEntry SelectEquivalentOwnedEntry(Guid partitionGuid,FirmwareBootEntry[] inventory)
        {
            if(partitionGuid==Guid.Empty)throw new InvalidOperationException("OWNED_FIRMWARE_IDENTITY_MISMATCH");
            if(inventory==null)throw new InvalidOperationException("FIRMWARE_INVENTORY_QUERY_FAILED");
            FirmwareBootEntry[] matches=inventory.Where(x=>x!=null&&x.ValidationState=="FirmwareLoadOptionValidated"&&x.StablePartitionGuid==partitionGuid&&SameLoaderPath(x.EfiPath,SecretoBootLoaderPath)).ToArray();
            if(matches.Length>1)throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_AMBIGUOUS");
            return matches.Length==1?matches[0]:null;
        }
        public static byte[] BuildLoadOption(uint partitionNumber,ulong partitionStartLba,ulong partitionSizeLba,Guid partitionGuid,string loaderPath,string description)
        {
            if(partitionNumber<1||partitionStartLba<1||partitionSizeLba<1||partitionGuid==Guid.Empty||loaderPath!="\\EFI\\SecretoBoot\\refind_x64.efi"||description!="SecretoBoot")throw new InvalidOperationException("FIRMWARE_LOAD_OPTION_INPUT_DENIED");
            byte[] path=Encoding.Unicode.GetBytes(loaderPath+"\0");ushort fileNodeLength=checked((ushort)(4+path.Length));ushort devicePathLength=checked((ushort)(42+fileNodeLength+4));
            using(var output=new MemoryStream())using(var writer=new BinaryWriter(output,Encoding.Unicode,true)){writer.Write(1u);writer.Write(devicePathLength);writer.Write(Encoding.Unicode.GetBytes(description+"\0"));writer.Write((byte)4);writer.Write((byte)1);writer.Write((ushort)42);writer.Write(partitionNumber);writer.Write(partitionStartLba);writer.Write(partitionSizeLba);writer.Write(partitionGuid.ToByteArray());writer.Write((byte)2);writer.Write((byte)2);writer.Write((byte)4);writer.Write((byte)4);writer.Write(fileNodeLength);writer.Write(path);writer.Write((byte)0x7f);writer.Write((byte)0xff);writer.Write((ushort)4);return output.ToArray();}
        }
        public static FirmwareEntryResult CreateOrReuseUnorderedEntry(uint partitionNumber,ulong startLba,ulong sizeLba,Guid partitionGuid)
        {
            RequireWindows();EnablePrivilege();byte[] oldOrder=ReadVariable("BootOrder");ParseU16(oldOrder);byte[] expected=BuildLoadOption(partitionNumber,startLba,sizeLba,partitionGuid,"\\EFI\\SecretoBoot\\refind_x64.efi","SecretoBoot");ushort selected=0;bool found=false;
            for(int i=0;i<4096;i++){ushort n=(ushort)i;byte[] current=ReadVariable("Boot"+n.ToString("X4"));FirmwareBootEntry parsed=ParseBootEntry(n,current);if(parsed.ValidationState=="FirmwareLoadOptionValidated"&&parsed.StablePartitionGuid==partitionGuid&&SameLoaderPath(parsed.EfiPath,SecretoBootLoaderPath))return new FirmwareEntryResult{Success=true,ExistingExact=true,EntryNumber=n,EntryName="Boot"+n.ToString("X4"),PreviousBootOrder=oldOrder,LoadOption=current,ReasonCode="OWNED_FIRMWARE_EQUIVALENT_FOUND"};if(Description(current)=="SecretoBoot")return new FirmwareEntryResult{ReasonCode="FIRMWARE_ENTRY_CONFLICTING_SECRETOBOOT"};if(!found&&current.Length==0){selected=n;found=true;}}
            if(!found)return new FirmwareEntryResult{ReasonCode="FIRMWARE_ENTRY_BOUNDED_SEARCH_EXHAUSTED"};string name="Boot"+selected.ToString("X4");WriteVariable(name,expected);byte[] verified=ReadVariable(name);if(!verified.SequenceEqual(expected)){Native.SetFirmwareEnvironmentVariableExW(name,Native.Global,Array.Empty<byte>(),0,Native.Attributes);return new FirmwareEntryResult{ReasonCode="FIRMWARE_ENTRY_READBACK_MISMATCH"};}return new FirmwareEntryResult{Success=true,ExistingExact=false,EntryNumber=selected,EntryName=name,PreviousBootOrder=oldOrder,LoadOption=verified,ReasonCode="FIRMWARE_ENTRY_CREATED_UNORDERED_VERIFIED"};
        }
        public static FirmwareEntryResult RepairMissingOwnedEntry(uint partitionNumber,ulong startLba,ulong sizeLba,Guid partitionGuid)
        {
            RequireWindows();EnablePrivilege();byte[] before=ReadVariable("BootOrder");ParseU16(before);FirmwareBootEntry equivalent=SelectEquivalentOwnedEntry(partitionGuid,ReadBootInventory());
            if(equivalent!=null){byte[] existing=ReadVariable(equivalent.FirmwareIdentifier);byte[] afterAdoption=ReadVariable("BootOrder");if(!afterAdoption.SequenceEqual(before))throw new InvalidOperationException("PERMANENT_BOOT_ORDER_CHANGED_DURING_REPAIR");return new FirmwareEntryResult{Success=true,ExistingExact=true,EntryNumber=equivalent.EntryNumber,EntryName=equivalent.FirmwareIdentifier,PreviousBootOrder=before,LoadOption=existing,ReasonCode="OWNED_FIRMWARE_EQUIVALENT_FOUND"};}
            FirmwareEntryResult repaired=CreateOrReuseUnorderedEntry(partitionNumber,startLba,sizeLba,partitionGuid);if(!repaired.Success)throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_CREATION_FAILED");
            bool created=!repaired.ExistingExact;try{FirmwareBootEntry verified=ValidateInstalledEntryIdentity(repaired.EntryNumber,repaired.EntryName,repaired.LoadOption,ReadVariable(repaired.EntryName),partitionGuid);ValidateInstalledEntryInventory(repaired.EntryNumber,verified,ReadBootInventory());byte[] after=ReadVariable("BootOrder");if(!after.SequenceEqual(before))throw new InvalidOperationException("PERMANENT_BOOT_ORDER_CHANGED_DURING_REPAIR");repaired.ReasonCode=repaired.ExistingExact?"OWNED_FIRMWARE_EQUIVALENT_FOUND":"OWNED_FIRMWARE_ENTRY_CREATED_VERIFIED";return repaired;}catch(Exception){if(created){try{RemoveOwnedEntry(repaired.EntryNumber,repaired.LoadOption);}catch{throw new InvalidOperationException("OWNED_FIRMWARE_REPAIR_ROLLBACK_FAILED");}}throw;}
        }
        private const string SecretoBootLoaderPath="\\EFI\\SecretoBoot\\refind_x64.efi";
        private static bool SameLoaderPath(string left,string right){return string.Equals(left,right,StringComparison.OrdinalIgnoreCase);}
        public static FirmwareBootEntry ValidateInstalledEntryIdentity(ushort entry,string recordedEntryName,byte[] recordedLoadOption,byte[] actualLoadOption,Guid expectedPartitionGuid)
        {
            string expectedName="Boot"+entry.ToString("X4");
            if(string.IsNullOrWhiteSpace(recordedEntryName)||!string.Equals(recordedEntryName,expectedName,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_NUMBER_MISMATCH");
            if(expectedPartitionGuid==Guid.Empty)throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_PARTITION_IDENTITY_INVALID");
            if(recordedLoadOption==null||recordedLoadOption.Length==0)throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_RECORDED_IDENTITY_MISSING");
            FirmwareBootEntry recorded=ParseBootEntry(entry,recordedLoadOption);
            if(recorded.ValidationState!="FirmwareLoadOptionValidated")throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_RECORDED_IDENTITY_INVALID");
            if(recorded.StablePartitionGuid!=expectedPartitionGuid)throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_RECORDED_PARTITION_MISMATCH");
            if(!SameLoaderPath(recorded.EfiPath,SecretoBootLoaderPath))throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_RECORDED_LOADER_MISMATCH");
            if(actualLoadOption==null||actualLoadOption.Length==0)throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_MISSING");
            FirmwareBootEntry actual=ParseBootEntry(entry,actualLoadOption);
            if(actual.ValidationState!="FirmwareLoadOptionValidated")throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_LOAD_OPTION_INVALID");
            if(actual.StablePartitionGuid!=expectedPartitionGuid)throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_PARTITION_MISMATCH");
            if(!SameLoaderPath(actual.EfiPath,SecretoBootLoaderPath))throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_LOADER_MISMATCH");
            return actual;
        }
        public static void ValidateInstalledEntryInventory(ushort entry,FirmwareBootEntry expected,FirmwareBootEntry[] inventory)
        {
            if(expected==null||expected.ValidationState!="FirmwareLoadOptionValidated"||expected.StablePartitionGuid==Guid.Empty||!SameLoaderPath(expected.EfiPath,SecretoBootLoaderPath))throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_IDENTITY_DENIED");
            if(inventory==null)throw new InvalidOperationException("OWNED_FIRMWARE_INVENTORY_MISSING");
            FirmwareBootEntry[] matches=inventory.Where(x=>x!=null&&x.ValidationState=="FirmwareLoadOptionValidated"&&x.StablePartitionGuid==expected.StablePartitionGuid&&SameLoaderPath(x.EfiPath,SecretoBootLoaderPath)).ToArray();
            if(matches.Length==0)throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_MISSING");
            if(matches.Length!=1)throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_AMBIGUOUS");
            if(matches[0].EntryNumber!=entry)throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_NUMBER_MISMATCH");
        }
        private static FirmwareBootEntry VerifyInstalledOwnedEntryExact(ushort entry,string recordedEntryName,byte[] recordedLoadOption,Guid expectedPartitionGuid){return ValidateInstalledEntryIdentity(entry,recordedEntryName,recordedLoadOption,ReadVariable("Boot"+entry.ToString("X4")),expectedPartitionGuid);}
        public static FirmwareBootEntry VerifyInstalledOwnedEntry(ushort entry,string recordedEntryName,byte[] recordedLoadOption,Guid expectedPartitionGuid){FirmwareBootEntry actual=VerifyInstalledOwnedEntryExact(entry,recordedEntryName,recordedLoadOption,expectedPartitionGuid);ValidateInstalledEntryInventory(entry,actual,ReadBootInventory());return actual;}
        public static void VerifyOwnedEntry(ushort entry,byte[] expectedLoadOption){byte[] actual=ReadVariable("Boot"+entry.ToString("X4"));if(expectedLoadOption==null||!actual.SequenceEqual(expectedLoadOption)||Description(actual)!="SecretoBoot")throw new InvalidOperationException("FIRMWARE_ENTRY_POSTWRITE_VERIFICATION_DENIED");}
        public static void SetBootNextAndVerify(ushort entry,byte[] expectedLoadOption){VerifyOwnedEntry(entry,expectedLoadOption);WriteVariable("BootNext",U16(new[]{entry}));byte[] actual=ReadVariable("BootNext");if(actual.Length!=2||ParseU16(actual)[0]!=entry)throw new InvalidOperationException("BOOTNEXT_READBACK_MISMATCH");VerifyOwnedEntry(entry,expectedLoadOption);}
        public static void SetInstalledBootNextAndVerify(ushort entry,string recordedEntryName,byte[] recordedLoadOption,Guid expectedPartitionGuid){VerifyInstalledOwnedEntryExact(entry,recordedEntryName,recordedLoadOption,expectedPartitionGuid);WriteVariable("BootNext",U16(new[]{entry}));byte[] actual=ReadVariable("BootNext");if(actual.Length!=2||ParseU16(actual)[0]!=entry)throw new InvalidOperationException("BOOTNEXT_READBACK_MISMATCH");VerifyInstalledOwnedEntryExact(entry,recordedEntryName,recordedLoadOption,expectedPartitionGuid);}
        public static void ClearOwnedBootNext(ushort entry){byte[] value=ReadVariable("BootNext");if(value.Length==0)return;if(value.Length!=2||ParseU16(value)[0]!=entry)throw new InvalidOperationException("BOOTNEXT_FOREIGN_STATE_DENIED");if(!Native.SetFirmwareEnvironmentVariableExW("BootNext",Native.Global,Array.Empty<byte>(),0,Native.Attributes))throw new InvalidOperationException("BOOTNEXT_CLEAR_DENIED_"+Marshal.GetLastWin32Error());}
        public static ushort[] BuildPersistentOrder(ushort entry,ushort[] previous){if(previous==null)throw new ArgumentNullException(nameof(previous));return new[]{entry}.Concat(previous.Where(x=>x!=entry)).ToArray();}
        private sealed class BcdEditResult{internal int ExitCode;internal string Output="";internal string Error="";internal string EffectiveCommand="";}
        public static string LastPersistentDefaultDiagnostic{get;private set;}="Not evaluated";
        private static string BoundedDiagnosticText(string value,int maximum){string text=(value??"").Replace("\r"," ").Replace("\n"," | ").Replace("\t"," ").Trim();return text.Length<=maximum?text:text.Substring(0,maximum);}
        private static BcdEditResult RunBcdEdit(params string[] arguments)
        {
            string executable=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32","bcdedit.exe");
            if(!File.Exists(executable))throw new InvalidOperationException("WINDOWS_FIRMWARE_MANAGER_UNAVAILABLE");
            if(arguments==null||arguments.Length==0||arguments.Any(x=>string.IsNullOrWhiteSpace(x)||x.IndexOfAny(new[]{'\r','\n','\0'})>=0))throw new InvalidOperationException("WINDOWS_FIRMWARE_ARGUMENTS_DENIED");
            var start=new ProcessStartInfo{FileName=executable,UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
            foreach(string argument in arguments)start.ArgumentList.Add(argument);
            using(var process=Process.Start(start))
            {
                if(process==null)throw new InvalidOperationException("WINDOWS_FIRMWARE_MANAGER_START_FAILED");
                var outputTask=process.StandardOutput.ReadToEndAsync();var errorTask=process.StandardError.ReadToEndAsync();
                if(!process.WaitForExit(15000)){try{process.Kill();}catch{}throw new InvalidOperationException("WINDOWS_FIRMWARE_MANAGER_TIMEOUT");}
                string output=outputTask.GetAwaiter().GetResult(),error=errorTask.GetAwaiter().GetResult();
                if(output.Length>1048576||error.Length>65536)throw new InvalidOperationException("WINDOWS_FIRMWARE_MANAGER_OUTPUT_CAP_EXCEEDED");
                return new BcdEditResult{ExitCode=process.ExitCode,Output=output,Error=error,EffectiveCommand=executable+" "+string.Join(" ",arguments)};
            }
        }
        private static string[] BcdBlocks(string output){return Regex.Split((output??"").Replace("\r\n","\n"),@"\n\s*\n").Where(x=>!string.IsNullOrWhiteSpace(x)).ToArray();}
        private static string ResolveOwnedBcdIdentifier(string output)
        {
            var matches=new List<string>();
            foreach(string block in BcdBlocks(output))
            {
                if(block.IndexOf(SecretoBootLoaderPath,StringComparison.OrdinalIgnoreCase)<0||block.IndexOf("SecretoBoot",StringComparison.OrdinalIgnoreCase)<0)continue;
                Match identifier=Regex.Match(block,@"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}",RegexOptions.CultureInvariant);
                if(identifier.Success)matches.Add(identifier.Value.ToLowerInvariant());
            }
            string[] unique=matches.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if(unique.Length==0)throw new InvalidOperationException("OWNED_WINDOWS_FIRMWARE_OBJECT_NOT_FOUND");
            if(unique.Length!=1)throw new InvalidOperationException("OWNED_WINDOWS_FIRMWARE_OBJECT_AMBIGUOUS");
            return unique[0];
        }
        private static string CurrentBcdDisplayOrderFirst(string output)
        {
            string manager=BcdBlocks(output).FirstOrDefault(x=>x.IndexOf("{fwbootmgr}",StringComparison.OrdinalIgnoreCase)>=0);
            if(string.IsNullOrWhiteSpace(manager))throw new InvalidOperationException("WINDOWS_FIRMWARE_DISPLAYORDER_NOT_FOUND");
            Match first=Regex.Match(manager,@"(?im)^\s*displayorder\s+(\{(?:bootmgr|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\})",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);
            if(!first.Success)throw new InvalidOperationException("WINDOWS_FIRMWARE_DISPLAYORDER_EMPTY");
            return first.Groups[1].Value.ToLowerInvariant();
        }
        public static string ResolveOwnedBcdIdentifierForValidation(string output){return ResolveOwnedBcdIdentifier(output);}
        public static string CurrentBcdDisplayOrderFirstForValidation(string output){return CurrentBcdDisplayOrderFirst(output);}
        private const string NativeWindowsBootManagerPath="\\EFI\\Microsoft\\Boot\\bootmgfw.efi";
        private const string SecretoBootCompatibilityPath="\\EFI\\SecretoBoot\\refind_x64.efi";
        private static string ParseBootManagerPath(string output)
        {
            Match path=Regex.Match(output??"",@"(?im)^\s*path\s+(\\EFI\\[^\r\n]+\.efi)\s*$",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);
            if(!path.Success)throw new InvalidOperationException("WINDOWS_BOOTMGR_PATH_MISSING");
            return path.Groups[1].Value.Trim();
        }
        public static string ParseBootManagerPathForValidation(string output){return ParseBootManagerPath(output);}
        public static string ReadWindowsBootManagerPath()
        {
            BcdEditResult read=RunBcdEdit("/enum","{bootmgr}");
            if(read.ExitCode!=0)throw new InvalidOperationException("WINDOWS_BOOTMGR_QUERY_FAILED");
            return ParseBootManagerPath(read.Output);
        }
        public static string EnableWindowsFirstCompatibility()
        {
            string before=ReadWindowsBootManagerPath();
            if(!SameLoaderPath(before,NativeWindowsBootManagerPath))throw new InvalidOperationException("WINDOWS_NATIVE_PATH_MISMATCH");
            BcdEditResult write=RunBcdEdit("/set","{bootmgr}","path",SecretoBootCompatibilityPath);bool attempted=true;
            try
            {
                if(write.ExitCode!=0)throw new InvalidOperationException("WINDOWS_FIRST_COMPATIBILITY_WRITE_DENIED");
                string after=ReadWindowsBootManagerPath();
                if(!SameLoaderPath(after,SecretoBootCompatibilityPath))throw new InvalidOperationException("WINDOWS_FIRST_COMPATIBILITY_READBACK_MISMATCH");
                return before;
            }
            catch
            {
                if(attempted)
                {
                    BcdEditResult rollback=RunBcdEdit("/set","{bootmgr}","path",before);
                    if(rollback.ExitCode!=0||!SameLoaderPath(ReadWindowsBootManagerPath(),before))throw new InvalidOperationException("WINDOWS_FIRST_COMPATIBILITY_ROLLBACK_FAILED");
                }
                throw;
            }
        }
        public static void RestoreNativeWindowsBoot(string recordedOriginalPath)
        {
            if(!SameLoaderPath(recordedOriginalPath,NativeWindowsBootManagerPath))throw new InvalidOperationException("RECORDED_NATIVE_WINDOWS_BOOT_PATH_DENIED");
            string current=ReadWindowsBootManagerPath();
            if(!SameLoaderPath(current,SecretoBootCompatibilityPath)&&!SameLoaderPath(current,NativeWindowsBootManagerPath))throw new InvalidOperationException("WINDOWS_BOOT_MANAGER_PATH_CONCURRENT_CHANGE_DENIED");
            if(SameLoaderPath(current,NativeWindowsBootManagerPath))return;
            BcdEditResult restore=RunBcdEdit("/set","{bootmgr}","path",recordedOriginalPath);
            if(restore.ExitCode!=0||!SameLoaderPath(ReadWindowsBootManagerPath(),recordedOriginalPath))throw new InvalidOperationException("NATIVE_WINDOWS_BOOT_RESTORE_FAILED");
        }
        public static void MakeDefault(ushort entry)
        {
            LastPersistentDefaultDiagnostic="Stage=Start; Store=SystemDefault; Result=NotExecuted";
            byte[] before=ReadVariable("BootOrder");ushort[] order=ParseU16(before);ushort[] expected=BuildPersistentOrder(entry,order);
            FirmwareBootEntry owned=ReadBootInventory().SingleOrDefault(x=>x.EntryNumber==entry&&x.ValidationState=="FirmwareLoadOptionValidated"&&SameLoaderPath(x.EfiPath,SecretoBootLoaderPath));
            if(owned==null)throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_IDENTITY_DENIED");
            BcdEditResult inventory=RunBcdEdit("/enum","firmware");if(inventory.ExitCode!=0){LastPersistentDefaultDiagnostic="Stage=PreWriteInventory; Command="+inventory.EffectiveCommand+"; ExitCode="+inventory.ExitCode+"; Stdout="+BoundedDiagnosticText(inventory.Output,240)+"; Stderr="+BoundedDiagnosticText(inventory.Error,240)+"; Result=WINDOWS_FIRMWARE_INVENTORY_QUERY_FAILED";throw new InvalidOperationException("WINDOWS_FIRMWARE_INVENTORY_QUERY_FAILED");}
            string identifier=ResolveOwnedBcdIdentifier(inventory.Output),originalFirstIdentifier=CurrentBcdDisplayOrderFirst(inventory.Output);bool commandCompleted=false;
            if(!Regex.IsMatch(identifier,@"^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$",RegexOptions.CultureInvariant))throw new InvalidOperationException("OWNED_WINDOWS_FIRMWARE_IDENTIFIER_INVALID");
            try
            {
                BcdEditResult write=RunBcdEdit("/set","{fwbootmgr}","displayorder",identifier,"/addfirst");commandCompleted=true;
                if(write.ExitCode!=0){LastPersistentDefaultDiagnostic="Stage=Write; Store=SystemDefault; Command="+write.EffectiveCommand+"; ExitCode="+write.ExitCode+"; Stdout="+BoundedDiagnosticText(write.Output,240)+"; Stderr="+BoundedDiagnosticText(write.Error,240)+"; ExpectedFirst="+identifier+"; Result=PERSISTENT_BOOTORDER_WRITE_DENIED";throw new InvalidOperationException("PERSISTENT_BOOTORDER_WRITE_DENIED");}
                ushort[] actual=ParseU16(ReadVariable("BootOrder"));
                BcdEditResult fresh=RunBcdEdit("/enum","firmware");string freshFirst=fresh.ExitCode==0?CurrentBcdDisplayOrderFirst(fresh.Output):"UNAVAILABLE";
                LastPersistentDefaultDiagnostic="Stage=ImmediateReadback; Store=SystemDefault; Command="+write.EffectiveCommand+"; ExitCode="+write.ExitCode+"; Stdout="+BoundedDiagnosticText(write.Output,240)+"; Stderr="+BoundedDiagnosticText(write.Error,240)+"; FreshEnumCommand="+fresh.EffectiveCommand+"; FreshEnumExitCode="+fresh.ExitCode+"; ExpectedFirst="+identifier+"; ActualFirst="+freshFirst+"; RawBootOrderFirst=Boot"+(actual.Length==0?"NONE":actual[0].ToString("X4"))+"; Result="+(fresh.ExitCode==0&&string.Equals(freshFirst,identifier,StringComparison.OrdinalIgnoreCase)&&actual.SequenceEqual(expected)&&actual.Length>0&&actual[0]==entry?"VERIFIED":"PERSISTENT_BOOTORDER_WRITE_NOT_EFFECTIVE");
                if(fresh.ExitCode!=0||!string.Equals(freshFirst,identifier,StringComparison.OrdinalIgnoreCase)||!actual.SequenceEqual(expected)||actual.Length==0||actual[0]!=entry)throw new InvalidOperationException("PERSISTENT_BOOTORDER_WRITE_NOT_EFFECTIVE");
                FirmwareBootEntry freshOwned=ReadBootInventory().SingleOrDefault(x=>x.EntryNumber==entry&&x.ValidationState=="FirmwareLoadOptionValidated"&&x.StablePartitionGuid==owned.StablePartitionGuid&&SameLoaderPath(x.EfiPath,SecretoBootLoaderPath));
                if(freshOwned==null)throw new InvalidOperationException("PERSISTENT_BOOTORDER_FRESH_IDENTITY_MISMATCH");
            }
            catch
            {
                if(commandCompleted)
                {
                    BcdEditResult rollback=RunBcdEdit("/set","{fwbootmgr}","displayorder",originalFirstIdentifier,"/addfirst");
                    BcdEditResult rollbackInventory=RunBcdEdit("/enum","firmware");
                    if(rollback.ExitCode!=0||rollbackInventory.ExitCode!=0||!string.Equals(CurrentBcdDisplayOrderFirst(rollbackInventory.Output),originalFirstIdentifier,StringComparison.OrdinalIgnoreCase)||!ReadVariable("BootOrder").SequenceEqual(before))throw new InvalidOperationException("PERSISTENT_BOOTORDER_ROLLBACK_FAILED");
                }
                throw;
            }
        }
        public static void VerifyPersistentDefault(ushort entry,byte[] expectedLoadOption,byte[] previousOrder){VerifyOwnedEntry(entry,expectedLoadOption);ushort[] previous=ParseU16(previousOrder);ushort[] expected=BuildPersistentOrder(entry,previous);ushort[] actual=ParseU16(ReadVariable("BootOrder"));if(!actual.SequenceEqual(expected)||actual.Length==0||actual[0]!=entry)throw new InvalidOperationException("PERSISTENT_DEFAULT_READBACK_MISMATCH");byte[] next=ReadVariable("BootNext");if(next.Length==2&&ParseU16(next)[0]==entry)throw new InvalidOperationException("PERSISTENT_DEFAULT_BOOTNEXT_CONFLICT_DENIED");}
        public static void VerifyInstalledPersistentDefault(ushort entry,string recordedEntryName,byte[] recordedLoadOption,Guid expectedPartitionGuid,byte[] previousOrder){VerifyInstalledOwnedEntryExact(entry,recordedEntryName,recordedLoadOption,expectedPartitionGuid);ushort[] previous=ParseU16(previousOrder);ushort[] expected=BuildPersistentOrder(entry,previous);ushort[] actual=ParseU16(ReadVariable("BootOrder"));if(!actual.SequenceEqual(expected)||actual.Length==0||actual[0]!=entry)throw new InvalidOperationException("PERSISTENT_DEFAULT_READBACK_MISMATCH");byte[] next=ReadVariable("BootNext");if(next.Length==2&&ParseU16(next)[0]==entry)throw new InvalidOperationException("PERSISTENT_DEFAULT_BOOTNEXT_CONFLICT_DENIED");}
        public static void RestoreExactOrder(byte[] expectedOrder){ushort[] expected=ParseU16(expectedOrder);WriteVariable("BootOrder",expectedOrder);ushort[] actual=ParseU16(ReadVariable("BootOrder"));if(!actual.SequenceEqual(expected))throw new InvalidOperationException("BOOT_ORDER_ROLLBACK_READBACK_MISMATCH");}
        public static void RestorePreviousOrder(ushort entry,byte[] previousOrder){ushort[] current=ParseU16(ReadVariable("BootOrder"));ushort[] previous=ParseU16(previousOrder);ushort[] expectedCurrent=BuildPersistentOrder(entry,previous);if(!current.SequenceEqual(expectedCurrent))throw new InvalidOperationException("BOOT_ORDER_CONCURRENT_CHANGE_DENIED");WriteVariable("BootOrder",previousOrder);ushort[] actual=ParseU16(ReadVariable("BootOrder"));if(!actual.SequenceEqual(previous))throw new InvalidOperationException("BOOT_ORDER_RESTORE_READBACK_MISMATCH");}
        public static void RemoveOwnedEntry(ushort entry,byte[] expectedLoadOption){string name="Boot"+entry.ToString("X4");byte[] current=ReadVariable(name);if(current.Length==0)throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_MISSING");if(expectedLoadOption==null||!current.SequenceEqual(expectedLoadOption))throw new InvalidOperationException("OWNED_FIRMWARE_ENTRY_IDENTITY_DENIED");byte[] next=ReadVariable("BootNext");if(next.Length==2&&ParseU16(next)[0]==entry)ClearOwnedBootNext(entry);ushort[] order=ParseU16(ReadVariable("BootOrder"));if(order.Contains(entry))WriteVariable("BootOrder",U16(order.Where(x=>x!=entry)));if(!Native.SetFirmwareEnvironmentVariableExW(name,Native.Global,Array.Empty<byte>(),0,Native.Attributes))throw new InvalidOperationException("FIRMWARE_ENTRY_DELETE_DENIED_"+Marshal.GetLastWin32Error());}
    }
}
