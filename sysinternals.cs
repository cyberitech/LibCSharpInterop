using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

/*
 * HAIL TO MY SAVIOR http://pinvoke.net/
 */

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_DATA_DIRECTORY
{
    public UInt32 VirtualAddress;
    public UInt32 Size;
}
[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_DOS_HEADER
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
    public char[] e_magic;       // Magic number
    public UInt16 e_cblp;    // Bytes on last page of file
    public UInt16 e_cp;      // Pages in file
    public UInt16 e_crlc;    // Relocations
    public UInt16 e_cparhdr;     // Size of header in paragraphs
    public UInt16 e_minalloc;    // Minimum extra paragraphs needed
    public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
    public UInt16 e_ss;      // Initial (relative) SS value
    public UInt16 e_sp;      // Initial SP value
    public UInt16 e_csum;    // Checksum
    public UInt16 e_ip;      // Initial IP value
    public UInt16 e_cs;      // Initial (relative) CS value
    public UInt16 e_lfarlc;      // File address of relocation table
    public UInt16 e_ovno;    // Overlay number
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public UInt16[] e_res1;    // Reserved words
    public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
    public UInt16 e_oeminfo;     // OEM information; e_oemid specific
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
    public UInt16[] e_res2;    // Reserved words
    public Int32 e_lfanew;      // File address of new exe header

    private string _e_magic
    {
        get { return new string(e_magic); }
    }

    public bool isValid
    {
        get { return _e_magic == "MZ"; }
    }
}
[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_FILE_HEADER
{
    public UInt16 Machine;
    public UInt16 NumberOfSections;
    public UInt32 TimeDateStamp;
    public UInt32 PointerToSymbolTable;
    public UInt32 NumberOfSymbols;
    public UInt16 SizeOfOptionalHeader;
    public UInt16 Characteristics;
}

[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_NT_HEADERS32
{
    [FieldOffset(0)]
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public char[] Signature;

    [FieldOffset(4)]
    public IMAGE_FILE_HEADER FileHeader;

    [FieldOffset(24)]
    public IMAGE_OPTIONAL_HEADER32 OptionalHeader;

    private string _Signature
    {
        get { return new string(Signature); }
    }

    public bool isValid
    {
        get { return _Signature == "PE\0\0" && OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR32_MAGIC; }
    }
}
[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_NT_HEADERS64
{
    [FieldOffset(0)]
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public char[] Signature;

    [FieldOffset(4)]
    public IMAGE_FILE_HEADER FileHeader;

    [FieldOffset(24)]
    public IMAGE_OPTIONAL_HEADER64 OptionalHeader;

    private string _Signature
    {
        get { return new string(Signature); }
    }

    public bool isValid
    {
        get { return _Signature == "PE\0\0" && OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC; }
    }
}
public enum MachineType : ushort
{
    Native = 0,
    I386 = 0x014c,
    Itanium = 0x0200,
    x64 = 0x8664
}
public enum MagicType : ushort
{
    IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
}
public enum SubSystemType : ushort
{
    IMAGE_SUBSYSTEM_UNKNOWN = 0,
    IMAGE_SUBSYSTEM_NATIVE = 1,
    IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
    IMAGE_SUBSYSTEM_POSIX_CUI = 7,
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
    IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
    IMAGE_SUBSYSTEM_EFI_ROM = 13,
    IMAGE_SUBSYSTEM_XBOX = 14

}
public enum DllCharacteristicsType : ushort
{
    RES_0 = 0x0001,
    RES_1 = 0x0002,
    RES_2 = 0x0004,
    RES_3 = 0x0008,
    IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
    IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
    IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
    RES_4 = 0x1000,
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
}

[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_OPTIONAL_HEADER32
{
    [FieldOffset(0)]
    public MagicType Magic;

    [FieldOffset(2)]
    public byte MajorLinkerVersion;

    [FieldOffset(3)]
    public byte MinorLinkerVersion;

    [FieldOffset(4)]
    public uint SizeOfCode;

    [FieldOffset(8)]
    public uint SizeOfInitializedData;

    [FieldOffset(12)]
    public uint SizeOfUninitializedData;

    [FieldOffset(16)]
    public uint AddressOfEntryPoint;

    [FieldOffset(20)]
    public uint BaseOfCode;

    // PE32 contains this additional field
    [FieldOffset(24)]
    public uint BaseOfData;

    [FieldOffset(28)]
    public uint ImageBase;

    [FieldOffset(32)]
    public uint SectionAlignment;

    [FieldOffset(36)]
    public uint FileAlignment;

    [FieldOffset(40)]
    public ushort MajorOperatingSystemVersion;

    [FieldOffset(42)]
    public ushort MinorOperatingSystemVersion;

    [FieldOffset(44)]
    public ushort MajorImageVersion;

    [FieldOffset(46)]
    public ushort MinorImageVersion;

    [FieldOffset(48)]
    public ushort MajorSubsystemVersion;

    [FieldOffset(50)]
    public ushort MinorSubsystemVersion;

    [FieldOffset(52)]
    public uint Win32VersionValue;

    [FieldOffset(56)]
    public uint SizeOfImage;

    [FieldOffset(60)]
    public uint SizeOfHeaders;

    [FieldOffset(64)]
    public uint CheckSum;

    [FieldOffset(68)]
    public SubSystemType Subsystem;

    [FieldOffset(70)]
    public DllCharacteristicsType DllCharacteristics;

    [FieldOffset(72)]
    public uint SizeOfStackReserve;

    [FieldOffset(76)]
    public uint SizeOfStackCommit;

    [FieldOffset(80)]
    public uint SizeOfHeapReserve;

    [FieldOffset(84)]
    public uint SizeOfHeapCommit;

    [FieldOffset(88)]
    public uint LoaderFlags;

    [FieldOffset(92)]
    public uint NumberOfRvaAndSizes;

    [FieldOffset(96)]
    public IMAGE_DATA_DIRECTORY ExportTable;

    [FieldOffset(104)]
    public IMAGE_DATA_DIRECTORY ImportTable;

    [FieldOffset(112)]
    public IMAGE_DATA_DIRECTORY ResourceTable;

    [FieldOffset(120)]
    public IMAGE_DATA_DIRECTORY ExceptionTable;

    [FieldOffset(128)]
    public IMAGE_DATA_DIRECTORY CertificateTable;

    [FieldOffset(136)]
    public IMAGE_DATA_DIRECTORY BaseRelocationTable;

    [FieldOffset(144)]
    public IMAGE_DATA_DIRECTORY Debug;

    [FieldOffset(152)]
    public IMAGE_DATA_DIRECTORY Architecture;

    [FieldOffset(160)]
    public IMAGE_DATA_DIRECTORY GlobalPtr;

    [FieldOffset(168)]
    public IMAGE_DATA_DIRECTORY TLSTable;

    [FieldOffset(176)]
    public IMAGE_DATA_DIRECTORY LoadConfigTable;

    [FieldOffset(184)]
    public IMAGE_DATA_DIRECTORY BoundImport;

    [FieldOffset(192)]
    public IMAGE_DATA_DIRECTORY IAT;

    [FieldOffset(200)]
    public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

    [FieldOffset(208)]
    public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

    [FieldOffset(216)]
    public IMAGE_DATA_DIRECTORY Reserved;
}
[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_OPTIONAL_HEADER64
{
    [FieldOffset(0)]
    public MagicType Magic;

    [FieldOffset(2)]
    public byte MajorLinkerVersion;

    [FieldOffset(3)]
    public byte MinorLinkerVersion;

    [FieldOffset(4)]
    public uint SizeOfCode;

    [FieldOffset(8)]
    public uint SizeOfInitializedData;

    [FieldOffset(12)]
    public uint SizeOfUninitializedData;

    [FieldOffset(16)]
    public uint AddressOfEntryPoint;

    [FieldOffset(20)]
    public uint BaseOfCode;

    [FieldOffset(24)]
    public ulong ImageBase;

    [FieldOffset(32)]
    public uint SectionAlignment;

    [FieldOffset(36)]
    public uint FileAlignment;

    [FieldOffset(40)]
    public ushort MajorOperatingSystemVersion;

    [FieldOffset(42)]
    public ushort MinorOperatingSystemVersion;

    [FieldOffset(44)]
    public ushort MajorImageVersion;

    [FieldOffset(46)]
    public ushort MinorImageVersion;

    [FieldOffset(48)]
    public ushort MajorSubsystemVersion;

    [FieldOffset(50)]
    public ushort MinorSubsystemVersion;

    [FieldOffset(52)]
    public uint Win32VersionValue;

    [FieldOffset(56)]
    public uint SizeOfImage;

    [FieldOffset(60)]
    public uint SizeOfHeaders;

    [FieldOffset(64)]
    public uint CheckSum;

    [FieldOffset(68)]
    public SubSystemType Subsystem;

    [FieldOffset(70)]
    public DllCharacteristicsType DllCharacteristics;

    [FieldOffset(72)]
    public ulong SizeOfStackReserve;

    [FieldOffset(80)]
    public ulong SizeOfStackCommit;

    [FieldOffset(88)]
    public ulong SizeOfHeapReserve;

    [FieldOffset(96)]
    public ulong SizeOfHeapCommit;

    [FieldOffset(104)]
    public uint LoaderFlags;

    [FieldOffset(108)]
    public uint NumberOfRvaAndSizes;

    [FieldOffset(112)]
    public IMAGE_DATA_DIRECTORY ExportTable;

    [FieldOffset(120)]
    public IMAGE_DATA_DIRECTORY ImportTable;

    [FieldOffset(128)]
    public IMAGE_DATA_DIRECTORY ResourceTable;

    [FieldOffset(136)]
    public IMAGE_DATA_DIRECTORY ExceptionTable;

    [FieldOffset(144)]
    public IMAGE_DATA_DIRECTORY CertificateTable;

    [FieldOffset(152)]
    public IMAGE_DATA_DIRECTORY BaseRelocationTable;

    [FieldOffset(160)]
    public IMAGE_DATA_DIRECTORY Debug;

    [FieldOffset(168)]
    public IMAGE_DATA_DIRECTORY Architecture;

    [FieldOffset(176)]
    public IMAGE_DATA_DIRECTORY GlobalPtr;

    [FieldOffset(184)]
    public IMAGE_DATA_DIRECTORY TLSTable;

    [FieldOffset(192)]
    public IMAGE_DATA_DIRECTORY LoadConfigTable;

    [FieldOffset(200)]
    public IMAGE_DATA_DIRECTORY BoundImport;

    [FieldOffset(208)]
    public IMAGE_DATA_DIRECTORY IAT;

    [FieldOffset(216)]
    public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

    [FieldOffset(224)]
    public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

    [FieldOffset(232)]
    public IMAGE_DATA_DIRECTORY Reserved;
}
[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_SECTION_HEADER
{
    [FieldOffset(0)]
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public char[] Name;

    [FieldOffset(8)]
    public UInt32 VirtualSize;

    [FieldOffset(12)]
    public UInt32 VirtualAddress;

    [FieldOffset(16)]
    public UInt32 SizeOfRawData;

    [FieldOffset(20)]
    public UInt32 PointerToRawData;

    [FieldOffset(24)]
    public UInt32 PointerToRelocations;

    [FieldOffset(28)]
    public UInt32 PointerToLinenumbers;

    [FieldOffset(32)]
    public UInt16 NumberOfRelocations;

    [FieldOffset(34)]
    public UInt16 NumberOfLinenumbers;

    [FieldOffset(36)]
    public DataSectionFlags Characteristics;

    public string Section
    {
        get { return new string(Name); }
    }
}
[Flags]
public enum DataSectionFlags : uint
{
    /// <summary>
    /// Reserved for future use.
    /// </summary>
    TypeReg = 0x00000000,
    /// <summary>
    /// Reserved for future use.
    /// </summary>
    TypeDsect = 0x00000001,
    /// <summary>
    /// Reserved for future use.
    /// </summary>
    TypeNoLoad = 0x00000002,
    /// <summary>
    /// Reserved for future use.
    /// </summary>
    TypeGroup = 0x00000004,
    /// <summary>
    /// The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
    /// </summary>
    TypeNoPadded = 0x00000008,
    /// <summary>
    /// Reserved for future use.
    /// </summary>
    TypeCopy = 0x00000010,
    /// <summary>
    /// The section contains executable code.
    /// </summary>
    ContentCode = 0x00000020,
    /// <summary>
    /// The section contains initialized data.
    /// </summary>
    ContentInitializedData = 0x00000040,
    /// <summary>
    /// The section contains uninitialized data.
    /// </summary>
    ContentUninitializedData = 0x00000080,
    /// <summary>
    /// Reserved for future use.
    /// </summary>
    LinkOther = 0x00000100,
    /// <summary>
    /// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
    /// </summary>
    LinkInfo = 0x00000200,
    /// <summary>
    /// Reserved for future use.
    /// </summary>
    TypeOver = 0x00000400,
    /// <summary>
    /// The section will not become part of the image. This is valid only for object files.
    /// </summary>
    LinkRemove = 0x00000800,
    /// <summary>
    /// The section contains COMDAT data. For more information, see section 5.5.6, COMDAT Sections (Object Only). This is valid only for object files.
    /// </summary>
    LinkComDat = 0x00001000,
    /// <summary>
    /// Reset speculative exceptions handling bits in the TLB entries for this section.
    /// </summary>
    NoDeferSpecExceptions = 0x00004000,
    /// <summary>
    /// The section contains data referenced through the global pointer (GP).
    /// </summary>
    RelativeGP = 0x00008000,
    /// <summary>
    /// Reserved for future use.
    /// </summary>
    MemPurgeable = 0x00020000,
    /// <summary>
    /// Reserved for future use.
    /// </summary>
    Memory16Bit = 0x00020000,
    /// <summary>
    /// Reserved for future use.
    /// </summary>
    MemoryLocked = 0x00040000,
    /// <summary>
    /// Reserved for future use.
    /// </summary>
    MemoryPreload = 0x00080000,
    /// <summary>
    /// Align data on a 1-byte boundary. Valid only for object files.
    /// </summary>
    Align1Bytes = 0x00100000,
    /// <summary>
    /// Align data on a 2-byte boundary. Valid only for object files.
    /// </summary>
    Align2Bytes = 0x00200000,
    /// <summary>
    /// Align data on a 4-byte boundary. Valid only for object files.
    /// </summary>
    Align4Bytes = 0x00300000,
    /// <summary>
    /// Align data on an 8-byte boundary. Valid only for object files.
    /// </summary>
    Align8Bytes = 0x00400000,
    /// <summary>
    /// Align data on a 16-byte boundary. Valid only for object files.
    /// </summary>
    Align16Bytes = 0x00500000,
    /// <summary>
    /// Align data on a 32-byte boundary. Valid only for object files.
    /// </summary>
    Align32Bytes = 0x00600000,
    /// <summary>
    /// Align data on a 64-byte boundary. Valid only for object files.
    /// </summary>
    Align64Bytes = 0x00700000,
    /// <summary>
    /// Align data on a 128-byte boundary. Valid only for object files.
    /// </summary>
    Align128Bytes = 0x00800000,
    /// <summary>
    /// Align data on a 256-byte boundary. Valid only for object files.
    /// </summary>
    Align256Bytes = 0x00900000,
    /// <summary>
    /// Align data on a 512-byte boundary. Valid only for object files.
    /// </summary>
    Align512Bytes = 0x00A00000,
    /// <summary>
    /// Align data on a 1024-byte boundary. Valid only for object files.
    /// </summary>
    Align1024Bytes = 0x00B00000,
    /// <summary>
    /// Align data on a 2048-byte boundary. Valid only for object files.
    /// </summary>
    Align2048Bytes = 0x00C00000,
    /// <summary>
    /// Align data on a 4096-byte boundary. Valid only for object files.
    /// </summary>
    Align4096Bytes = 0x00D00000,
    /// <summary>
    /// Align data on an 8192-byte boundary. Valid only for object files.
    /// </summary>
    Align8192Bytes = 0x00E00000,
    /// <summary>
    /// The section contains extended relocations.
    /// </summary>
    LinkExtendedRelocationOverflow = 0x01000000,
    /// <summary>
    /// The section can be discarded as needed.
    /// </summary>
    MemoryDiscardable = 0x02000000,
    /// <summary>
    /// The section cannot be cached.
    /// </summary>
    MemoryNotCached = 0x04000000,
    /// <summary>
    /// The section is not pageable.
    /// </summary>
    MemoryNotPaged = 0x08000000,
    /// <summary>
    /// The section can be shared in memory.
    /// </summary>
    MemoryShared = 0x10000000,
    /// <summary>
    /// The section can be executed as code.
    /// </summary>
    MemoryExecute = 0x20000000,
    /// <summary>
    /// The section can be read.
    /// </summary>
    MemoryRead = 0x40000000,
    /// <summary>
    /// The section can be written to.
    /// </summary>
    MemoryWrite = 0x80000000
}
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct STARTUPINFO
{
    public uint cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
    public uint dwX;
    public uint dwY;
    public uint dwXSize;
    public uint dwYSize;
    public uint dwXCountChars;
    public uint dwYCountChars;
    public uint dwFillAttribute;
    public uint dwFlags;
    public ushort wShowWindow;
    public ushort cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}
[StructLayout(LayoutKind.Sequential)]
internal struct PROCESS_INFORMATION
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
}
public enum CONTEXT_FLAGS : uint
{
    CONTEXT_i386 = 0x10000,
    CONTEXT_i486 = 0x10000,   //  same as i386
    CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
    CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
    CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
    CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
    CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
    CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
    CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
    CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
}


[StructLayout(LayoutKind.Sequential)]
public struct FLOATING_SAVE_AREA
{
    public uint ControlWord;
    public uint StatusWord;
    public uint TagWord;
    public uint ErrorOffset;
    public uint ErrorSelector;
    public uint DataOffset;
    public uint DataSelector;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
    public byte[] RegisterArea;
    public uint Cr0NpxState;
}

[StructLayout(LayoutKind.Sequential)]
public struct CONTEXT
{
    public uint ContextFlags; //set this to an appropriate value
                              // Retrieved by CONTEXT_DEBUG_REGISTERS
    public uint Dr0;
    public uint Dr1;
    public uint Dr2;
    public uint Dr3;
    public uint Dr6;
    public uint Dr7;
    // Retrieved by CONTEXT_FLOATING_POINT
    public FLOATING_SAVE_AREA FloatSave;
    // Retrieved by CONTEXT_SEGMENTS
    public uint SegGs;
    public uint SegFs;
    public uint SegEs;
    public uint SegDs;
    // Retrieved by CONTEXT_INTEGER
    public uint Edi;
    public uint Esi;
    public uint Ebx;
    public uint Edx;
    public uint Ecx;
    public uint Eax;
    // Retrieved by CONTEXT_CONTROL
    public uint Ebp;
    public uint Eip;
    public uint SegCs;
    public uint EFlags;
    public uint Esp;
    public uint SegSs;
    // Retrieved by CONTEXT_EXTENDED_REGISTERS
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
    public byte[] ExtendedRegisters;
}

// Next x64

[StructLayout(LayoutKind.Sequential)]
public struct M128A
{
    public ulong High;
    public long Low;

    public override string ToString()
    {
        return string.Format("High:{0}, Low:{1}", this.High, this.Low);
    }
}

/// <summary>
/// x64
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 16)]
public struct XSAVE_FORMAT64
{
    public ushort ControlWord;
    public ushort StatusWord;
    public byte TagWord;
    public byte Reserved1;
    public ushort ErrorOpcode;
    public uint ErrorOffset;
    public ushort ErrorSelector;
    public ushort Reserved2;
    public uint DataOffset;
    public ushort DataSelector;
    public ushort Reserved3;
    public uint MxCsr;
    public uint MxCsr_Mask;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public M128A[] FloatRegisters;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public M128A[] XmmRegisters;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
    public byte[] Reserved4;
}

/// <summary>
/// x64
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 16)]
public struct CONTEXT64
{
    public ulong P1Home;
    public ulong P2Home;
    public ulong P3Home;
    public ulong P4Home;
    public ulong P5Home;
    public ulong P6Home;

    public CONTEXT_FLAGS ContextFlags;
    public uint MxCsr;

    public ushort SegCs;
    public ushort SegDs;
    public ushort SegEs;
    public ushort SegFs;
    public ushort SegGs;
    public ushort SegSs;
    public uint EFlags;

    public ulong Dr0;
    public ulong Dr1;
    public ulong Dr2;
    public ulong Dr3;
    public ulong Dr6;
    public ulong Dr7;

    public ulong Rax;
    public ulong Rcx;
    public ulong Rdx;
    public ulong Rbx;
    public ulong Rsp;
    public ulong Rbp;
    public ulong Rsi;
    public ulong Rdi;
    public ulong R8;
    public ulong R9;
    public ulong R10;
    public ulong R11;
    public ulong R12;
    public ulong R13;
    public ulong R14;
    public ulong R15;
    public ulong Rip;

    public XSAVE_FORMAT64 DUMMYUNIONNAME;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
    public M128A[] VectorRegister;
    public ulong VectorControl;

    public ulong DebugControl;
    public ulong LastBranchToRip;
    public ulong LastBranchFromRip;
    public ulong LastExceptionToRip;
    public ulong LastExceptionFromRip;
}
[StructLayout(LayoutKind.Sequential)]
public struct SECURITY_ATTRIBUTES
{
    public int nLength;
    public IntPtr lpSecurityDescriptor;
    public int bInheritHandle;
}
public struct CREATION_FLAGS
{
    public const uint DEBUG_PROCESS = 0x00000001;
    public const uint DEBUG_ONLY_THIS_PROCESS = 0x00000002;
    public const uint CREATE_SUSPENDED = 0x00000004;
    public const uint DETACHED_PROCESS = 0x00000008;
    public const uint CREATE_NEW_CONSOLE = 0x00000010;
    public const uint NORMAL_PRIORITY_CLASS = 0x00000020;
    public const uint IDLE_PRIORITY_CLASS = 0x00000040;
    public const uint HIGH_PRIORITY_CLASS = 0x00000080;
    public const uint REALTIME_PRIORITY_CLASS = 0x00000100;
    public const uint CREATE_NEW_PROCESS_GROUP = 0x00000200;
    public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    public const uint CREATE_SEPARATE_WOW_VDM = 0x00000800;
    public const uint CREATE_SHARED_WOW_VDM = 0x00001000;
    public const uint CREATE_FORCEDOS = 0x00002000;
    public const uint BELOW_NORMAL_PRIORITY_CLASS = 0x00004000;
    public const uint ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000;
    public const uint INHERIT_PARENT_AFFINITY = 0x00010000;
    public const uint INHERIT_CALLER_PRIORITY = 0x00020000;
    public const uint CREATE_PROTECTED_PROCESS = 0x00040000;
    public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    public const uint PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000;
    public const uint PROCESS_MODE_BACKGROUND_END = 0x00200000;
    public const uint CREATE_BREAKAWAY_FROM_JOB = 0x01000000;
    public const uint CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000;
    public const uint CREATE_DEFAULT_ERROR_MODE = 0x04000000;
    public const uint CREATE_NO_WINDOW = 0x08000000;
    public const uint PROFILE_USER = 0x10000000;
    public const uint PROFILE_KERNEL = 0x20000000;
    public const uint PROFILE_SERVER = 0x40000000;
    public const uint CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000;
}
