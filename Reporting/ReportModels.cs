namespace ELFInspector.Reporting;

/// <summary>
/// Represents a public API member.
/// </summary>
public class HeaderReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Class { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Endianness { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ushort Type { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string TypeName { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ushort MachineCode { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Machine { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte OsAbiCode { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string OsAbi { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte AbiVersion { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint Flags { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong EntryPoint { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Interpreter { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Soname { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string RPath { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string RunPath { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class SectionReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Name { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint Type { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string TypeName { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Flags { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string FlagsText { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Address { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Offset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Size { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class SegmentReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint Type { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string TypeName { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint Flags { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string FlagsText { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Offset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong VirtualAddress { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong PhysicalAddress { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong FileSize { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong MemorySize { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Align { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class SymbolReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Name { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string QualifiedName { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Address { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Size { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Binding { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Type { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint SectionIndexRaw { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint SectionIndex { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte Visibility { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsDynamic { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsImport { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsExport { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Library { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Version { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class RelocationReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Offset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Info { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Encoding { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public long Addend { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool HasAddend { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong SymbolIndex { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint Type { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string TypeName { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string SymbolName { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string SymbolVersion { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string SymbolLibrary { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string SourceSection { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string AppliesToSection { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string LoaderPath { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsPltPath { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsGotPath { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsTlsPath { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class DynamicReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public long Tag { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string TagName { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Value { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string StringValue { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string DecodedValue { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class NoteReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Name { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint Type { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string TypeName { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string DescriptionHex { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string DecodedDescription { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ImportLibraryReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Name { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<string> Symbols { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class SysvHashReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool Present { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint BucketCount { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint ChainCount { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<uint> Buckets { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<uint> Chains { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class GnuHashReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool Present { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint BucketCount { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint SymbolOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint BloomWordCount { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint BloomShift { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint BloomWordBits { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ulong> BloomWords { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<uint> Buckets { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<uint> Chains { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class HashLookupPathReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Algorithm { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string SymbolName { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint Hash { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint BucketIndex { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint BucketValue { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool BloomMayMatch { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint ChainStartSymbolIndex { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint ChainVisitedCount { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool MatchFound { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint MatchedSymbolIndex { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class HashTablesReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public SysvHashReport Sysv { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public GnuHashReport Gnu { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<HashLookupPathReport> LookupPaths { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class CompressedSectionReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Name { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint CompressionType { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string CompressionTypeName { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong CompressedSize { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong UncompressedSize { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Alignment { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsGnuStyleZdebug { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool DecompressionSucceeded { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Error { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class SectionGroupReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Name { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint Flags { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsComdat { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint SignatureSymbolIndex { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string SignatureSymbolName { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<uint> MemberSectionIndexes { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<string> MemberSectionNames { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class SectionSpecialCasesReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<CompressedSectionReport> CompressedSections { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<SectionGroupReport> SectionGroups { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class EhFrameReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool Present { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Address { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Size { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint CieCount { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint FdeCount { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool TerminatorSeen { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<EhFrameCieReport> CieEntries { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<EhFrameFdeReport> FdeEntries { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class EhFrameCieReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int Index { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Offset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong ContentLength { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsDwarf64 { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint CieId { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte Version { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Augmentation { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong CodeAlignmentFactor { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public long DataAlignmentFactor { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong ReturnAddressRegister { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte FdePointerEncoding { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<string> Instructions { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class EhFrameFdeReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int Index { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Offset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong ContentLength { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsDwarf64 { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong CiePointer { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int? CieIndex { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong InitialLocation { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong AddressRange { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong EndLocation { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool CfaRuleAvailable { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong CfaRegister { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public long CfaOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool ReturnAddressOffsetAvailable { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public long ReturnAddressOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<string> Instructions { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class EhFrameHeaderReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool Present { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte Version { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte EhFramePointerEncoding { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte FdeCountEncoding { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte TableEncoding { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool EhFramePointerDecoded { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong EhFramePointer { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool FdeCountDecoded { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong FdeCount { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint ParsedTableEntries { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class DebugSectionReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Name { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Size { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsCompressed { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong UncompressedSize { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class UnwindReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public EhFrameReport EhFrame { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public EhFrameHeaderReport EhFrameHeader { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<DebugSectionReport> DebugSections { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class DwarfCompileUnitReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Offset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong UnitLength { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsDwarf64 { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ushort Version { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte? UnitType { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong AbbrevOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte AddressSize { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class DwarfLineTableReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Offset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong UnitLength { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsDwarf64 { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ushort Version { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte AddressSize { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte SegmentSelectorSize { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong HeaderLength { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte MinimumInstructionLength { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte MaximumOperationsPerInstruction { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool DefaultIsStmt { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public sbyte LineBase { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte LineRange { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte OpcodeBase { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong IncludeDirectoryCount { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong FileNameEntryCount { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class DwarfReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool HasDebugInfo { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool HasDebugAbbrev { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool HasDebugLine { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool HasDebugStr { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool HasDebugRanges { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool HasDebugAddr { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool HasDebugStrOffsets { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool HasDebugRngLists { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool HasDebugLocLists { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<DwarfCompileUnitReport> CompileUnits { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<DwarfLineTableReport> LineTables { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<DwarfSemanticUnitReport> SemanticUnits { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<DwarfSymbolMappingReport> SymbolMappings { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public DwarfQueryReport Query { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class DwarfAddressRangeReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Start { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong End { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class DwarfFunctionParameterQueryReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Name { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong? TypeDieOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public DwarfTypeReferenceQueryReport Type { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class DwarfTypeReferenceQueryReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong? DirectDieOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong? CanonicalDieOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string DisplayName { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsResolved { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ulong> TraversedDieOffsets { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class DwarfTypeQueryReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong DieOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Name { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string TagText { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong? TypeDieOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong? ByteSize { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong? Encoding { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string EncodingText { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsDeclaration { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class DwarfFunctionQueryReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong DieOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Name { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string LinkageName { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong? ReturnTypeDieOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public DwarfTypeReferenceQueryReport ReturnType { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsDeclaration { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<DwarfAddressRangeReport> AddressRanges { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<DwarfFunctionParameterQueryReport> Parameters { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class DwarfVariableQueryReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong DieOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Name { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong? TypeDieOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public DwarfTypeReferenceQueryReport Type { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsExternal { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsDeclaration { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<DwarfAddressRangeReport> AddressRanges { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class DwarfQueryLinkReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong SourceDieOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Relation { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Label { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong? TargetDieOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsResolved { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong? RangeStart { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong? RangeEnd { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class DwarfQueryReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<DwarfTypeQueryReport> Types { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<DwarfFunctionQueryReport> Functions { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<DwarfVariableQueryReport> Variables { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<DwarfQueryLinkReport> Links { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class DwarfAttributeReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Name { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string NameText { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Form { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string FormText { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Kind { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong UnsignedValue { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public long SignedValue { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool BoolValue { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string StringValue { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string BytesHex { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong UnitRelativeValueOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong ConsumedByteCount { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string DecodeStatus { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string DecodeNote { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class DwarfDieReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Offset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong AbbrevCode { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Tag { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string TagText { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool HasChildren { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<DwarfAttributeReport> Attributes { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<DwarfDieReport> Children { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class DwarfSemanticUnitReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Offset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong UnitLength { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsDwarf64 { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ushort Version { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte? UnitType { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong AbbrevOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte AddressSize { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<DwarfDieReport> RootDies { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<DwarfPreservedRegionReport> PreservedRegions { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class DwarfPreservedRegionReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong UnitRelativeOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong UnitRelativeLength { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Reason { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string PreviewHex { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class DwarfSymbolMappingReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string SymbolName { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong SymbolAddress { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong DieOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string DieTagText { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string MatchType { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class CoreThreadReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int Index { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int? ThreadId { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int? ParentProcessId { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int? ProcessGroupId { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int? SessionId { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int? Signal { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int? CurrentSignal { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ulong> RegisterPreview { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class CoreDumpReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsCoreDump { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string ProcessName { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int? ProcessId { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int? Signal { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int AuxVectorEntryCount { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int FileMappingCount { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<int> Signals { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<CoreThreadReport> Threads { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<CoreThreadUnwindReport> UnwindThreads { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public CoreUnwindMetricsReport UnwindMetrics { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class CoreUnwindMetricsReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int ThreadCount { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int CfiThreads { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int FramePointerThreads { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int LinkRegisterThreads { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int StackScanThreads { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int NoUnwindThreads { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public double CfiRatio { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public double StackScanRatio { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool CfiDominatesStackScan { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class CoreUnwindFrameReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int Index { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong InstructionPointer { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong StackPointer { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong? FramePointer { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string SymbolName { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Strategy { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class CoreThreadUnwindReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int ThreadIndex { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int? ThreadId { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Strategy { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool Complete { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<CoreUnwindFrameReport> Frames { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class SecurityFeaturesReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Pie { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Relro { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Nx { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool BindNow { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool CanaryHints { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<string> CanaryIndicators { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool FortifyHints { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<string> FortifyIndicators { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfReport
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public HeaderReport Header { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public HashTablesReport HashTables { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public SectionSpecialCasesReport SectionSpecialCases { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public UnwindReport Unwind { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public DwarfReport Dwarf { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public CoreDumpReport CoreDump { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public SecurityFeaturesReport Security { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<SectionReport> Sections { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<SegmentReport> Segments { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<SymbolReport> Symbols { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<SymbolReport> ImportedSymbols { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<SymbolReport> ExportedSymbols { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<RelocationReport> Relocations { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<DynamicReport> Dynamics { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<NoteReport> Notes { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<string> Imports { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ImportLibraryReport> ImportLibrariesDetailed { get; set; }
}
