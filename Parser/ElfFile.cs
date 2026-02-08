namespace ELFInspector.Parser;

public class ElfSysvHashTable
{
	public ulong Address { get; set; }
	public uint BucketCount { get; set; }
	public uint ChainCount { get; set; }
	public List<uint> Buckets { get; } = new();
	public List<uint> Chains { get; } = new();
}

public class ElfGnuHashTable
{
	public ulong Address { get; set; }
	public uint BucketCount { get; set; }
	public uint SymbolOffset { get; set; }
	public uint BloomWordCount { get; set; }
	public uint BloomShift { get; set; }
	public uint BloomWordBits { get; set; }
	public List<ulong> BloomWords { get; } = new();
	public List<uint> Buckets { get; } = new();
	public List<uint> Chains { get; } = new();
}

public class ElfHashLookupPath
{
	public string Algorithm { get; set; }
	public string SymbolName { get; set; }
	public uint Hash { get; set; }
	public uint BucketIndex { get; set; }
	public uint BucketValue { get; set; }
	public bool BloomMayMatch { get; set; }
	public uint ChainStartSymbolIndex { get; set; }
	public uint ChainVisitedCount { get; set; }
	public bool MatchFound { get; set; }
	public uint MatchedSymbolIndex { get; set; }
}

public class ElfCompressedSection
{
	public string Name { get; set; }
	public uint CompressionType { get; set; }
	public string CompressionTypeName { get; set; }
	public ulong CompressedSize { get; set; }
	public ulong UncompressedSize { get; set; }
	public ulong Alignment { get; set; }
	public bool IsGnuStyleZdebug { get; set; }
	public bool DecompressionSucceeded { get; set; }
	public string Error { get; set; }
}

public class ElfSectionGroup
{
	public string Name { get; set; }
	public uint Flags { get; set; }
	public bool IsComdat { get; set; }
	public uint SignatureSymbolIndex { get; set; }
	public string SignatureSymbolName { get; set; }
	public List<uint> MemberSectionIndexes { get; } = new();
	public List<string> MemberSectionNames { get; } = new();
}

public class ElfDebugSectionInfo
{
	public string Name { get; set; }
	public ulong Size { get; set; }
	public bool IsCompressed { get; set; }
	public ulong UncompressedSize { get; set; }
}

public class ElfEhFrameInfo
{
	public bool Present { get; set; }
	public ulong Address { get; set; }
	public ulong Size { get; set; }
	public uint CieCount { get; set; }
	public uint FdeCount { get; set; }
	public bool TerminatorSeen { get; set; }
	public List<ElfEhFrameCieInfo> CieEntries { get; } = new();
	public List<ElfEhFrameFdeInfo> FdeEntries { get; } = new();
}

public class ElfEhFrameCieInfo
{
	public int Index { get; set; }
	public ulong Offset { get; set; }
	public ulong ContentLength { get; set; }
	public bool IsDwarf64 { get; set; }
	public uint CieId { get; set; }
	public byte Version { get; set; }
	public string Augmentation { get; set; }
	public ulong CodeAlignmentFactor { get; set; }
	public long DataAlignmentFactor { get; set; }
	public ulong ReturnAddressRegister { get; set; }
	public byte FdePointerEncoding { get; set; }
	public List<string> Instructions { get; } = new();
}

public class ElfEhFrameFdeInfo
{
	public int Index { get; set; }
	public ulong Offset { get; set; }
	public ulong ContentLength { get; set; }
	public bool IsDwarf64 { get; set; }
	public ulong CiePointer { get; set; }
	public int? CieIndex { get; set; }
	public ulong InitialLocation { get; set; }
	public ulong AddressRange { get; set; }
	public ulong EndLocation { get; set; }
	public bool CfaRuleAvailable { get; set; }
	public ulong CfaRegister { get; set; }
	public long CfaOffset { get; set; }
	public bool ReturnAddressOffsetAvailable { get; set; }
	public long ReturnAddressOffset { get; set; }
	public List<string> Instructions { get; } = new();
}

public class ElfEhFrameHeaderInfo
{
	public bool Present { get; set; }
	public byte Version { get; set; }
	public byte EhFramePointerEncoding { get; set; }
	public byte FdeCountEncoding { get; set; }
	public byte TableEncoding { get; set; }
	public bool EhFramePointerDecoded { get; set; }
	public ulong EhFramePointer { get; set; }
	public bool FdeCountDecoded { get; set; }
	public ulong FdeCount { get; set; }
	public uint ParsedTableEntries { get; set; }
}

public class ElfUnwindInfo
{
	public ElfEhFrameInfo EhFrame { get; set; } = new();
	public ElfEhFrameHeaderInfo EhFrameHeader { get; set; } = new();
	public List<ElfDebugSectionInfo> DebugSections { get; } = new();
}

public class ElfDwarfCompileUnitInfo
{
	public ulong Offset { get; set; }
	public ulong UnitLength { get; set; }
	public bool IsDwarf64 { get; set; }
	public ushort Version { get; set; }
	public byte? UnitType { get; set; }
	public ulong AbbrevOffset { get; set; }
	public byte AddressSize { get; set; }
}

public class ElfDwarfLineTableInfo
{
	public ulong Offset { get; set; }
	public ulong UnitLength { get; set; }
	public bool IsDwarf64 { get; set; }
	public ushort Version { get; set; }
	public byte AddressSize { get; set; }
	public byte SegmentSelectorSize { get; set; }
	public ulong HeaderLength { get; set; }
	public byte MinimumInstructionLength { get; set; }
	public byte MaximumOperationsPerInstruction { get; set; }
	public bool DefaultIsStmt { get; set; }
	public sbyte LineBase { get; set; }
	public byte LineRange { get; set; }
	public byte OpcodeBase { get; set; }
	public ulong IncludeDirectoryCount { get; set; }
	public ulong FileNameEntryCount { get; set; }
}

public class ElfDwarfIndexInfo
{
	public bool HasDebugInfo { get; set; }
	public bool HasDebugAbbrev { get; set; }
	public bool HasDebugLine { get; set; }
	public bool HasDebugStr { get; set; }
	public bool HasDebugRanges { get; set; }
	public bool HasDebugAddr { get; set; }
	public bool HasDebugStrOffsets { get; set; }
	public bool HasDebugRngLists { get; set; }
	public bool HasDebugLocLists { get; set; }
	public List<ElfDwarfCompileUnitInfo> CompileUnits { get; } = new();
	public List<ElfDwarfLineTableInfo> LineTables { get; } = new();
	public List<ElfDwarfSemanticCompilationUnit> SemanticUnits { get; } = new();
	public List<ElfDwarfSymbolMapping> SymbolMappings { get; } = new();
}

public enum ElfDwarfAttributeValueKind
{
	None = 0,
	Unsigned = 1,
	Signed = 2,
	String = 3,
	Address = 4,
	Reference = 5,
	Flag = 6,
	Bytes = 7
}

public enum ElfDwarfDecodeStatus
{
	Exact = 0,
	Partial = 1,
	PreservedUnknown = 2,
	DecodeError = 3
}

public class ElfDwarfAttributeValue
{
	public ulong Name { get; set; }
	public string NameText { get; set; }
	public ulong Form { get; set; }
	public string FormText { get; set; }
	public ElfDwarfAttributeValueKind Kind { get; set; }
	public ulong UnsignedValue { get; set; }
	public long SignedValue { get; set; }
	public bool BoolValue { get; set; }
	public string StringValue { get; set; }
	public byte[] BytesValue { get; set; }
	public ulong UnitRelativeValueOffset { get; set; }
	public ulong ConsumedByteCount { get; set; }
	public ElfDwarfDecodeStatus DecodeStatus { get; set; }
	public string DecodeNote { get; set; }
}

public class ElfDwarfDie
{
	public ulong Offset { get; set; }
	public ulong AbbrevCode { get; set; }
	public ulong Tag { get; set; }
	public string TagText { get; set; }
	public bool HasChildren { get; set; }
	public List<ElfDwarfAttributeValue> Attributes { get; } = new();
	public List<ElfDwarfDie> Children { get; } = new();
}

public class ElfDwarfSemanticCompilationUnit
{
	public ulong Offset { get; set; }
	public ulong UnitLength { get; set; }
	public bool IsDwarf64 { get; set; }
	public ushort Version { get; set; }
	public byte? UnitType { get; set; }
	public ulong AbbrevOffset { get; set; }
	public byte AddressSize { get; set; }
	public List<ElfDwarfDie> RootDies { get; } = new();
	public List<ElfDwarfPreservedRegion> PreservedRegions { get; } = new();
}

public class ElfDwarfPreservedRegion
{
	public ulong UnitRelativeOffset { get; set; }
	public ulong UnitRelativeLength { get; set; }
	public string Reason { get; set; }
	public string PreviewHex { get; set; }
}

public class ElfDwarfSymbolMapping
{
	public string SymbolName { get; set; }
	public ulong SymbolAddress { get; set; }
	public ulong DieOffset { get; set; }
	public string DieTagText { get; set; }
	public string MatchType { get; set; }
}

public class ElfCoreThreadInfo
{
	public int Index { get; set; }
	public int? ThreadId { get; set; }
	public int? ParentProcessId { get; set; }
	public int? ProcessGroupId { get; set; }
	public int? SessionId { get; set; }
	public int? Signal { get; set; }
	public int? CurrentSignal { get; set; }
	public List<ulong> RegisterPreview { get; } = new();
}

public class ElfCoreUnwindFrameInfo
{
	public int Index { get; set; }
	public ulong InstructionPointer { get; set; }
	public ulong StackPointer { get; set; }
	public ulong? FramePointer { get; set; }
	public string SymbolName { get; set; }
	public string Strategy { get; set; }
}

public class ElfCoreThreadUnwindInfo
{
	public int ThreadIndex { get; set; }
	public int? ThreadId { get; set; }
	public string Strategy { get; set; }
	public bool Complete { get; set; }
	public List<ElfCoreUnwindFrameInfo> Frames { get; } = new();
}

public class ElfCoreDumpInfo
{
	public bool IsCoreDump { get; set; }
	public string ProcessName { get; set; }
	public int? ProcessId { get; set; }
	public int? Signal { get; set; }
	public int AuxVectorEntryCount { get; set; }
	public int FileMappingCount { get; set; }
	public List<int> Signals { get; } = new();
	public List<ElfCoreThreadInfo> Threads { get; } = new();
	public List<ElfCoreThreadUnwindInfo> UnwindThreads { get; } = new();
}

public class ElfFile
{
	internal ElfParseOptions ParseOptions { get; set; } = ElfParseOptions.StrictDefault;

	public ElfHeader Header { get; set; }
	public string InterpreterPath { get; set; }
	public string Soname { get; set; }
	public string RPath { get; set; }
	public string RunPath { get; set; }
	public List<ElfSectionHeader> Sections { get; } = new();
	public List<ElfProgramHeader> ProgramHeaders { get; } = new();
	public List<ElfSymbol> Symbols { get; } = new();
	public List<ElfSymbol> ImportedSymbols { get; } = new();
	public List<ElfSymbol> ExportedSymbols { get; } = new();
	public List<ElfRelocation> Relocations { get; } = new();
	public List<ElfDynamicEntry> DynamicEntries { get; } = new();
	public List<ElfNote> Notes { get; } = new();
	public List<ElfCompressedSection> CompressedSections { get; } = new();
	public List<ElfSectionGroup> SectionGroups { get; } = new();
	public ElfSysvHashTable SysvHashTable { get; set; }
	public ElfGnuHashTable GnuHashTable { get; set; }
	public List<ElfHashLookupPath> HashLookupPaths { get; } = new();
	public ElfUnwindInfo Unwind { get; set; } = new();
	public ElfDwarfIndexInfo Dwarf { get; set; } = new();
	public ElfCoreDumpInfo CoreDump { get; set; } = new();

	public List<string> ImportLibraries { get; } = new();
}
