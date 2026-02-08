namespace ELFInspector.Reporting;

public class HeaderReport
{
	public string Class { get; set; }
	public string Endianness { get; set; }
	public ushort Type { get; set; }
	public string TypeName { get; set; }
	public ushort MachineCode { get; set; }
	public string Machine { get; set; }
	public byte OsAbiCode { get; set; }
	public string OsAbi { get; set; }
	public byte AbiVersion { get; set; }
	public uint Flags { get; set; }
	public ulong EntryPoint { get; set; }
	public string Interpreter { get; set; }
	public string Soname { get; set; }
	public string RPath { get; set; }
	public string RunPath { get; set; }
}

public class SectionReport
{
	public string Name { get; set; }
	public uint Type { get; set; }
	public string TypeName { get; set; }
	public ulong Flags { get; set; }
	public string FlagsText { get; set; }
	public ulong Address { get; set; }
	public ulong Offset { get; set; }
	public ulong Size { get; set; }
}

public class SegmentReport
{
	public uint Type { get; set; }
	public string TypeName { get; set; }
	public uint Flags { get; set; }
	public string FlagsText { get; set; }
	public ulong Offset { get; set; }
	public ulong VirtualAddress { get; set; }
	public ulong PhysicalAddress { get; set; }
	public ulong FileSize { get; set; }
	public ulong MemorySize { get; set; }
	public ulong Align { get; set; }
}

public class SymbolReport
{
	public string Name { get; set; }
	public string QualifiedName { get; set; }
	public ulong Address { get; set; }
	public ulong Size { get; set; }
	public string Binding { get; set; }
	public string Type { get; set; }
	public uint SectionIndexRaw { get; set; }
	public uint SectionIndex { get; set; }
	public byte Visibility { get; set; }
	public bool IsDynamic { get; set; }
	public bool IsImport { get; set; }
	public bool IsExport { get; set; }
	public string Library { get; set; }
	public string Version { get; set; }
}

public class RelocationReport
{
	public ulong Offset { get; set; }
	public ulong Info { get; set; }
	public string Encoding { get; set; }
	public long Addend { get; set; }
	public bool HasAddend { get; set; }
	public ulong SymbolIndex { get; set; }
	public uint Type { get; set; }
	public string TypeName { get; set; }
	public string SymbolName { get; set; }
	public string SymbolVersion { get; set; }
	public string SymbolLibrary { get; set; }
	public string SourceSection { get; set; }
	public string AppliesToSection { get; set; }
	public string LoaderPath { get; set; }
	public bool IsPltPath { get; set; }
	public bool IsGotPath { get; set; }
	public bool IsTlsPath { get; set; }
}

public class DynamicReport
{
	public long Tag { get; set; }
	public string TagName { get; set; }
	public ulong Value { get; set; }
	public string StringValue { get; set; }
	public string DecodedValue { get; set; }
}

public class NoteReport
{
	public string Name { get; set; }
	public uint Type { get; set; }
	public string TypeName { get; set; }
	public string DescriptionHex { get; set; }
	public string DecodedDescription { get; set; }
}

public class ImportLibraryReport
{
	public string Name { get; set; }
	public List<string> Symbols { get; set; }
}

public class SysvHashReport
{
	public bool Present { get; set; }
	public uint BucketCount { get; set; }
	public uint ChainCount { get; set; }
	public List<uint> Buckets { get; set; }
	public List<uint> Chains { get; set; }
}

public class GnuHashReport
{
	public bool Present { get; set; }
	public uint BucketCount { get; set; }
	public uint SymbolOffset { get; set; }
	public uint BloomWordCount { get; set; }
	public uint BloomShift { get; set; }
	public uint BloomWordBits { get; set; }
	public List<ulong> BloomWords { get; set; }
	public List<uint> Buckets { get; set; }
	public List<uint> Chains { get; set; }
}

public class HashLookupPathReport
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

public class HashTablesReport
{
	public SysvHashReport Sysv { get; set; }
	public GnuHashReport Gnu { get; set; }
	public List<HashLookupPathReport> LookupPaths { get; set; }
}

public class CompressedSectionReport
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

public class SectionGroupReport
{
	public string Name { get; set; }
	public uint Flags { get; set; }
	public bool IsComdat { get; set; }
	public uint SignatureSymbolIndex { get; set; }
	public string SignatureSymbolName { get; set; }
	public List<uint> MemberSectionIndexes { get; set; }
	public List<string> MemberSectionNames { get; set; }
}

public class SectionSpecialCasesReport
{
	public List<CompressedSectionReport> CompressedSections { get; set; }
	public List<SectionGroupReport> SectionGroups { get; set; }
}

public class EhFrameReport
{
	public bool Present { get; set; }
	public ulong Address { get; set; }
	public ulong Size { get; set; }
	public uint CieCount { get; set; }
	public uint FdeCount { get; set; }
	public bool TerminatorSeen { get; set; }
	public List<EhFrameCieReport> CieEntries { get; set; }
	public List<EhFrameFdeReport> FdeEntries { get; set; }
}

public class EhFrameCieReport
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
	public List<string> Instructions { get; set; }
}

public class EhFrameFdeReport
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
	public List<string> Instructions { get; set; }
}

public class EhFrameHeaderReport
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

public class DebugSectionReport
{
	public string Name { get; set; }
	public ulong Size { get; set; }
	public bool IsCompressed { get; set; }
	public ulong UncompressedSize { get; set; }
}

public class UnwindReport
{
	public EhFrameReport EhFrame { get; set; }
	public EhFrameHeaderReport EhFrameHeader { get; set; }
	public List<DebugSectionReport> DebugSections { get; set; }
}

public class DwarfCompileUnitReport
{
	public ulong Offset { get; set; }
	public ulong UnitLength { get; set; }
	public bool IsDwarf64 { get; set; }
	public ushort Version { get; set; }
	public byte? UnitType { get; set; }
	public ulong AbbrevOffset { get; set; }
	public byte AddressSize { get; set; }
}

public class DwarfLineTableReport
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

public class DwarfReport
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
	public List<DwarfCompileUnitReport> CompileUnits { get; set; }
	public List<DwarfLineTableReport> LineTables { get; set; }
	public List<DwarfSemanticUnitReport> SemanticUnits { get; set; }
	public List<DwarfSymbolMappingReport> SymbolMappings { get; set; }
	public DwarfQueryReport Query { get; set; }
}

public class DwarfAddressRangeReport
{
	public ulong Start { get; set; }
	public ulong End { get; set; }
}

public class DwarfFunctionParameterQueryReport
{
	public string Name { get; set; }
	public ulong? TypeDieOffset { get; set; }
}

public class DwarfTypeQueryReport
{
	public ulong DieOffset { get; set; }
	public string Name { get; set; }
	public string TagText { get; set; }
	public ulong? TypeDieOffset { get; set; }
	public ulong? ByteSize { get; set; }
	public ulong? Encoding { get; set; }
	public string EncodingText { get; set; }
	public bool IsDeclaration { get; set; }
}

public class DwarfFunctionQueryReport
{
	public ulong DieOffset { get; set; }
	public string Name { get; set; }
	public string LinkageName { get; set; }
	public ulong? ReturnTypeDieOffset { get; set; }
	public bool IsDeclaration { get; set; }
	public List<DwarfAddressRangeReport> AddressRanges { get; set; }
	public List<DwarfFunctionParameterQueryReport> Parameters { get; set; }
}

public class DwarfVariableQueryReport
{
	public ulong DieOffset { get; set; }
	public string Name { get; set; }
	public ulong? TypeDieOffset { get; set; }
	public bool IsExternal { get; set; }
	public bool IsDeclaration { get; set; }
	public List<DwarfAddressRangeReport> AddressRanges { get; set; }
}

public class DwarfQueryReport
{
	public List<DwarfTypeQueryReport> Types { get; set; }
	public List<DwarfFunctionQueryReport> Functions { get; set; }
	public List<DwarfVariableQueryReport> Variables { get; set; }
}

public class DwarfAttributeReport
{
	public ulong Name { get; set; }
	public string NameText { get; set; }
	public ulong Form { get; set; }
	public string FormText { get; set; }
	public string Kind { get; set; }
	public ulong UnsignedValue { get; set; }
	public long SignedValue { get; set; }
	public bool BoolValue { get; set; }
	public string StringValue { get; set; }
	public string BytesHex { get; set; }
	public ulong UnitRelativeValueOffset { get; set; }
	public ulong ConsumedByteCount { get; set; }
	public string DecodeStatus { get; set; }
	public string DecodeNote { get; set; }
}

public class DwarfDieReport
{
	public ulong Offset { get; set; }
	public ulong AbbrevCode { get; set; }
	public ulong Tag { get; set; }
	public string TagText { get; set; }
	public bool HasChildren { get; set; }
	public List<DwarfAttributeReport> Attributes { get; set; }
	public List<DwarfDieReport> Children { get; set; }
}

public class DwarfSemanticUnitReport
{
	public ulong Offset { get; set; }
	public ulong UnitLength { get; set; }
	public bool IsDwarf64 { get; set; }
	public ushort Version { get; set; }
	public byte? UnitType { get; set; }
	public ulong AbbrevOffset { get; set; }
	public byte AddressSize { get; set; }
	public List<DwarfDieReport> RootDies { get; set; }
	public List<DwarfPreservedRegionReport> PreservedRegions { get; set; }
}

public class DwarfPreservedRegionReport
{
	public ulong UnitRelativeOffset { get; set; }
	public ulong UnitRelativeLength { get; set; }
	public string Reason { get; set; }
	public string PreviewHex { get; set; }
}

public class DwarfSymbolMappingReport
{
	public string SymbolName { get; set; }
	public ulong SymbolAddress { get; set; }
	public ulong DieOffset { get; set; }
	public string DieTagText { get; set; }
	public string MatchType { get; set; }
}

public class CoreThreadReport
{
	public int Index { get; set; }
	public int? ThreadId { get; set; }
	public int? ParentProcessId { get; set; }
	public int? ProcessGroupId { get; set; }
	public int? SessionId { get; set; }
	public int? Signal { get; set; }
	public int? CurrentSignal { get; set; }
	public List<ulong> RegisterPreview { get; set; }
}

public class CoreDumpReport
{
	public bool IsCoreDump { get; set; }
	public string ProcessName { get; set; }
	public int? ProcessId { get; set; }
	public int? Signal { get; set; }
	public int AuxVectorEntryCount { get; set; }
	public int FileMappingCount { get; set; }
	public List<int> Signals { get; set; }
	public List<CoreThreadReport> Threads { get; set; }
	public List<CoreThreadUnwindReport> UnwindThreads { get; set; }
}

public class CoreUnwindFrameReport
{
	public int Index { get; set; }
	public ulong InstructionPointer { get; set; }
	public ulong StackPointer { get; set; }
	public ulong? FramePointer { get; set; }
	public string SymbolName { get; set; }
	public string Strategy { get; set; }
}

public class CoreThreadUnwindReport
{
	public int ThreadIndex { get; set; }
	public int? ThreadId { get; set; }
	public string Strategy { get; set; }
	public bool Complete { get; set; }
	public List<CoreUnwindFrameReport> Frames { get; set; }
}

public class SecurityFeaturesReport
{
	public string Pie { get; set; }
	public string Relro { get; set; }
	public string Nx { get; set; }
	public bool BindNow { get; set; }
	public bool CanaryHints { get; set; }
	public List<string> CanaryIndicators { get; set; }
	public bool FortifyHints { get; set; }
	public List<string> FortifyIndicators { get; set; }
}

public class ElfReport
{
	public HeaderReport Header { get; set; }
	public HashTablesReport HashTables { get; set; }
	public SectionSpecialCasesReport SectionSpecialCases { get; set; }
	public UnwindReport Unwind { get; set; }
	public DwarfReport Dwarf { get; set; }
	public CoreDumpReport CoreDump { get; set; }
	public SecurityFeaturesReport Security { get; set; }
	public List<SectionReport> Sections { get; set; }
	public List<SegmentReport> Segments { get; set; }
	public List<SymbolReport> Symbols { get; set; }
	public List<SymbolReport> ImportedSymbols { get; set; }
	public List<SymbolReport> ExportedSymbols { get; set; }
	public List<RelocationReport> Relocations { get; set; }
	public List<DynamicReport> Dynamics { get; set; }
	public List<NoteReport> Notes { get; set; }
	public List<string> Imports { get; set; }
	public List<ImportLibraryReport> ImportLibrariesDetailed { get; set; }
}
