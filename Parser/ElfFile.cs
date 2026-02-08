namespace ELFInspector.Parser;

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfSysvHashTable
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Address { get; set; }
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
	public List<uint> Buckets { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<uint> Chains { get; } = new();
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfGnuHashTable
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Address { get; set; }
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
	public List<ulong> BloomWords { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<uint> Buckets { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<uint> Chains { get; } = new();
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfHashLookupPath
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
public class ElfCompressedSection
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
public class ElfSectionGroup
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
	public List<uint> MemberSectionIndexes { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<string> MemberSectionNames { get; } = new();
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfDebugSectionInfo
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
public class ElfEhFrameInfo
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
	public List<ElfEhFrameCieInfo> CieEntries { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfEhFrameFdeInfo> FdeEntries { get; } = new();
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfEhFrameCieInfo
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
	public List<string> Instructions { get; } = new();
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfEhFrameFdeInfo
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
	public List<string> Instructions { get; } = new();
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfEhFrameHeaderInfo
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
public class ElfUnwindInfo
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ElfEhFrameInfo EhFrame { get; set; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ElfEhFrameHeaderInfo EhFrameHeader { get; set; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfDebugSectionInfo> DebugSections { get; } = new();
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfDwarfCompileUnitInfo
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
public class ElfDwarfLineTableInfo
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
public class ElfDwarfIndexInfo
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
	public List<ElfDwarfCompileUnitInfo> CompileUnits { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfDwarfLineTableInfo> LineTables { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfDwarfSemanticCompilationUnit> SemanticUnits { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfDwarfSymbolMapping> SymbolMappings { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ElfDwarfQueryModel Query { get; } = new();
}

/// <summary>
/// Represents a public API member.
/// </summary>
public enum ElfDwarfAttributeValueKind
{
	/// <summary>
	/// No decoded value.
	/// </summary>
	None = 0,
	/// <summary>
	/// Unsigned integral value.
	/// </summary>
	Unsigned = 1,
	/// <summary>
	/// Signed integral value.
	/// </summary>
	Signed = 2,
	/// <summary>
	/// String value.
	/// </summary>
	String = 3,
	/// <summary>
	/// Address value.
	/// </summary>
	Address = 4,
	/// <summary>
	/// Reference to another DIE or offset.
	/// </summary>
	Reference = 5,
	/// <summary>
	/// Boolean flag value.
	/// </summary>
	Flag = 6,
	/// <summary>
	/// Raw byte sequence.
	/// </summary>
	Bytes = 7
}

/// <summary>
/// Represents a public API member.
/// </summary>
public enum ElfDwarfDecodeStatus
{
	/// <summary>
	/// The value was decoded exactly.
	/// </summary>
	Exact = 0,
	/// <summary>
	/// The value was decoded partially.
	/// </summary>
	Partial = 1,
	/// <summary>
	/// Unknown value preserved without semantic decoding.
	/// </summary>
	PreservedUnknown = 2,
	/// <summary>
	/// Decoding failed.
	/// </summary>
	DecodeError = 3
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfDwarfAttributeValue
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
	public ElfDwarfAttributeValueKind Kind { get; set; }
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
	public byte[] BytesValue { get; set; }
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
	public ElfDwarfDecodeStatus DecodeStatus { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string DecodeNote { get; set; }
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfDwarfDie
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
	public List<ElfDwarfAttributeValue> Attributes { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfDwarfDie> Children { get; } = new();
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfDwarfSemanticCompilationUnit
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
	public List<ElfDwarfDie> RootDies { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfDwarfPreservedRegion> PreservedRegions { get; } = new();
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfDwarfPreservedRegion
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
public class ElfDwarfSymbolMapping
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
public class ElfDwarfAddressRange
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
public class ElfDwarfFunctionParameterQuery
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
	public ElfDwarfTypeReferenceQuery Type { get; set; } = new();
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfDwarfTypeReferenceQuery
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
	public List<ulong> TraversedDieOffsets { get; } = new();
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfDwarfTypeQuery
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
public class ElfDwarfFunctionQuery
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
	public ElfDwarfTypeReferenceQuery ReturnType { get; set; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsDeclaration { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfDwarfAddressRange> AddressRanges { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfDwarfFunctionParameterQuery> Parameters { get; } = new();
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfDwarfVariableQuery
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
	public ElfDwarfTypeReferenceQuery Type { get; set; } = new();
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
	public List<ElfDwarfAddressRange> AddressRanges { get; } = new();
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfDwarfQueryLink
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
public class ElfDwarfQueryModel
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfDwarfTypeQuery> Types { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfDwarfFunctionQuery> Functions { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfDwarfVariableQuery> Variables { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfDwarfQueryLink> Links { get; } = new();
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfCoreThreadInfo
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
	public List<ulong> RegisterPreview { get; } = new();
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfCoreUnwindFrameInfo
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
public class ElfCoreThreadUnwindInfo
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
	public List<ElfCoreUnwindFrameInfo> Frames { get; } = new();
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfCoreDumpInfo
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
	public List<int> Signals { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfCoreThreadInfo> Threads { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfCoreThreadUnwindInfo> UnwindThreads { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ElfCoreUnwindMetrics UnwindMetrics { get; } = new();
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfCoreUnwindMetrics
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
public class ElfFile
{
	internal ElfParseOptions ParseOptions { get; set; } = ElfParseOptions.StrictDefault;

	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ElfHeader Header { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string InterpreterPath { get; set; }
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
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfSectionHeader> Sections { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfProgramHeader> ProgramHeaders { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfSymbol> Symbols { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfSymbol> ImportedSymbols { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfSymbol> ExportedSymbols { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfRelocation> Relocations { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfDynamicEntry> DynamicEntries { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfNote> Notes { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfCompressedSection> CompressedSections { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfSectionGroup> SectionGroups { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ElfSysvHashTable SysvHashTable { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ElfGnuHashTable GnuHashTable { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<ElfHashLookupPath> HashLookupPaths { get; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ElfUnwindInfo Unwind { get; set; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ElfDwarfIndexInfo Dwarf { get; set; } = new();
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ElfCoreDumpInfo CoreDump { get; set; } = new();

	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public List<string> ImportLibraries { get; } = new();
}
