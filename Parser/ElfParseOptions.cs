namespace ELFInspector.Parser;

/// <summary>
/// Represents a public API member.
/// </summary>
public enum ElfHeaderValidationMode
{
	/// <summary>
	/// Enforces strict ELF header conformance.
	/// </summary>
	Strict = 0,
	/// <summary>
	/// Allows compatibility parsing for non-conforming legacy headers.
	/// </summary>
	Compat = 1
}

/// <summary>
/// Represents a public API member.
/// </summary>
public enum ElfDataSourceMode
{
	/// <summary>
	/// Chooses the source mode automatically.
	/// </summary>
	Auto = 0,
	/// <summary>
	/// Uses a memory-mapped source.
	/// </summary>
	MemoryMapped = 1,
	/// <summary>
	/// Uses a stream-backed source.
	/// </summary>
	Stream = 2,
	/// <summary>
	/// Uses an in-memory source.
	/// </summary>
	InMemory = 3
}

/// <summary>
/// Represents a public API member.
/// </summary>
public sealed class ElfParseOptions
{
	private static readonly TimeSpan DefaultZstdToolTimeout = TimeSpan.FromSeconds(15);
	private const int DefaultHashLookupPathSymbolLimit = 4_096;
	private const int DefaultHashLookupPathChainVisitLimit = 8_192;
	private const ulong DefaultMaxInputBytes = 4UL * 1024UL * 1024UL * 1024UL;
	private const ulong DefaultMaxParserEntryCount = 1_000_000UL;
	private const int DefaultMaxNoteCount = 100_000;
	private const ulong DefaultMaxStringTableStringBytes = 64UL * 1024UL;

	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public static ElfParseOptions StrictDefault { get; } = new();

	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ElfHeaderValidationMode HeaderValidationMode { get; init; } = ElfHeaderValidationMode.Strict;
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool EnableExternalZstdToolFallback { get; init; } = false;
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public TimeSpan ExternalZstdToolTimeout { get; init; } = DefaultZstdToolTimeout;
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string ExternalZstdToolPath { get; init; } = string.Empty;
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ElfDataSourceMode DataSourceMode { get; init; } = ElfDataSourceMode.Auto;
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int? HashLookupPathSymbolLimit { get; init; } = DefaultHashLookupPathSymbolLimit;
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public int HashLookupPathChainVisitLimit { get; init; } = DefaultHashLookupPathChainVisitLimit;
	/// <summary>
	/// Maximum input size in bytes accepted by the parser. Set to 0 to disable this limit.
	/// </summary>
	public ulong MaxInputBytes { get; init; } = DefaultMaxInputBytes;
	/// <summary>
	/// Maximum parser entry count for bounded table-style structures. Set to 0 to disable this limit.
	/// </summary>
	public ulong MaxParserEntryCount { get; init; } = DefaultMaxParserEntryCount;
	/// <summary>
	/// Maximum number of distinct NOTE entries retained during NOTE parsing. Set to 0 to disable this limit.
	/// </summary>
	public int MaxNoteCount { get; init; } = DefaultMaxNoteCount;
	/// <summary>
	/// Maximum number of bytes read for a single string table entry before truncation. Set to 0 to disable this limit.
	/// </summary>
	public ulong MaxStringTableStringBytes { get; init; } = DefaultMaxStringTableStringBytes;
}
