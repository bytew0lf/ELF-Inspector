namespace ELFInspector.Parser;

public enum ElfHeaderValidationMode
{
	Strict = 0,
	Compat = 1
}

public enum ElfDataSourceMode
{
	Auto = 0,
	MemoryMapped = 1,
	Stream = 2,
	InMemory = 3
}

public sealed class ElfParseOptions
{
	private static readonly TimeSpan DefaultZstdToolTimeout = TimeSpan.FromSeconds(15);
	private const int DefaultHashLookupPathSymbolLimit = 4_096;
	private const int DefaultHashLookupPathChainVisitLimit = 8_192;

	public static ElfParseOptions StrictDefault { get; } = new();

	public ElfHeaderValidationMode HeaderValidationMode { get; init; } = ElfHeaderValidationMode.Strict;
	public bool EnableExternalZstdToolFallback { get; init; } = true;
	public TimeSpan ExternalZstdToolTimeout { get; init; } = DefaultZstdToolTimeout;
	public string ExternalZstdToolPath { get; init; } = string.Empty;
	public ElfDataSourceMode DataSourceMode { get; init; } = ElfDataSourceMode.Auto;
	public int? HashLookupPathSymbolLimit { get; init; } = DefaultHashLookupPathSymbolLimit;
	public int HashLookupPathChainVisitLimit { get; init; } = DefaultHashLookupPathChainVisitLimit;
}
