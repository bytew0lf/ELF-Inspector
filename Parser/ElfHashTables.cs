namespace ELFInspector.Parser;

public static partial class ElfReader
{
	private const uint ShtHash = 5;
	private const uint ShtGnuHash = 0x6FFFFFF6;

	public static void ParseHashTables(ReadOnlySpan<byte> data, ElfFile elf)
	{
		elf.SysvHashTable = null;
		elf.GnuHashTable = null;
		elf.HashLookupPaths.Clear();

		ParseSysvHashTable(data, elf);
		ParseGnuHashTable(data, elf);
		BuildHashLookupPaths(elf);
	}

	private static void ParseSysvHashTable(ReadOnlySpan<byte> data, ElfFile elf)
	{
		if (!TryGetDynamicValue(elf, DtHash, out var hashAddress))
			return;
		if (!TryGetMappedFileRange(elf, hashAddress, out var tableOffset, out var mappedRangeSize))
			return;

		if (TryGetSectionRangeBound(elf, hashAddress, ShtHash, out var sectionRange))
			mappedRangeSize = Math.Min(mappedRangeSize, sectionRange);
		if (mappedRangeSize < 8)
			return;

		EnsureReadableRange(data, tableOffset, 8, "DT_HASH");
		var reader = new EndianBinaryReader(data, elf.Header.IsLittleEndian)
		{
			Position = ToInt32(tableOffset)
		};

		var bucketCount = reader.ReadUInt32();
		var chainCount = reader.ReadUInt32();

		var table = new ElfSysvHashTable
		{
			Address = hashAddress,
			BucketCount = bucketCount,
			ChainCount = chainCount
		};

		var availableEntryCount = mappedRangeSize > 8 ? (mappedRangeSize - 8) / 4UL : 0UL;
		var bucketEntriesToRead = Math.Min((ulong)bucketCount, availableEntryCount);
		var chainEntriesToRead = Math.Min((ulong)chainCount, availableEntryCount - bucketEntriesToRead);

		for (ulong i = 0; i < bucketEntriesToRead; i++)
		{
			reader.Position = ToInt32(checked(tableOffset + 8UL + (i * 4UL)));
			table.Buckets.Add(reader.ReadUInt32());
		}

		for (ulong i = 0; i < chainEntriesToRead; i++)
		{
			reader.Position = ToInt32(checked(tableOffset + 8UL + (bucketEntriesToRead * 4UL) + (i * 4UL)));
			table.Chains.Add(reader.ReadUInt32());
		}

		elf.SysvHashTable = table;
	}

	private static void ParseGnuHashTable(ReadOnlySpan<byte> data, ElfFile elf)
	{
		if (!TryGetDynamicValue(elf, DtGnuHash, out var hashAddress))
			return;
		if (!TryGetMappedFileRange(elf, hashAddress, out var tableOffset, out var mappedRangeSize))
			return;

		if (TryGetSectionRangeBound(elf, hashAddress, ShtGnuHash, out var sectionRange))
			mappedRangeSize = Math.Min(mappedRangeSize, sectionRange);
		if (mappedRangeSize < 16)
			return;

		EnsureReadableRange(data, tableOffset, 16, "DT_GNU_HASH");
		var reader = new EndianBinaryReader(data, elf.Header.IsLittleEndian)
		{
			Position = ToInt32(tableOffset)
		};

		var bucketCount = reader.ReadUInt32();
		var symbolOffset = reader.ReadUInt32();
		var bloomWordCount = reader.ReadUInt32();
		var bloomShift = reader.ReadUInt32();

		var bloomWordSize = elf.Header.Class == ElfClass.Elf32 ? 4UL : 8UL;
		var bloomWordBits = elf.Header.Class == ElfClass.Elf32 ? 32U : 64U;

		var table = new ElfGnuHashTable
		{
			Address = hashAddress,
			BucketCount = bucketCount,
			SymbolOffset = symbolOffset,
			BloomWordCount = bloomWordCount,
			BloomShift = bloomShift,
			BloomWordBits = bloomWordBits
		};

		var headerSize = 16UL;
		var maxBloomWordsByRange = mappedRangeSize > headerSize ? (mappedRangeSize - headerSize) / bloomWordSize : 0UL;
		var bloomWordsToRead = Math.Min((ulong)bloomWordCount, maxBloomWordsByRange);

		for (ulong i = 0; i < bloomWordsToRead; i++)
		{
			reader.Position = ToInt32(checked(tableOffset + headerSize + (i * bloomWordSize)));
			table.BloomWords.Add(elf.Header.Class == ElfClass.Elf32 ? reader.ReadUInt32() : reader.ReadUInt64());
		}

		var bucketStart = checked(tableOffset + headerSize + (bloomWordsToRead * bloomWordSize));
		var consumedAfterHeader = checked(headerSize + (bloomWordsToRead * bloomWordSize));
		var maxBucketsByRange = mappedRangeSize > consumedAfterHeader ? (mappedRangeSize - consumedAfterHeader) / 4UL : 0UL;
		var bucketsToRead = Math.Min((ulong)bucketCount, maxBucketsByRange);

		for (ulong i = 0; i < bucketsToRead; i++)
		{
			reader.Position = ToInt32(checked(bucketStart + (i * 4UL)));
			table.Buckets.Add(reader.ReadUInt32());
		}

		var chainStart = checked(bucketStart + (bucketsToRead * 4UL));
		var consumedAfterBuckets = checked(consumedAfterHeader + (bucketsToRead * 4UL));
		var maxChainsByRange = mappedRangeSize > consumedAfterBuckets ? (mappedRangeSize - consumedAfterBuckets) / 4UL : 0UL;
		var inferredChainCount = DetermineGnuHashChainCount(data, elf, chainStart, maxChainsByRange, symbolOffset, table.Buckets);

		for (ulong i = 0; i < inferredChainCount; i++)
		{
			reader.Position = ToInt32(checked(chainStart + (i * 4UL)));
			table.Chains.Add(reader.ReadUInt32());
		}

		elf.GnuHashTable = table;
	}

	private static bool TryGetSectionRangeBound(ElfFile elf, ulong virtualAddress, uint sectionType, out ulong remainingSize)
	{
		remainingSize = 0;

		foreach (var section in elf.Sections)
		{
			if (section.Type != sectionType || section.Size == 0)
				continue;

			var start = section.Address;
			var end = start + section.Size;
			if (end < start)
				end = ulong.MaxValue;

			if (virtualAddress < start || virtualAddress >= end)
				continue;

			remainingSize = end - virtualAddress;
			return true;
		}

		return false;
	}

	private static ulong DetermineGnuHashChainCount(ReadOnlySpan<byte> data, ElfFile elf, ulong chainStart, ulong maxChainsByRange, uint symbolOffset, IReadOnlyList<uint> buckets)
	{
		if (maxChainsByRange == 0 || buckets.Count == 0)
			return 0;

		var maxBucketValue = buckets.Max();
		if (maxBucketValue < symbolOffset)
			return 0;

		if (TryInferGnuHashChainCountFromTerminator(data, elf, chainStart, maxChainsByRange, symbolOffset, maxBucketValue, out var chainCountByTerminator))
			return chainCountByTerminator;

		var chainCountBySymbolCount = InferGnuHashChainCountFromDynamicSymbols(elf, symbolOffset);
		if (chainCountBySymbolCount > 0)
			return Math.Min(chainCountBySymbolCount, maxChainsByRange);

		return maxChainsByRange;
	}

	private static bool TryInferGnuHashChainCountFromTerminator(
		ReadOnlySpan<byte> data,
		ElfFile elf,
		ulong chainStart,
		ulong maxChainsByRange,
		uint symbolOffset,
		uint maxBucketValue,
		out ulong chainCount)
	{
		chainCount = 0;
		if (maxBucketValue < symbolOffset)
			return true;

		var startIndex = (ulong)(maxBucketValue - symbolOffset);
		if (startIndex >= maxChainsByRange)
			return false;

		var reader = new EndianBinaryReader(data, elf.Header.IsLittleEndian);
		for (var chainIndex = startIndex; chainIndex < maxChainsByRange && chainIndex < MaxParserEntryCount; chainIndex++)
		{
			var chainOffset = checked(chainStart + (chainIndex * 4UL));
			EnsureReadableRange(data, chainOffset, 4, "DT_GNU_HASH chain");

			reader.Position = ToInt32(chainOffset);
			var chainValue = reader.ReadUInt32();

			if ((chainValue & 1U) == 0)
				continue;

			chainCount = chainIndex + 1UL;
			return true;
		}

		return false;
	}

	private static ulong InferGnuHashChainCountFromDynamicSymbols(ElfFile elf, uint symbolOffset)
	{
		var dynamicSymbolCount = GetDynamicSymbolCountFromSymbols(elf);
		if (dynamicSymbolCount == 0)
			return 0;
		if (dynamicSymbolCount <= symbolOffset)
			return 0;

		return dynamicSymbolCount - symbolOffset;
	}

	private static uint GetDynamicSymbolCountFromSymbols(ElfFile elf)
	{
		var dynamicSymbols = elf.Symbols.Where(symbol => symbol.IsDynamic).ToList();
		if (dynamicSymbols.Count == 0)
			return 0;

		return checked(dynamicSymbols.Max(symbol => symbol.Index) + 1U);
	}

	private static int GetHashLookupPathSymbolLimit(ElfFile elf)
	{
		var configuredLimit = elf.ParseOptions?.HashLookupPathSymbolLimit;
		if (!configuredLimit.HasValue)
			return int.MaxValue;
		if (configuredLimit.Value <= 0)
			return 0;
		return configuredLimit.Value;
	}

	private static uint GetHashLookupPathChainVisitLimit(ElfFile elf)
	{
		var configuredLimit = elf.ParseOptions?.HashLookupPathChainVisitLimit ?? 0;
		if (configuredLimit <= 0)
			return 1;
		return (uint)configuredLimit;
	}

	private static void BuildHashLookupPaths(ElfFile elf)
	{
		if (elf.SysvHashTable == null && elf.GnuHashTable == null)
			return;

		var symbolNames = new SortedSet<string>(StringComparer.Ordinal);

		foreach (var symbol in elf.ImportedSymbols)
		{
			if (!string.IsNullOrEmpty(symbol.Name))
				symbolNames.Add(symbol.Name);
		}

		foreach (var symbol in elf.ExportedSymbols)
		{
			if (!string.IsNullOrEmpty(symbol.Name))
				symbolNames.Add(symbol.Name);
		}

		foreach (var symbol in elf.Symbols.Where(symbol => symbol.IsDynamic))
		{
			if (!string.IsNullOrEmpty(symbol.Name))
				symbolNames.Add(symbol.Name);
		}

		if (symbolNames.Count == 0)
			return;

		var dynamicSymbolsByIndex = elf.Symbols
			.Where(symbol => symbol.IsDynamic && !string.IsNullOrEmpty(symbol.Name))
			.GroupBy(symbol => symbol.Index)
			.ToDictionary(group => group.Key, group => group.First().Name);

		var symbolLimit = GetHashLookupPathSymbolLimit(elf);
		if (symbolLimit == 0)
			return;

		var chainVisitLimit = GetHashLookupPathChainVisitLimit(elf);
		var symbolsToEvaluate = symbolLimit == int.MaxValue
			? symbolNames.ToList()
			: symbolNames.Take(symbolLimit).ToList();

		foreach (var symbolName in symbolsToEvaluate)
		{
			if (elf.SysvHashTable != null)
				elf.HashLookupPaths.Add(BuildSysvLookupPath(elf.SysvHashTable, symbolName, dynamicSymbolsByIndex, chainVisitLimit));
			if (elf.GnuHashTable != null)
				elf.HashLookupPaths.Add(BuildGnuLookupPath(elf.GnuHashTable, symbolName, dynamicSymbolsByIndex, chainVisitLimit));
		}
	}

	private static ElfHashLookupPath BuildSysvLookupPath(
		ElfSysvHashTable table,
		string symbolName,
		Dictionary<uint, string> dynamicSymbolsByIndex,
		uint chainVisitLimit)
	{
		var path = new ElfHashLookupPath
		{
			Algorithm = "SYSV",
			SymbolName = symbolName,
			Hash = ComputeSysvHash(symbolName),
			BloomMayMatch = true
		};

		if (table.BucketCount == 0)
			return path;

		path.BucketIndex = path.Hash % table.BucketCount;
		if (path.BucketIndex >= table.Buckets.Count)
			return path;

		path.BucketValue = table.Buckets[(int)path.BucketIndex];
		path.ChainStartSymbolIndex = path.BucketValue;

		if (path.BucketValue == 0)
			return path;

		if (TryMatchSymbolByIndex(path.BucketValue, symbolName, dynamicSymbolsByIndex))
		{
			path.MatchFound = true;
			path.MatchedSymbolIndex = path.BucketValue;
			path.ChainVisitedCount = 1;
			return path;
		}

		if (path.BucketValue >= table.Chains.Count)
			return path;

		var visited = new HashSet<uint>();
		var current = path.BucketValue;

		while (current != 0 && current < table.Chains.Count && path.ChainVisitedCount < chainVisitLimit)
		{
			if (!visited.Add(current))
				break;

			path.ChainVisitedCount++;
			current = table.Chains[(int)current];
			if (current == 0)
				break;

			if (TryMatchSymbolByIndex(current, symbolName, dynamicSymbolsByIndex))
			{
				path.MatchFound = true;
				path.MatchedSymbolIndex = current;
				break;
			}
		}

		return path;
	}

	private static ElfHashLookupPath BuildGnuLookupPath(
		ElfGnuHashTable table,
		string symbolName,
		Dictionary<uint, string> dynamicSymbolsByIndex,
		uint chainVisitLimit)
	{
		var path = new ElfHashLookupPath
		{
			Algorithm = "GNU",
			SymbolName = symbolName,
			Hash = ComputeGnuHash(symbolName),
			BloomMayMatch = true
		};

		if (table.BucketCount == 0)
			return path;

		path.BucketIndex = path.Hash % table.BucketCount;
		if (path.BucketIndex >= table.Buckets.Count)
			return path;

		path.BucketValue = table.Buckets[(int)path.BucketIndex];
		path.ChainStartSymbolIndex = path.BucketValue;
		path.BloomMayMatch = EvaluateGnuBloom(path.Hash, table);

		if (path.BucketValue < table.SymbolOffset)
			return path;

		var chainIndex = (ulong)(path.BucketValue - table.SymbolOffset);
		while (chainIndex < (ulong)table.Chains.Count && path.ChainVisitedCount < chainVisitLimit)
		{
			var chainValue = table.Chains[(int)chainIndex];
			var symbolIndex = checked(table.SymbolOffset + (uint)chainIndex);
			path.ChainVisitedCount++;

			var hashMatches = (chainValue | 1U) == (path.Hash | 1U);
			if (hashMatches && TryMatchSymbolByIndex(symbolIndex, symbolName, dynamicSymbolsByIndex))
			{
				path.MatchFound = true;
				path.MatchedSymbolIndex = symbolIndex;
				break;
			}

			if ((chainValue & 1U) != 0)
				break;

			chainIndex++;
		}

		return path;
	}

	private static bool EvaluateGnuBloom(uint hash, ElfGnuHashTable table)
	{
		if (table.BloomWords.Count == 0)
			return true;
		if (table.BloomWords.Count != table.BloomWordCount)
			return true;
		if (table.BloomWordBits is not (32 or 64))
			return true;

		var wordBits = table.BloomWordBits;
		var wordIndex = (hash / wordBits) % (uint)table.BloomWords.Count;
		var word = table.BloomWords[(int)wordIndex];

		var bit1 = (int)(hash % wordBits);
		var bit2 = (int)((hash >> (int)Math.Min(table.BloomShift, 31U)) % wordBits);

		return (((word >> bit1) & 1UL) != 0) && (((word >> bit2) & 1UL) != 0);
	}

	private static bool TryMatchSymbolByIndex(uint symbolIndex, string symbolName, Dictionary<uint, string> dynamicSymbolsByIndex)
	{
		return dynamicSymbolsByIndex.TryGetValue(symbolIndex, out var candidateName)
			&& string.Equals(candidateName, symbolName, StringComparison.Ordinal);
	}

	private static uint ComputeSysvHash(string symbolName)
	{
		uint hash = 0;
		foreach (var value in Encoding.UTF8.GetBytes(symbolName))
		{
			hash = (hash << 4) + value;
			var high = hash & 0xF0000000U;
			if (high != 0)
				hash ^= high >> 24;
			hash &= ~high;
		}

		return hash;
	}

	private static uint ComputeGnuHash(string symbolName)
	{
		uint hash = 5381;
		foreach (var value in Encoding.UTF8.GetBytes(symbolName))
			hash = (hash * 33U) + value;

		return hash;
	}
}
