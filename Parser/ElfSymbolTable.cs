namespace ELFInspector.Parser;

public enum ElfSymbolBinding
{
	Local = 0,
	Global = 1,
	Weak = 2,
	GnuUnique = 10,
}

public enum ElfSymbolType
{
	Notype = 0,
	Object = 1,
	Function = 2,
	Section = 3,
	File = 4,
	Common = 5,
	Tls = 6,
	GnuIfunc = 10,
}

public class ElfSymbol
{
	private const uint ShnUndef = 0;

	public string Name { get; set; }
	public ulong Value { get; set; }
	public ulong Size { get; set; }
	public ElfSymbolBinding Binding { get; set; }
	public ElfSymbolType Type { get; set; }
	public uint SectionIndexRaw { get; set; }
	public uint SectionIndex { get; set; }
	public byte Visibility { get; set; }
	public bool IsDynamic { get; set; }
	public uint TableSectionIndex { get; set; }
	public uint Index { get; set; }
	public ushort VersionIndex { get; set; }
	public bool IsVersionHidden { get; set; }
	public string VersionName { get; set; }
	public string LibraryName { get; set; }

	public bool IsImport =>
		IsDynamic &&
		SectionIndex == ShnUndef &&
		!string.IsNullOrEmpty(Name);

	public bool IsExport =>
		(Binding is ElfSymbolBinding.Global or ElfSymbolBinding.Weak or ElfSymbolBinding.GnuUnique) &&
		SectionIndex != ShnUndef &&
		!string.IsNullOrEmpty(Name) &&
		Type is not (ElfSymbolType.Section or ElfSymbolType.File);

	public string QualifiedName
	{
		get
		{
			if (string.IsNullOrEmpty(Name))
				return string.Empty;
			if (string.IsNullOrEmpty(VersionName))
				return Name;

			if (IsImport)
				return $"{Name}@{VersionName}";

			var separator = IsVersionHidden ? "@" : "@@";
			return $"{Name}{separator}{VersionName}";
		}
	}
}

public static partial class ElfReader
{
	private const ushort SymbolVersionLocal = 0;
	private const ushort SymbolVersionGlobal = 1;
	private const uint ShnUndef = 0;

	public static void ParseSymbolTables(IEndianDataSource data, ElfFile elf)
	{
		elf.Symbols.Clear();
		elf.ImportedSymbols.Clear();
		elf.ExportedSymbols.Clear();

		var extendedSectionIndicesBySymtab = ParseSymbolSectionIndices(data, elf);

		for (var sectionIndex = 0; sectionIndex < elf.Sections.Count; sectionIndex++)
		{
			var section = elf.Sections[sectionIndex];
			if (section.Type is not (ShtSymTab or ShtDynSym))
				continue;

			extendedSectionIndicesBySymtab.TryGetValue((uint)sectionIndex, out var extendedIndices);
			ParseSymbolTable(data, elf, section, (uint)sectionIndex, extendedIndices);
		}

		if (elf.Symbols.Count == 0)
			ParseDynamicSymbolTableFallback(data, elf);

		ResolveDynamicSymbolVersions(data, elf);
		ClassifySymbols(elf);
		AssignFallbackImportLibraries(elf);
	}

	public static void ParseSymbolTables(ReadOnlySpan<byte> data, ElfFile elf)
	{
		using var source = ElfDataSourceFactory.CreateInMemory(data);
		ParseSymbolTables(source, elf);
	}

	private static Dictionary<uint, uint[]> ParseSymbolSectionIndices(IEndianDataSource data, ElfFile elf)
	{
		var result = new Dictionary<uint, uint[]>();

		foreach (var section in elf.Sections)
		{
			if (section.Type != ShtSymTabShndx)
				continue;
			if (section.Size == 0)
				continue;
			if (section.Link >= elf.Sections.Count)
				continue;

			var entrySize = section.EntrySize == 0 ? 4UL : section.EntrySize;
			if (entrySize < 4)
				throw new InvalidDataException("Invalid SHT_SYMTAB_SHNDX entry size.");

			EnsureReadableRange(data, section.Offset, section.Size, "SHT_SYMTAB_SHNDX");
			var entryCount = section.Size / entrySize;
			EnsureReasonableEntryCount(entryCount, "SHT_SYMTAB_SHNDX");

			var values = new uint[GetManagedArrayLength(entryCount, "SHT_SYMTAB_SHNDX")];
			var reader = new EndianDataReader(data, elf.Header.IsLittleEndian);
			for (ulong i = 0; i < entryCount; i++)
			{
				reader.Position = checked(section.Offset + (i * entrySize));
				values[i] = reader.ReadUInt32();
			}

			if (!result.ContainsKey(section.Link))
				result[section.Link] = values;
		}

		return result;
	}

	private static void ParseSymbolTable(IEndianDataSource data, ElfFile elf, ElfSectionHeader tableSection, uint tableSectionIndex, uint[] extendedSectionIndices)
	{
		if (tableSection.Size == 0)
			return;

		var entrySize = tableSection.EntrySize;
		if (entrySize == 0)
			entrySize = elf.Header.Class == ElfClass.Elf32 ? 16UL : 24UL;

		var minEntrySize = elf.Header.Class == ElfClass.Elf32 ? 16UL : 24UL;
		if (entrySize < minEntrySize)
			throw new InvalidDataException("Invalid symbol table entry size.");

		EnsureReadableRange(data, tableSection.Offset, tableSection.Size, "symbol table");
		var entryCount = tableSection.Size / entrySize;
		EnsureReasonableEntryCount(entryCount, "symbol table");

		var reader = new EndianDataReader(data, elf.Header.IsLittleEndian);

		for (ulong i = 0; i < entryCount; i++)
		{
			var entryOffset = checked(tableSection.Offset + (i * entrySize));
			reader.Position = entryOffset;

			uint nameIndex;
			ulong value;
			ulong size;
			byte info;
			byte other;
			ushort sectionIndexRaw;

				if (elf.Header.Class == ElfClass.Elf32)
				{
					nameIndex = reader.ReadUInt32();
					value = reader.ReadUInt32();
					size = reader.ReadUInt32();
					info = reader.ReadByte();
					other = reader.ReadByte();
					sectionIndexRaw = reader.ReadUInt16();
				}
				else
				{
					nameIndex = reader.ReadUInt32();
					info = reader.ReadByte();
					other = reader.ReadByte();
					sectionIndexRaw = reader.ReadUInt16();
					value = reader.ReadUInt64();
					size = reader.ReadUInt64();
				}

			var resolvedSectionIndex = ResolveSectionIndex(sectionIndexRaw, extendedSectionIndices, i);
			var bind = (ElfSymbolBinding)(info >> 4);
			var type = (ElfSymbolType)(info & 0xF);
			var symbolName = ReadString(data, elf, tableSection.Link, nameIndex);

			elf.Symbols.Add(new ElfSymbol
			{
				Name = symbolName,
				Value = value,
				Size = size,
				Binding = bind,
				Type = type,
				SectionIndexRaw = sectionIndexRaw,
				SectionIndex = resolvedSectionIndex,
				Visibility = (byte)(other & 0x3),
				IsDynamic = tableSection.Type == ShtDynSym,
				TableSectionIndex = tableSectionIndex,
				Index = (uint)i,
				VersionIndex = SymbolVersionGlobal,
				VersionName = string.Empty,
				LibraryName = string.Empty,
			});
		}
	}

	private static void ParseDynamicSymbolTableFallback(IEndianDataSource data, ElfFile elf)
	{
		if (!TryGetDynamicValue(elf, DtSymTab, out var symTabVirtualAddress))
			return;
		if (!TryGetDynamicValue(elf, DtStrTab, out var strTabVirtualAddress))
			return;
		if (!TryVirtualAddressToFileOffset(elf, symTabVirtualAddress, out var symTabFileOffset))
			return;
		if (!TryVirtualAddressToFileOffset(elf, strTabVirtualAddress, out var strTabFileOffset))
			return;

		var entrySize = TryGetDynamicValue(elf, DtSymEnt, out var configuredEntrySize)
			? configuredEntrySize
			: (elf.Header.Class == ElfClass.Elf32 ? 16UL : 24UL);
		var minEntrySize = elf.Header.Class == ElfClass.Elf32 ? 16UL : 24UL;
		if (entrySize < minEntrySize)
			return;

		var stringTableSize = TryGetDynamicValue(elf, DtStrSz, out var configuredStringTableSize)
			? configuredStringTableSize
			: 0UL;
		if (stringTableSize == 0 && TryGetMappedFileRange(elf, strTabVirtualAddress, out _, out var mappedStringRange))
			stringTableSize = mappedStringRange;
		if (stringTableSize == 0)
			return;

		if (!TryDetermineDynamicSymbolCount(data, elf, symTabVirtualAddress, strTabVirtualAddress, entrySize, out var symbolCount))
			return;
		if (symbolCount == 0)
			return;

		EnsureReasonableEntryCount(symbolCount, "dynamic symbol table");
		var totalSymbolBytes = checked(symbolCount * entrySize);
		EnsureReadableRange(data, symTabFileOffset, totalSymbolBytes, "dynamic symbol table");
		EnsureReadableRange(data, strTabFileOffset, stringTableSize, "dynamic string table");

		var reader = new EndianDataReader(data, elf.Header.IsLittleEndian);
		const uint syntheticTableIndex = uint.MaxValue;

		for (ulong i = 0; i < symbolCount; i++)
		{
			reader.Position = checked(symTabFileOffset + (i * entrySize));

			uint nameIndex;
			ulong value;
			ulong size;
			byte info;
			byte other;
			ushort sectionIndexRaw;

			if (elf.Header.Class == ElfClass.Elf32)
			{
				nameIndex = reader.ReadUInt32();
				value = reader.ReadUInt32();
				size = reader.ReadUInt32();
				info = reader.ReadByte();
				other = reader.ReadByte();
				sectionIndexRaw = reader.ReadUInt16();
			}
			else
			{
				nameIndex = reader.ReadUInt32();
				info = reader.ReadByte();
				other = reader.ReadByte();
				sectionIndexRaw = reader.ReadUInt16();
				value = reader.ReadUInt64();
				size = reader.ReadUInt64();
			}

			var symbolName = ReadStringFromFileOffset(data, strTabFileOffset, stringTableSize, nameIndex);
			elf.Symbols.Add(new ElfSymbol
			{
				Name = symbolName,
				Value = value,
				Size = size,
				Binding = (ElfSymbolBinding)(info >> 4),
				Type = (ElfSymbolType)(info & 0xF),
				SectionIndexRaw = sectionIndexRaw,
				SectionIndex = sectionIndexRaw,
				Visibility = (byte)(other & 0x3),
				IsDynamic = true,
				TableSectionIndex = syntheticTableIndex,
				Index = (uint)i,
				VersionIndex = SymbolVersionGlobal,
				VersionName = string.Empty,
				LibraryName = string.Empty
			});
		}
	}

	private static bool TryDetermineDynamicSymbolCount(IEndianDataSource data, ElfFile elf, ulong symTabVirtualAddress, ulong strTabVirtualAddress, ulong entrySize, out ulong count)
	{
		if (TryGetDynamicSymbolCountFromSysvHash(data, elf, out count))
			return true;

		if (strTabVirtualAddress > symTabVirtualAddress)
		{
			var bytes = strTabVirtualAddress - symTabVirtualAddress;
			count = bytes / entrySize;
			if (count > 0)
				return true;
		}

		if (TryGetMappedFileRange(elf, symTabVirtualAddress, out _, out var mappedRangeBytes))
		{
			count = mappedRangeBytes / entrySize;
			if (count > 0)
				return true;
		}

		if (TryGetDynamicSymbolCountFromGnuHash(data, elf, out count))
			return true;

		count = 0;
		return false;
	}

	private static bool TryGetDynamicSymbolCountFromSysvHash(IEndianDataSource data, ElfFile elf, out ulong count)
	{
		count = 0;
		if (!TryGetDynamicValue(elf, DtHash, out var hashVirtualAddress))
			return false;
		if (!TryMapVirtualRangeToFile(elf, hashVirtualAddress, 8, out var hashFileOffset))
			return false;

		EnsureReadableRange(data, hashFileOffset, 8, "DT_HASH");
		var reader = new EndianDataReader(data, elf.Header.IsLittleEndian)
		{
			Position = hashFileOffset
		};

		reader.ReadUInt32(); // nbucket
		count = reader.ReadUInt32(); // nchain == #dynsym entries
		return count > 0;
	}

	private static bool TryGetDynamicSymbolCountFromGnuHash(IEndianDataSource data, ElfFile elf, out ulong count)
	{
		count = 0;
		if (!TryGetDynamicValue(elf, DtGnuHash, out var gnuHashVirtualAddress))
			return false;
		if (!TryGetMappedFileRange(elf, gnuHashVirtualAddress, out var gnuHashFileOffset, out var gnuHashRangeSize))
			return false;
		if (gnuHashRangeSize < 16)
			return false;

		EnsureReadableRange(data, gnuHashFileOffset, 16, "DT_GNU_HASH");
		var reader = new EndianDataReader(data, elf.Header.IsLittleEndian)
		{
			Position = gnuHashFileOffset
		};

		var bucketCount = reader.ReadUInt32();
		var symbolOffset = reader.ReadUInt32();
		var bloomCount = reader.ReadUInt32();
		reader.ReadUInt32(); // bloom_shift

		if (bucketCount == 0)
			return false;

		var bloomWordSize = elf.Header.Class == ElfClass.Elf32 ? 4UL : 8UL;
		var bloomBytes = checked((ulong)bloomCount * bloomWordSize);
		var bucketBytes = checked((ulong)bucketCount * 4UL);
		var bucketOffset = checked(gnuHashFileOffset + 16UL + bloomBytes);
		var chainOffset = checked(bucketOffset + bucketBytes);
		var gnuHashEnd = checked(gnuHashFileOffset + gnuHashRangeSize);

		if (chainOffset < gnuHashFileOffset || chainOffset > gnuHashEnd)
			return false;

		EnsureReadableRange(data, bucketOffset, bucketBytes, "DT_GNU_HASH buckets");

		var maxBucket = 0UL;
		for (ulong i = 0; i < bucketCount; i++)
		{
			reader.Position = checked(bucketOffset + (i * 4UL));
			var bucketValue = reader.ReadUInt32();
			if (bucketValue > maxBucket)
				maxBucket = bucketValue;
		}

		var symbolOffsetUlong = (ulong)symbolOffset;
		if (maxBucket < symbolOffsetUlong)
			return false;

		var chainIndex = maxBucket - symbolOffsetUlong;
		var chainCursor = checked(chainOffset + (chainIndex * 4UL));
		var symbolIndex = maxBucket;

		for (ulong i = 0; i < MaxParserEntryCount; i++)
		{
			if (chainCursor + 4UL > gnuHashEnd)
				return false;

			reader.Position = chainCursor;
			var chainValue = reader.ReadUInt32();

			if ((chainValue & 1U) != 0)
			{
				count = checked(symbolIndex + 1UL);
				return count > 0;
			}

			symbolIndex++;
			chainCursor = checked(chainCursor + 4UL);
		}

		return false;
	}

	private static uint ResolveSectionIndex(ushort sectionIndexRaw, uint[] extendedSectionIndices, ulong symbolIndex)
	{
		if (sectionIndexRaw != ShnXIndex)
			return sectionIndexRaw;
		if (extendedSectionIndices == null)
			return ShnUndef;
		if (symbolIndex >= (ulong)extendedSectionIndices.Length)
			return ShnUndef;

		return extendedSectionIndices[symbolIndex];
	}

	private static void ResolveDynamicSymbolVersions(IEndianDataSource data, ElfFile elf)
	{
		var versionIndexMapByDynsym = ParseVersionSymbolTables(data, elf);
		if (versionIndexMapByDynsym.Count == 0)
			return;

		var versionNeeds = ParseVersionNeeds(data, elf);
		var versionDefinitions = ParseVersionDefinitions(data, elf);

		foreach (var symbol in elf.Symbols)
		{
			if (!symbol.IsDynamic)
				continue;
			if (!versionIndexMapByDynsym.TryGetValue(symbol.TableSectionIndex, out var versionIndexes))
				continue;
			if (symbol.Index >= versionIndexes.Length)
				continue;

			var rawIndex = versionIndexes[symbol.Index];
			symbol.IsVersionHidden = (rawIndex & 0x8000) != 0;

			var versionIndex = (ushort)(rawIndex & 0x7FFF);
			symbol.VersionIndex = versionIndex;

			if (versionIndex is SymbolVersionLocal or SymbolVersionGlobal)
				continue;

			if (versionNeeds.TryGetValue(versionIndex, out var needInfo))
			{
				symbol.LibraryName = needInfo.LibraryName;
				symbol.VersionName = needInfo.VersionName;
				continue;
			}

			if (versionDefinitions.TryGetValue(versionIndex, out var definitionName))
				symbol.VersionName = definitionName;
		}
	}

	private static Dictionary<uint, ushort[]> ParseVersionSymbolTables(IEndianDataSource data, ElfFile elf)
	{
		var result = new Dictionary<uint, ushort[]>();

		foreach (var section in elf.Sections)
		{
			if (section.Type != ShtGnuVerSym)
				continue;
			if (section.Size == 0)
				continue;

			var entrySize = section.EntrySize == 0 ? 2UL : section.EntrySize;
			if (entrySize < 2)
				throw new InvalidDataException("Invalid GNU version symbol entry size.");

			EnsureReadableRange(data, section.Offset, section.Size, "GNU version symbols");
			var count = section.Size / entrySize;
			EnsureReasonableEntryCount(count, "GNU version symbols");

			var versions = new ushort[GetManagedArrayLength(count, "GNU version symbols")];
			var reader = new EndianDataReader(data, elf.Header.IsLittleEndian);

			for (ulong i = 0; i < count; i++)
			{
				reader.Position = checked(section.Offset + (i * entrySize));
				versions[i] = reader.ReadUInt16();
			}

			result[section.Link] = versions;
		}

		ParseVersionSymbolTableFromDynamic(data, elf, result);

		return result;
	}

	private static void ParseVersionSymbolTableFromDynamic(IEndianDataSource data, ElfFile elf, Dictionary<uint, ushort[]> result)
	{
		if (!TryGetDynamicValue(elf, DtVerSym, out var versionTableVirtualAddress))
			return;
		if (!TryGetMappedFileRange(elf, versionTableVirtualAddress, out var versionTableFileOffset, out var versionTableRange))
			return;
		if (!TryGetDynamicSymbolGroupForVersionTable(elf, out var tableSectionIndex, out var symbolCount))
			return;
		if (result.ContainsKey(tableSectionIndex))
			return;
		if (versionTableRange < 2)
			return;

		var maxEntriesByRange = versionTableRange / 2;
		var entryCount = Math.Min(symbolCount, maxEntriesByRange);
		if (entryCount == 0)
			return;

		EnsureReasonableEntryCount(entryCount, "DT_VERSYM entries");
		EnsureReadableRange(data, versionTableFileOffset, checked(entryCount * 2UL), "DT_VERSYM");

		var versions = new ushort[GetManagedArrayLength(entryCount, "DT_VERSYM entries")];
		var reader = new EndianDataReader(data, elf.Header.IsLittleEndian);
		for (ulong i = 0; i < entryCount; i++)
		{
			reader.Position = checked(versionTableFileOffset + (i * 2UL));
			versions[i] = reader.ReadUInt16();
		}

		result[tableSectionIndex] = versions;
	}

	private static bool TryGetDynamicSymbolGroupForVersionTable(ElfFile elf, out uint tableSectionIndex, out ulong symbolCount)
	{
		tableSectionIndex = 0;
		symbolCount = 0;

		var symbolGroup = elf.Symbols
			.Where(s => s.IsDynamic)
			.GroupBy(s => s.TableSectionIndex)
			.OrderByDescending(group => group.Max(s => s.Index))
			.ThenByDescending(group => group.Count())
			.FirstOrDefault();

		if (symbolGroup == null)
			return false;

		tableSectionIndex = symbolGroup.Key;
		symbolCount = checked((ulong)symbolGroup.Max(s => s.Index) + 1UL);
		return symbolCount > 0;
	}

	private static Dictionary<ushort, (string LibraryName, string VersionName)> ParseVersionNeeds(IEndianDataSource data, ElfFile elf)
	{
		var result = new Dictionary<ushort, (string LibraryName, string VersionName)>();
		var reader = new EndianDataReader(data, elf.Header.IsLittleEndian);

		foreach (var section in elf.Sections)
		{
			if (section.Type != ShtGnuVerNeed)
				continue;
			if (section.Size == 0)
				continue;

			EnsureReadableRange(data, section.Offset, section.Size, "GNU version needs");
			var sectionEnd = checked(section.Offset + section.Size);
			var entryCursor = section.Offset;

			while (entryCursor + 16 <= sectionEnd)
			{
				reader.Position = entryCursor;
				reader.ReadUInt16(); // vn_version
				var auxCount = reader.ReadUInt16();
				var fileNameOffset = reader.ReadUInt32();
				var auxOffset = reader.ReadUInt32();
				var nextOffset = reader.ReadUInt32();

				var libraryName = ReadString(data, elf, section.Link, fileNameOffset);
				var auxCursor = checked(entryCursor + auxOffset);

				for (var i = 0; i < auxCount && auxCursor + 16 <= sectionEnd; i++)
				{
					reader.Position = auxCursor;
					reader.ReadUInt32(); // vna_hash
					reader.ReadUInt16(); // vna_flags
					var versionIndex = (ushort)(reader.ReadUInt16() & 0x7FFF);
					var versionNameOffset = reader.ReadUInt32();
					var nextAuxOffset = reader.ReadUInt32();

					if (versionIndex is not (SymbolVersionLocal or SymbolVersionGlobal) && !result.ContainsKey(versionIndex))
					{
						var versionName = ReadString(data, elf, section.Link, versionNameOffset);
						result[versionIndex] = (libraryName, versionName);
					}

					if (nextAuxOffset == 0)
						break;
					if (auxCursor + nextAuxOffset <= auxCursor || auxCursor + nextAuxOffset > sectionEnd)
						break;

					auxCursor += nextAuxOffset;
				}

				if (nextOffset == 0)
					break;
				if (entryCursor + nextOffset <= entryCursor || entryCursor + nextOffset > sectionEnd)
					break;

				entryCursor += nextOffset;
			}
		}

		ParseVersionNeedsFromDynamic(data, elf, result);

		return result;
	}

	private static void ParseVersionNeedsFromDynamic(IEndianDataSource data, ElfFile elf, Dictionary<ushort, (string LibraryName, string VersionName)> result)
	{
		if (!TryGetDynamicValue(elf, DtVerNeed, out var versionNeedsVirtualAddress))
			return;
		if (!TryGetMappedFileRange(elf, versionNeedsVirtualAddress, out var versionNeedsFileOffset, out var versionNeedsRange))
			return;
		if (!TryGetDynamicStringTable(elf, out var strTabFileOffset, out var strTabSize))
			return;
		if (versionNeedsRange < 16)
			return;

		EnsureReadableRange(data, strTabFileOffset, strTabSize, "dynamic string table");
		var versionNeedsEnd = checked(versionNeedsFileOffset + versionNeedsRange);
		var maxEntries = TryGetDynamicValue(elf, DtVerNeedNum, out var configuredCount)
			? configuredCount
			: MaxParserEntryCount;
		if (maxEntries == 0)
			return;
		maxEntries = Math.Min(maxEntries, MaxParserEntryCount);

		var reader = new EndianDataReader(data, elf.Header.IsLittleEndian);
		var entryCursor = versionNeedsFileOffset;

		for (ulong entryIndex = 0; entryIndex < maxEntries && entryCursor + 16UL <= versionNeedsEnd; entryIndex++)
		{
			reader.Position = entryCursor;
			reader.ReadUInt16(); // vn_version
			var auxCount = reader.ReadUInt16();
			var fileNameOffset = reader.ReadUInt32();
			var auxOffset = reader.ReadUInt32();
			var nextOffset = reader.ReadUInt32();

			var libraryName = ReadStringFromFileOffset(data, strTabFileOffset, strTabSize, fileNameOffset);
			if (auxOffset != 0 && auxOffset <= versionNeedsEnd - entryCursor)
			{
				var auxCursor = entryCursor + auxOffset;
				for (ulong auxIndex = 0; auxIndex < auxCount && auxCursor + 16UL <= versionNeedsEnd; auxIndex++)
				{
					reader.Position = auxCursor;
					reader.ReadUInt32(); // vna_hash
					reader.ReadUInt16(); // vna_flags
					var versionIndex = (ushort)(reader.ReadUInt16() & 0x7FFF);
					var versionNameOffset = reader.ReadUInt32();
					var nextAuxOffset = reader.ReadUInt32();

					if (versionIndex is not (SymbolVersionLocal or SymbolVersionGlobal) && !result.ContainsKey(versionIndex))
					{
						var versionName = ReadStringFromFileOffset(data, strTabFileOffset, strTabSize, versionNameOffset);
						result[versionIndex] = (libraryName, versionName);
					}

					if (nextAuxOffset == 0)
						break;
					if (nextAuxOffset > versionNeedsEnd - auxCursor)
						break;

					auxCursor += nextAuxOffset;
				}
			}

			if (nextOffset == 0)
				break;
			if (nextOffset > versionNeedsEnd - entryCursor)
				break;

			entryCursor += nextOffset;
		}
	}

	private static Dictionary<ushort, string> ParseVersionDefinitions(IEndianDataSource data, ElfFile elf)
	{
		var result = new Dictionary<ushort, string>();
		var reader = new EndianDataReader(data, elf.Header.IsLittleEndian);

		foreach (var section in elf.Sections)
		{
			if (section.Type != ShtGnuVerDef)
				continue;
			if (section.Size == 0)
				continue;

			EnsureReadableRange(data, section.Offset, section.Size, "GNU version definitions");
			var sectionEnd = checked(section.Offset + section.Size);
			var entryCursor = section.Offset;

			while (entryCursor + 20 <= sectionEnd)
			{
				reader.Position = entryCursor;
				reader.ReadUInt16(); // vd_version
				reader.ReadUInt16(); // vd_flags
				var versionIndex = reader.ReadUInt16();
				reader.ReadUInt16(); // vd_cnt
				reader.ReadUInt32(); // vd_hash
				var auxOffset = reader.ReadUInt32();
				var nextOffset = reader.ReadUInt32();

				if (versionIndex > SymbolVersionGlobal && auxOffset != 0)
				{
					var auxCursor = checked(entryCursor + auxOffset);
					if (auxCursor + 8 <= sectionEnd)
					{
						reader.Position = auxCursor;
						var nameOffset = reader.ReadUInt32();
						var versionName = ReadString(data, elf, section.Link, nameOffset);
						if (!result.ContainsKey(versionIndex))
							result[versionIndex] = versionName;
					}
				}

				if (nextOffset == 0)
					break;
				if (entryCursor + nextOffset <= entryCursor || entryCursor + nextOffset > sectionEnd)
					break;

				entryCursor += nextOffset;
			}
		}

		ParseVersionDefinitionsFromDynamic(data, elf, result);

		return result;
	}

	private static void ParseVersionDefinitionsFromDynamic(IEndianDataSource data, ElfFile elf, Dictionary<ushort, string> result)
	{
		if (!TryGetDynamicValue(elf, DtVerDef, out var versionDefinitionsVirtualAddress))
			return;
		if (!TryGetMappedFileRange(elf, versionDefinitionsVirtualAddress, out var versionDefinitionsFileOffset, out var versionDefinitionsRange))
			return;
		if (!TryGetDynamicStringTable(elf, out var strTabFileOffset, out var strTabSize))
			return;
		if (versionDefinitionsRange < 20)
			return;

		EnsureReadableRange(data, strTabFileOffset, strTabSize, "dynamic string table");
		var versionDefinitionsEnd = checked(versionDefinitionsFileOffset + versionDefinitionsRange);
		var maxEntries = TryGetDynamicValue(elf, DtVerDefNum, out var configuredCount)
			? configuredCount
			: MaxParserEntryCount;
		if (maxEntries == 0)
			return;
		maxEntries = Math.Min(maxEntries, MaxParserEntryCount);

		var reader = new EndianDataReader(data, elf.Header.IsLittleEndian);
		var entryCursor = versionDefinitionsFileOffset;

		for (ulong entryIndex = 0; entryIndex < maxEntries && entryCursor + 20UL <= versionDefinitionsEnd; entryIndex++)
		{
			reader.Position = entryCursor;
			reader.ReadUInt16(); // vd_version
			reader.ReadUInt16(); // vd_flags
			var versionIndex = reader.ReadUInt16();
			reader.ReadUInt16(); // vd_cnt
			reader.ReadUInt32(); // vd_hash
			var auxOffset = reader.ReadUInt32();
			var nextOffset = reader.ReadUInt32();

			if (versionIndex > SymbolVersionGlobal && auxOffset != 0 && auxOffset <= versionDefinitionsEnd - entryCursor)
			{
				var auxCursor = entryCursor + auxOffset;
				if (auxCursor + 8UL <= versionDefinitionsEnd)
				{
					reader.Position = auxCursor;
					var nameOffset = reader.ReadUInt32();
					var versionName = ReadStringFromFileOffset(data, strTabFileOffset, strTabSize, nameOffset);
					if (!result.ContainsKey(versionIndex))
						result[versionIndex] = versionName;
				}
			}

			if (nextOffset == 0)
				break;
			if (nextOffset > versionDefinitionsEnd - entryCursor)
				break;

			entryCursor += nextOffset;
		}
	}

	private static bool TryGetDynamicStringTable(ElfFile elf, out ulong strTabFileOffset, out ulong strTabSize)
	{
		strTabFileOffset = 0;
		strTabSize = 0;

		if (!TryGetDynamicValue(elf, DtStrTab, out var strTabVirtualAddress))
			return false;
		if (!TryVirtualAddressToFileOffset(elf, strTabVirtualAddress, out strTabFileOffset))
			return false;

		strTabSize = TryGetDynamicValue(elf, DtStrSz, out var configuredSize) ? configuredSize : 0UL;
		if (strTabSize == 0 && TryGetMappedFileRange(elf, strTabVirtualAddress, out _, out var mappedRange))
			strTabSize = mappedRange;

		return strTabSize > 0;
	}

	private static void ClassifySymbols(ElfFile elf)
	{
		elf.ImportedSymbols.Clear();
		elf.ExportedSymbols.Clear();

		var importSeen = new HashSet<string>(StringComparer.Ordinal);
		foreach (var symbol in elf.Symbols.Where(s => s.IsImport))
		{
			var key = $"{symbol.QualifiedName}|{symbol.LibraryName}";
			if (importSeen.Add(key))
				elf.ImportedSymbols.Add(symbol);
		}

		var exportSeen = new HashSet<string>(StringComparer.Ordinal);
		foreach (var symbol in elf.Symbols
			.Where(s => s.IsExport)
			.OrderByDescending(s => s.IsDynamic)
			.ThenBy(s => s.Name, StringComparer.Ordinal))
		{
			if (exportSeen.Add(symbol.QualifiedName))
				elf.ExportedSymbols.Add(symbol);
		}
	}

	private static string ReadString(IEndianDataSource data, ElfFile elf, uint strIndex, uint offset)
	{
		if (strIndex >= elf.Sections.Count)
			return string.Empty;

		var strSection = elf.Sections[(int)strIndex];
		return ReadStringFromFileOffset(data, strSection.Offset, strSection.Size, offset);
	}

	private static string ReadStringFromFileOffset(IEndianDataSource data, ulong tableOffset, ulong tableSize, ulong offset)
	{
		if (tableSize == 0 || offset >= tableSize)
			return string.Empty;

		EnsureReadableRange(data, tableOffset, tableSize, "string table");

		var start = checked(tableOffset + offset);
		var endLimit = checked(tableOffset + tableSize);
		if (start >= data.Length)
			return string.Empty;
		if (endLimit > data.Length)
			endLimit = data.Length;

		const int chunkSize = 256;
		using var buffer = new MemoryStream();
		var cursor = start;
		while (cursor < endLimit)
		{
			var remaining = endLimit - cursor;
			var currentSize = (ulong)Math.Min(chunkSize, remaining);
			var chunk = ReadBytes(data, cursor, currentSize, "string table content");
			var terminator = Array.IndexOf(chunk, (byte)0);
			if (terminator >= 0)
			{
				if (terminator > 0)
					buffer.Write(chunk, 0, terminator);
				break;
			}

			buffer.Write(chunk, 0, chunk.Length);
			cursor = checked(cursor + currentSize);
		}

		return Encoding.UTF8.GetString(buffer.ToArray());
	}

	private static int GetManagedArrayLength(ulong count, string blockName)
	{
		if (count > int.MaxValue)
			throw new InvalidDataException($"ELF {blockName} exceeds managed array limits.");

		return (int)count;
	}
}
