namespace ELFInspector.Parser;

public class ElfRelocation
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

public static partial class ElfReader
{
	private const ulong ShfAlloc = 0x2;

	public static void ParseRelocations(IEndianDataSource data, ElfFile elf)
	{
		elf.Relocations.Clear();

		for (var sectionIndex = 0; sectionIndex < elf.Sections.Count; sectionIndex++)
		{
			var section = elf.Sections[sectionIndex];
			if (section.Type == ShtRel)
				ParseRelSection(data, elf, section);
			else if (section.Type == ShtRela)
				ParseRelaSection(data, elf, section);
			else if (section.Type == ShtRelr)
				ParseRelrSection(data, elf, section);
		}

		ParseRelocationsFromDynamicEntries(data, elf);
	}

	public static void ParseRelocations(ReadOnlySpan<byte> data, ElfFile elf)
	{
		using var source = ElfDataSourceFactory.CreateInMemory(data);
		ParseRelocations(source, elf);
	}

	private static void ParseRelSection(IEndianDataSource data, ElfFile elf, ElfSectionHeader section)
	{
		if (section.Size == 0)
			return;

		var entrySize = section.EntrySize;
		if (entrySize == 0)
			entrySize = elf.Header.Class == ElfClass.Elf32 ? 8UL : 16UL;

		var minEntrySize = elf.Header.Class == ElfClass.Elf32 ? 8UL : 16UL;
		if (entrySize < minEntrySize)
			throw new InvalidDataException("Invalid REL entry size.");

		EnsureReadableRange(data, section.Offset, section.Size, "REL section");
		var reader = new EndianDataReader(data, elf.Header.IsLittleEndian);
		var entryCount = section.Size / entrySize;
		EnsureReasonableEntryCount(entryCount, "REL section");

		for (ulong i = 0; i < entryCount; i++)
		{
			var entryOffset = checked(section.Offset + (i * entrySize));
			reader.Position = entryOffset;

			ulong offset;
			ulong info;

			if (elf.Header.Class == ElfClass.Elf32)
			{
				offset = reader.ReadUInt32();
				info = reader.ReadUInt32();
			}
			else
			{
				offset = reader.ReadUInt64();
				info = reader.ReadUInt64();
			}

			CreateRelocation(elf, section, offset, info, 0, false, "REL");
		}
	}

	private static void ParseRelaSection(IEndianDataSource data, ElfFile elf, ElfSectionHeader section)
	{
		if (section.Size == 0)
			return;

		var entrySize = section.EntrySize;
		if (entrySize == 0)
			entrySize = elf.Header.Class == ElfClass.Elf32 ? 12UL : 24UL;

		var minEntrySize = elf.Header.Class == ElfClass.Elf32 ? 12UL : 24UL;
		if (entrySize < minEntrySize)
			throw new InvalidDataException("Invalid RELA entry size.");

		EnsureReadableRange(data, section.Offset, section.Size, "RELA section");
		var reader = new EndianDataReader(data, elf.Header.IsLittleEndian);
		var entryCount = section.Size / entrySize;
		EnsureReasonableEntryCount(entryCount, "RELA section");

		for (ulong i = 0; i < entryCount; i++)
		{
			var entryOffset = checked(section.Offset + (i * entrySize));
			reader.Position = entryOffset;

			ulong offset;
			ulong info;
			long addend;

			if (elf.Header.Class == ElfClass.Elf32)
			{
				offset = reader.ReadUInt32();
				info = reader.ReadUInt32();
				addend = unchecked((int)reader.ReadUInt32());
			}
			else
			{
				offset = reader.ReadUInt64();
				info = reader.ReadUInt64();
				addend = unchecked((long)reader.ReadUInt64());
			}

			CreateRelocation(elf, section, offset, info, addend, true, "RELA");
		}
	}

	private static void ParseRelrSection(IEndianDataSource data, ElfFile elf, ElfSectionHeader section)
	{
		if (section.Size == 0)
			return;

		var wordSize = elf.Header.Class == ElfClass.Elf32 ? 4UL : 8UL;
		var entrySize = section.EntrySize == 0 ? wordSize : section.EntrySize;
		if (entrySize != wordSize)
			throw new InvalidDataException("Invalid RELR entry size.");

		EnsureReadableRange(data, section.Offset, section.Size, "RELR section");
		var entryCount = section.Size / entrySize;
		EnsureReasonableEntryCount(entryCount, "RELR section");

		var wordBitCount = (int)(wordSize * 8);
		var reader = new EndianDataReader(data, elf.Header.IsLittleEndian);
		var nextOffset = 0UL;
		var hasBaseAddress = false;

		for (ulong i = 0; i < entryCount; i++)
		{
			reader.Position = checked(section.Offset + (i * entrySize));
			var encoded = elf.Header.Class == ElfClass.Elf32 ? reader.ReadUInt32() : reader.ReadUInt64();

			if ((encoded & 1UL) == 0)
			{
				AddRelrRelocation(elf, encoded, seen: null, sourceContext: section.Name ?? string.Empty);
				nextOffset = checked(encoded + wordSize);
				hasBaseAddress = true;
				continue;
			}

			if (!hasBaseAddress)
				throw new InvalidDataException("Invalid RELR bitmap entry without base address.");

			for (var bit = 0; bit < wordBitCount - 1; bit++)
			{
				if ((encoded & (1UL << (bit + 1))) == 0)
					continue;

				var relocationOffset = checked(nextOffset + ((ulong)bit * wordSize));
				AddRelrRelocation(elf, relocationOffset, seen: null, sourceContext: section.Name ?? string.Empty);
			}

			nextOffset = checked(nextOffset + ((ulong)(wordBitCount - 1) * wordSize));
		}
	}

	private static void ParseRelocationsFromDynamicEntries(IEndianDataSource data, ElfFile elf)
	{
		if (elf.DynamicEntries.Count == 0)
			return;

		var seen = new HashSet<string>(elf.Relocations.Select(ToRelocationKey), StringComparer.Ordinal);

		ParseDynamicRelocationTable(data, elf, DtRel, DtRelSz, DtRelEnt, false, "REL", "DT_REL", seen);
		ParseDynamicRelocationTable(data, elf, DtRela, DtRelaSz, DtRelaEnt, true, "RELA", "DT_RELA", seen);
		ParseDynamicRelrTable(data, elf, seen);
		ParseDynamicPltRelocationTable(data, elf, seen);
	}

	private static void ParseDynamicRelocationTable(IEndianDataSource data, ElfFile elf, long tableTag, long sizeTag, long entryTag, bool hasAddend, string encoding, string sourceContext, HashSet<string> seen)
	{
		if (!TryGetDynamicValue(elf, tableTag, out var tableVirtualAddress))
			return;
		if (!TryGetDynamicValue(elf, sizeTag, out var tableSize) || tableSize == 0)
			return;

		var defaultEntrySize = hasAddend
			? (elf.Header.Class == ElfClass.Elf32 ? 12UL : 24UL)
			: (elf.Header.Class == ElfClass.Elf32 ? 8UL : 16UL);
		var entrySize = TryGetDynamicValue(elf, entryTag, out var configuredEntrySize)
			? configuredEntrySize
			: defaultEntrySize;

		if (entrySize < defaultEntrySize)
			return;
		if (!TryMapVirtualRangeToFile(elf, tableVirtualAddress, tableSize, out var tableFileOffset))
			return;

		EnsureReadableRange(data, tableFileOffset, tableSize, $"DT_{encoding} relocation table");
		var entryCount = tableSize / entrySize;
		EnsureReasonableEntryCount(entryCount, $"DT_{encoding} relocation entries");

		var reader = new EndianDataReader(data, elf.Header.IsLittleEndian);
		for (ulong i = 0; i < entryCount; i++)
		{
			reader.Position = checked(tableFileOffset + (i * entrySize));

			ulong offset;
			ulong info;
			long addend = 0;
			if (elf.Header.Class == ElfClass.Elf32)
			{
				offset = reader.ReadUInt32();
				info = reader.ReadUInt32();
				if (hasAddend)
					addend = unchecked((int)reader.ReadUInt32());
			}
			else
			{
				offset = reader.ReadUInt64();
				info = reader.ReadUInt64();
				if (hasAddend)
					addend = unchecked((long)reader.ReadUInt64());
			}

			CreateRelocationFromDynamic(elf, offset, info, addend, hasAddend, encoding, sourceContext, seen);
		}
	}

	private static void ParseDynamicPltRelocationTable(IEndianDataSource data, ElfFile elf, HashSet<string> seen)
	{
		if (!TryGetDynamicValue(elf, DtJmpRel, out var tableVirtualAddress))
			return;
		if (!TryGetDynamicValue(elf, DtPltRelSz, out var tableSize) || tableSize == 0)
			return;
		if (!TryGetDynamicValue(elf, DtPltRel, out var formatTag))
			return;

		if (formatTag == (ulong)DtRela)
		{
			var entrySize = TryGetDynamicValue(elf, DtRelaEnt, out var relaEntrySize)
				? relaEntrySize
				: (elf.Header.Class == ElfClass.Elf32 ? 12UL : 24UL);
			ParseDynamicRelocationTableAtAddress(data, elf, tableVirtualAddress, tableSize, entrySize, true, "RELA", "DT_JMPREL", seen);
			return;
		}

		if (formatTag == (ulong)DtRel)
		{
			var entrySize = TryGetDynamicValue(elf, DtRelEnt, out var relEntrySize)
				? relEntrySize
				: (elf.Header.Class == ElfClass.Elf32 ? 8UL : 16UL);
			ParseDynamicRelocationTableAtAddress(data, elf, tableVirtualAddress, tableSize, entrySize, false, "REL", "DT_JMPREL", seen);
		}
	}

	private static void ParseDynamicRelocationTableAtAddress(IEndianDataSource data, ElfFile elf, ulong tableVirtualAddress, ulong tableSize, ulong entrySize, bool hasAddend, string encoding, string sourceContext, HashSet<string> seen)
	{
		var minimumSize = hasAddend
			? (elf.Header.Class == ElfClass.Elf32 ? 12UL : 24UL)
			: (elf.Header.Class == ElfClass.Elf32 ? 8UL : 16UL);
		if (entrySize < minimumSize)
			return;
		if (!TryMapVirtualRangeToFile(elf, tableVirtualAddress, tableSize, out var tableFileOffset))
			return;

		EnsureReadableRange(data, tableFileOffset, tableSize, $"DT_JMPREL {encoding} relocation table");
		var entryCount = tableSize / entrySize;
		EnsureReasonableEntryCount(entryCount, $"DT_JMPREL {encoding} relocation entries");

		var reader = new EndianDataReader(data, elf.Header.IsLittleEndian);
		for (ulong i = 0; i < entryCount; i++)
		{
			reader.Position = checked(tableFileOffset + (i * entrySize));

			ulong offset;
			ulong info;
			long addend = 0;
			if (elf.Header.Class == ElfClass.Elf32)
			{
				offset = reader.ReadUInt32();
				info = reader.ReadUInt32();
				if (hasAddend)
					addend = unchecked((int)reader.ReadUInt32());
			}
			else
			{
				offset = reader.ReadUInt64();
				info = reader.ReadUInt64();
				if (hasAddend)
					addend = unchecked((long)reader.ReadUInt64());
			}

			CreateRelocationFromDynamic(elf, offset, info, addend, hasAddend, encoding, sourceContext, seen);
		}
	}

	private static void ParseDynamicRelrTable(IEndianDataSource data, ElfFile elf, HashSet<string> seen)
	{
		if (!TryGetDynamicValue(elf, DtRelr, out var relrVirtualAddress))
			return;
		if (!TryGetDynamicValue(elf, DtRelrSz, out var relrSize) || relrSize == 0)
			return;

		var wordSize = elf.Header.Class == ElfClass.Elf32 ? 4UL : 8UL;
		var entrySize = TryGetDynamicValue(elf, DtRelrEnt, out var configuredEntrySize) ? configuredEntrySize : wordSize;
		if (entrySize != wordSize)
			return;
		if (!TryMapVirtualRangeToFile(elf, relrVirtualAddress, relrSize, out var relrFileOffset))
			return;

		EnsureReadableRange(data, relrFileOffset, relrSize, "DT_RELR relocation table");
		var entryCount = relrSize / entrySize;
		EnsureReasonableEntryCount(entryCount, "DT_RELR relocation entries");

		var wordBitCount = (int)(wordSize * 8);
		var reader = new EndianDataReader(data, elf.Header.IsLittleEndian);
		var nextOffset = 0UL;
		var hasBaseAddress = false;

		for (ulong i = 0; i < entryCount; i++)
		{
			reader.Position = checked(relrFileOffset + (i * entrySize));
			var encoded = elf.Header.Class == ElfClass.Elf32 ? reader.ReadUInt32() : reader.ReadUInt64();

			if ((encoded & 1UL) == 0)
			{
				AddRelrRelocation(elf, encoded, seen, "DT_RELR");
				nextOffset = checked(encoded + wordSize);
				hasBaseAddress = true;
				continue;
			}

			if (!hasBaseAddress)
				throw new InvalidDataException("Invalid DT_RELR bitmap entry without base address.");

			for (var bit = 0; bit < wordBitCount - 1; bit++)
			{
				if ((encoded & (1UL << (bit + 1))) == 0)
					continue;

				var relocationOffset = checked(nextOffset + ((ulong)bit * wordSize));
				AddRelrRelocation(elf, relocationOffset, seen, "DT_RELR");
			}

			nextOffset = checked(nextOffset + ((ulong)(wordBitCount - 1) * wordSize));
		}
	}

	private static void AddRelrRelocation(ElfFile elf, ulong offset)
	{
		AddRelrRelocation(elf, offset, null, string.Empty);
	}

	private static void AddRelrRelocation(ElfFile elf, ulong offset, HashSet<string> seen)
	{
		AddRelrRelocation(elf, offset, seen, string.Empty);
	}

	private static void AddRelrRelocation(ElfFile elf, ulong offset, HashSet<string> seen, string sourceContext)
	{
		var relativeType = GetRelativeRelocationType(elf.Header.Machine);
		var type = relativeType ?? 0U;
		var typeName = relativeType.HasValue
			? GetRelocationTypeName(elf.Header.Machine, relativeType.Value)
			: "RELR_RELATIVE";

		var relocation = new ElfRelocation
		{
			Offset = offset,
			Info = 0,
			Encoding = "RELR",
			Addend = 0,
			HasAddend = false,
			SymbolIndex = 0,
			Type = type,
			TypeName = typeName,
			SymbolName = string.Empty,
			SymbolVersion = string.Empty,
			SymbolLibrary = string.Empty,
			SourceSection = sourceContext,
			AppliesToSection = ResolveSectionNameByAddress(elf, offset)
		};
		AssignLoaderPath(relocation);

		AddRelocationIfMissing(elf, relocation, seen);
	}

	private static void CreateRelocation(ElfFile elf, ElfSectionHeader section, ulong offset, ulong info, long addend, bool hasAddend, string encoding)
	{
		var symbolIndex = DecodeRelocationSymbolIndex(elf, info);
		var type = DecodeRelocationType(elf, info);
		var symbol = ResolveSymbolByIndex(elf, section.Link, symbolIndex);
		var appliesToSection = ResolveSectionName(elf, section.Info);
		if (string.IsNullOrEmpty(appliesToSection))
			appliesToSection = ResolveSectionNameByAddress(elf, offset);

		var relocation = new ElfRelocation
		{
			Offset = offset,
			Info = info,
			Encoding = encoding,
			Addend = addend,
			HasAddend = hasAddend,
			SymbolIndex = symbolIndex,
			Type = type,
			TypeName = GetRelocationTypeName(elf.Header.Machine, type),
			SymbolName = symbol?.Name ?? string.Empty,
			SymbolVersion = symbol?.VersionName ?? string.Empty,
			SymbolLibrary = symbol?.LibraryName ?? string.Empty,
			SourceSection = section.Name ?? string.Empty,
			AppliesToSection = appliesToSection
		};
		AssignLoaderPath(relocation);

		elf.Relocations.Add(relocation);
	}

	private static void CreateRelocationFromDynamic(ElfFile elf, ulong offset, ulong info, long addend, bool hasAddend, string encoding, string sourceContext, HashSet<string> seen)
	{
		var symbolIndex = DecodeRelocationSymbolIndex(elf, info);
		var type = DecodeRelocationType(elf, info);
		var symbol = ResolveDynamicSymbolByIndex(elf, symbolIndex);

		var relocation = new ElfRelocation
		{
			Offset = offset,
			Info = info,
			Encoding = encoding,
			Addend = addend,
			HasAddend = hasAddend,
			SymbolIndex = symbolIndex,
			Type = type,
			TypeName = GetRelocationTypeName(elf.Header.Machine, type),
			SymbolName = symbol?.Name ?? string.Empty,
			SymbolVersion = symbol?.VersionName ?? string.Empty,
			SymbolLibrary = symbol?.LibraryName ?? string.Empty,
			SourceSection = sourceContext,
			AppliesToSection = ResolveSectionNameByAddress(elf, offset)
		};
		AssignLoaderPath(relocation);

		AddRelocationIfMissing(elf, relocation, seen);
	}

	private static void AssignLoaderPath(ElfRelocation relocation)
	{
		var typeName = relocation.TypeName ?? string.Empty;
		var source = relocation.SourceSection ?? string.Empty;
		var target = relocation.AppliesToSection ?? string.Empty;

		var isTlsPath =
			ContainsAny(typeName, "_TLS", "TLSDESC", "TPREL", "DTPREL", "TPOFF", "GOTTPOFF")
			|| ContainsAny(source, ".tdata", ".tbss", ".tls")
			|| ContainsAny(target, ".tdata", ".tbss", ".tls");

		var isPltPath =
			ContainsAny(typeName, "JUMP_SLOT", "JMP_SLOT", "_PLT", "PLT32", "PLTREL", "IRELATIVE")
			|| ContainsAny(source, ".rel.plt", ".rela.plt", ".plt", "DT_JMPREL")
			|| ContainsAny(target, ".plt");

		var isGotPath =
			ContainsAny(typeName, "_GOT", "GLOB_DAT", "GOTPC", "GOTOFF")
			|| ContainsAny(source, ".got")
			|| ContainsAny(target, ".got");

		if (isTlsPath && ContainsAny(typeName, "TLSDESC", "GOTTPOFF"))
			isGotPath = true;

		relocation.IsTlsPath = isTlsPath;
		relocation.IsPltPath = isPltPath;
		relocation.IsGotPath = isGotPath;

		var buckets = new List<string>(3);
		if (isPltPath)
			buckets.Add("PLT");
		if (isGotPath)
			buckets.Add("GOT");
		if (isTlsPath)
			buckets.Add("TLS");
		if (buckets.Count == 0)
			buckets.Add(string.Equals(relocation.Encoding, "RELR", StringComparison.Ordinal) ? "RELATIVE" : "GENERAL");

		relocation.LoaderPath = string.Join("+", buckets);
	}

	private static bool ContainsAny(string value, params string[] tokens)
	{
		if (string.IsNullOrEmpty(value))
			return false;

		for (var i = 0; i < tokens.Length; i++)
		{
			if (value.IndexOf(tokens[i], StringComparison.OrdinalIgnoreCase) >= 0)
				return true;
		}

		return false;
	}

	private static ulong DecodeRelocationSymbolIndex(ElfFile elf, ulong info)
	{
		if (elf.Header.Class == ElfClass.Elf32)
			return info >> 8;
		if (elf.Header.Machine == 8) // MIPS64: symbol index is the first 32-bit field.
			return elf.Header.IsLittleEndian ? (info & 0xFFFFFFFFUL) : (info >> 32);

		return info >> 32;
	}

	private static uint DecodeRelocationType(ElfFile elf, ulong info)
	{
		if (elf.Header.Class == ElfClass.Elf32)
			return (uint)(info & 0xFF);
		if (elf.Header.Machine == 8) // MIPS64: r_info has type1/type2/type3 fields.
		{
			byte type1;
			byte type2;
			byte type3;
			if (elf.Header.IsLittleEndian)
			{
				type1 = (byte)((info >> 56) & 0xFF);
				type2 = (byte)((info >> 48) & 0xFF);
				type3 = (byte)((info >> 40) & 0xFF);
			}
			else
			{
				type1 = (byte)(info & 0xFF);
				type2 = (byte)((info >> 8) & 0xFF);
				type3 = (byte)((info >> 16) & 0xFF);
			}

			return (uint)(type1 | (type2 << 8) | (type3 << 16));
		}

		return (uint)(info & 0xFFFFFFFF);
	}

	private static ElfSymbol ResolveSymbolByIndex(ElfFile elf, uint symbolTableSectionIndex, ulong symbolIndex)
	{
		return elf.Symbols.FirstOrDefault(s => s.TableSectionIndex == symbolTableSectionIndex && s.Index == symbolIndex);
	}

	private static ElfSymbol ResolveDynamicSymbolByIndex(ElfFile elf, ulong symbolIndex)
	{
		return elf.Symbols.FirstOrDefault(s => s.IsDynamic && s.Index == symbolIndex);
	}

	private static void AddRelocationIfMissing(ElfFile elf, ElfRelocation relocation, HashSet<string> seen)
	{
		if (seen == null)
		{
			elf.Relocations.Add(relocation);
			return;
		}

		var key = ToRelocationKey(relocation);
		if (!seen.Add(key))
			return;

		elf.Relocations.Add(relocation);
	}

	private static string ToRelocationKey(ElfRelocation relocation)
	{
		return $"{relocation.Offset:X16}|{relocation.Info:X16}|{relocation.Addend}|{relocation.HasAddend}|{relocation.Encoding}";
	}

	private static string ResolveSectionName(ElfFile elf, uint sectionIndex)
	{
		if (sectionIndex >= elf.Sections.Count)
			return string.Empty;

		return elf.Sections[(int)sectionIndex].Name ?? string.Empty;
	}

	private static string ResolveSectionNameByAddress(ElfFile elf, ulong address)
	{
		foreach (var section in elf.Sections)
		{
			if (section.Size == 0)
				continue;
			if ((section.Flags & ShfAlloc) == 0)
				continue;

			var start = section.Address;
			var end = start + section.Size;
			if (end < start)
				end = ulong.MaxValue;

			if (address >= start && address < end)
				return section.Name ?? string.Empty;
		}

		return string.Empty;
	}

	private static uint? GetRelativeRelocationType(ushort machine)
	{
		return machine switch
		{
			3 => 8,      // R_386_RELATIVE
			8 => 3,      // R_MIPS_REL32
			20 => 22,    // R_PPC_RELATIVE
			21 => 22,    // R_PPC64_RELATIVE
			22 => 12,    // R_390_RELATIVE
			2 => 22,     // R_SPARC_RELATIVE
			43 => 22,    // R_SPARC_RELATIVE
			40 => 23,    // R_ARM_RELATIVE
			62 => 8,     // R_X86_64_RELATIVE
			183 => 1027, // R_AARCH64_RELATIVE
			243 => 3,    // R_RISCV_RELATIVE
			_ => null
		};
	}

	private static readonly IReadOnlyDictionary<ushort, IReadOnlyDictionary<uint, string>> RelocationTypeTables = CreateRelocationTypeTables();

	private static string GetRelocationTypeName(ushort machine, uint type)
	{
		if (machine == 8)
			return GetMipsRelocationTypeName(type);

		if (RelocationTypeTables.TryGetValue(machine, out var table)
			&& table.TryGetValue(type, out var relocationName))
		{
			return relocationName;
		}

		return GetRelocationTypeNameFromSwitch(machine, type);
	}

	private static IReadOnlyDictionary<ushort, IReadOnlyDictionary<uint, string>> CreateRelocationTypeTables()
	{
		return new Dictionary<ushort, IReadOnlyDictionary<uint, string>>
		{
			[3] = CreateRelocationMap(
				(0, "R_386_NONE"),
				(1, "R_386_32"),
				(2, "R_386_PC32"),
				(3, "R_386_GOT32"),
				(4, "R_386_PLT32"),
				(5, "R_386_COPY"),
				(6, "R_386_GLOB_DAT"),
				(7, "R_386_JUMP_SLOT"),
				(8, "R_386_RELATIVE"),
				(9, "R_386_GOTOFF"),
				(10, "R_386_GOTPC"),
				(15, "R_386_TLS_TPOFF"),
				(16, "R_386_TLS_IE"),
				(17, "R_386_TLS_GOTIE"),
				(18, "R_386_TLS_LE"),
				(19, "R_386_TLS_GD"),
				(20, "R_386_TLS_LDM"),
				(36, "R_386_TLS_DTPMOD32"),
				(37, "R_386_TLS_DTPOFF32"),
				(38, "R_386_TLS_TPOFF32"),
				(39, "R_386_SIZE32"),
				(42, "R_386_IRELATIVE")),
			[20] = CreateRelocationMap(
				(0, "R_PPC_NONE"),
				(1, "R_PPC_ADDR32"),
				(10, "R_PPC_REL24"),
				(19, "R_PPC_COPY"),
				(20, "R_PPC_GLOB_DAT"),
				(21, "R_PPC_JMP_SLOT"),
				(22, "R_PPC_RELATIVE"),
				(26, "R_PPC_REL32"),
				(67, "R_PPC_TLS_DTPMOD32"),
				(68, "R_PPC_TLS_DTPREL32"),
				(69, "R_PPC_TLS_TPREL32"),
				(70, "R_PPC_TLS_GD"),
				(71, "R_PPC_TLS_LDM"),
				(248, "R_PPC_IRELATIVE")),
			[21] = CreateRelocationMap(
				(0, "R_PPC64_NONE"),
				(1, "R_PPC64_ADDR32"),
				(10, "R_PPC64_REL24"),
				(20, "R_PPC64_GLOB_DAT"),
				(21, "R_PPC64_JMP_SLOT"),
				(22, "R_PPC64_RELATIVE"),
				(38, "R_PPC64_ADDR64"),
				(67, "R_PPC64_TLS_DTPMOD64"),
				(68, "R_PPC64_TLS_DTPREL64"),
				(69, "R_PPC64_TLS_TPREL64"),
				(107, "R_PPC64_TLSDESC"),
				(248, "R_PPC64_IRELATIVE")),
			[22] = CreateRelocationMap(
				(0, "R_390_NONE"),
				(1, "R_390_8"),
				(2, "R_390_12"),
				(3, "R_390_16"),
				(4, "R_390_32"),
				(5, "R_390_PC32"),
				(9, "R_390_COPY"),
				(10, "R_390_GLOB_DAT"),
				(11, "R_390_JMP_SLOT"),
				(12, "R_390_RELATIVE"),
				(22, "R_390_64"),
				(23, "R_390_PC64"),
				(60, "R_390_TLS_LOAD"),
				(61, "R_390_IRELATIVE")),
			[2] = CreateRelocationMap(
				(0, "R_SPARC_NONE"),
				(3, "R_SPARC_32"),
				(8, "R_SPARC_WDISP30"),
				(10, "R_SPARC_HI22"),
				(13, "R_SPARC_LO10"),
				(19, "R_SPARC_COPY"),
				(20, "R_SPARC_GLOB_DAT"),
				(21, "R_SPARC_JMP_SLOT"),
				(22, "R_SPARC_RELATIVE"),
				(32, "R_SPARC_64"),
				(48, "R_SPARC_DISP64"),
				(49, "R_SPARC_PLT64"),
				(249, "R_SPARC_IRELATIVE")),
			[43] = CreateRelocationMap(
				(0, "R_SPARC_NONE"),
				(3, "R_SPARC_32"),
				(8, "R_SPARC_WDISP30"),
				(10, "R_SPARC_HI22"),
				(13, "R_SPARC_LO10"),
				(19, "R_SPARC_COPY"),
				(20, "R_SPARC_GLOB_DAT"),
				(21, "R_SPARC_JMP_SLOT"),
				(22, "R_SPARC_RELATIVE"),
				(32, "R_SPARC_64"),
				(48, "R_SPARC_DISP64"),
				(49, "R_SPARC_PLT64"),
				(249, "R_SPARC_IRELATIVE")),
			[40] = CreateRelocationMap(
				(0, "R_ARM_NONE"),
				(1, "R_ARM_PC24"),
				(2, "R_ARM_ABS32"),
				(3, "R_ARM_REL32"),
				(10, "R_ARM_THM_CALL"),
				(17, "R_ARM_TLS_DTPMOD32"),
				(18, "R_ARM_TLS_DTPOFF32"),
				(19, "R_ARM_TLS_TPOFF32"),
				(20, "R_ARM_COPY"),
				(21, "R_ARM_GLOB_DAT"),
				(22, "R_ARM_JUMP_SLOT"),
				(23, "R_ARM_RELATIVE"),
				(26, "R_ARM_GOT_BREL"),
				(27, "R_ARM_PLT32"),
				(28, "R_ARM_CALL"),
				(29, "R_ARM_JUMP24"),
				(30, "R_ARM_THM_JUMP24"),
				(42, "R_ARM_PREL31"),
				(43, "R_ARM_MOVW_ABS_NC"),
				(44, "R_ARM_MOVT_ABS"),
				(45, "R_ARM_MOVW_PREL_NC"),
				(46, "R_ARM_MOVT_PREL"),
				(47, "R_ARM_THM_MOVW_ABS_NC"),
				(48, "R_ARM_THM_MOVT_ABS"),
				(49, "R_ARM_THM_MOVW_PREL_NC"),
				(50, "R_ARM_THM_MOVT_PREL"),
				(160, "R_ARM_IRELATIVE")),
			[62] = CreateRelocationMap(
				(0, "R_X86_64_NONE"),
				(1, "R_X86_64_64"),
				(2, "R_X86_64_PC32"),
				(4, "R_X86_64_PLT32"),
				(5, "R_X86_64_COPY"),
				(6, "R_X86_64_GLOB_DAT"),
				(7, "R_X86_64_JUMP_SLOT"),
				(8, "R_X86_64_RELATIVE"),
				(9, "R_X86_64_GOTPCREL"),
				(16, "R_X86_64_DTPMOD64"),
				(17, "R_X86_64_DTPOFF64"),
				(18, "R_X86_64_TPOFF64"),
				(19, "R_X86_64_TLSGD"),
				(20, "R_X86_64_TLSLD"),
				(21, "R_X86_64_DTPOFF32"),
				(22, "R_X86_64_GOTTPOFF"),
				(23, "R_X86_64_TPOFF32"),
				(32, "R_X86_64_SIZE32"),
				(33, "R_X86_64_SIZE64"),
				(37, "R_X86_64_IRELATIVE")),
			[183] = CreateRelocationMap(
				(0, "R_AARCH64_NONE"),
				(257, "R_AARCH64_ABS64"),
				(258, "R_AARCH64_ABS32"),
				(259, "R_AARCH64_ABS16"),
				(260, "R_AARCH64_PREL64"),
				(261, "R_AARCH64_PREL32"),
				(262, "R_AARCH64_PREL16"),
				(1024, "R_AARCH64_COPY"),
				(1025, "R_AARCH64_GLOB_DAT"),
				(1026, "R_AARCH64_JUMP_SLOT"),
				(1027, "R_AARCH64_RELATIVE"),
				(1028, "R_AARCH64_TLS_DTPMOD64"),
				(1029, "R_AARCH64_TLS_DTPREL64"),
				(1030, "R_AARCH64_TLS_TPREL64"),
				(1031, "R_AARCH64_TLSDESC"),
				(1032, "R_AARCH64_IRELATIVE")),
			[243] = CreateRelocationMap(
				(0, "R_RISCV_NONE"),
				(1, "R_RISCV_32"),
				(2, "R_RISCV_64"),
				(3, "R_RISCV_RELATIVE"),
				(4, "R_RISCV_COPY"),
				(5, "R_RISCV_JUMP_SLOT"),
				(6, "R_RISCV_TLS_DTPMOD32"),
				(7, "R_RISCV_TLS_DTPMOD64"),
				(8, "R_RISCV_TLS_DTPREL32"),
				(9, "R_RISCV_TLS_DTPREL64"),
				(10, "R_RISCV_TLS_TPREL32"),
				(11, "R_RISCV_TLS_TPREL64"),
				(12, "R_RISCV_TLSDESC"),
				(16, "R_RISCV_BRANCH"),
				(17, "R_RISCV_JAL"),
				(18, "R_RISCV_CALL"),
				(19, "R_RISCV_CALL_PLT"),
				(20, "R_RISCV_GOT_HI20"),
				(21, "R_RISCV_TLS_GOT_HI20"),
				(22, "R_RISCV_TLS_GD_HI20"),
				(23, "R_RISCV_PCREL_HI20"),
				(24, "R_RISCV_PCREL_LO12_I"),
				(25, "R_RISCV_PCREL_LO12_S"),
				(26, "R_RISCV_HI20"),
				(27, "R_RISCV_LO12_I"),
				(28, "R_RISCV_LO12_S"),
				(29, "R_RISCV_TPREL_HI20"),
				(30, "R_RISCV_TPREL_LO12_I"),
				(31, "R_RISCV_TPREL_LO12_S"),
				(32, "R_RISCV_TPREL_ADD"),
				(33, "R_RISCV_ADD8"),
				(34, "R_RISCV_ADD16"),
				(35, "R_RISCV_ADD32"),
				(36, "R_RISCV_ADD64"),
				(37, "R_RISCV_SUB8"),
				(38, "R_RISCV_SUB16"),
				(39, "R_RISCV_SUB32"),
				(40, "R_RISCV_SUB64"),
				(43, "R_RISCV_ALIGN"),
				(44, "R_RISCV_RVC_BRANCH"),
				(45, "R_RISCV_RVC_JUMP"),
				(46, "R_RISCV_RELAX"),
				(47, "R_RISCV_SUB6"),
				(48, "R_RISCV_SET6"),
				(49, "R_RISCV_SET8"),
				(50, "R_RISCV_SET16"),
				(51, "R_RISCV_SET32"),
				(52, "R_RISCV_32_PCREL"),
				(58, "R_RISCV_IRELATIVE"))
		};
	}

	private static IReadOnlyDictionary<uint, string> CreateRelocationMap(params (uint Type, string Name)[] entries)
	{
		var map = new Dictionary<uint, string>();
		for (var i = 0; i < entries.Length; i++)
			map[entries[i].Type] = entries[i].Name;

		return map;
	}

	private static bool HasRelocationTypeTableEntry(ushort machine, uint type)
	{
		return RelocationTypeTables.TryGetValue(machine, out var table) && table.ContainsKey(type);
	}

	private static string GetRelocationTypeNameFromSwitch(ushort machine, uint type)
		{
			return machine switch
			{
				3 => type switch
			{
				0 => "R_386_NONE",
				1 => "R_386_32",
				2 => "R_386_PC32",
				3 => "R_386_GOT32",
				4 => "R_386_PLT32",
				5 => "R_386_COPY",
				6 => "R_386_GLOB_DAT",
				7 => "R_386_JUMP_SLOT",
				8 => "R_386_RELATIVE",
				9 => "R_386_GOTOFF",
				10 => "R_386_GOTPC",
				11 => "R_386_32PLT",
				14 => "R_386_PLT32",
				15 => "R_386_TLS_TPOFF",
				16 => "R_386_TLS_IE",
				17 => "R_386_TLS_GOTIE",
				18 => "R_386_TLS_LE",
				19 => "R_386_TLS_GD",
				20 => "R_386_TLS_LDM",
				21 => "R_386_16",
				22 => "R_386_PC16",
				23 => "R_386_8",
				24 => "R_386_PC8",
					36 => "R_386_TLS_DTPMOD32",
					37 => "R_386_TLS_DTPOFF32",
					38 => "R_386_TLS_TPOFF32",
					39 => "R_386_SIZE32",
					42 => "R_386_IRELATIVE",
					_ => FormatRelocationTypeFallback("R_386", type)
				},
				8 => GetMipsRelocationTypeName(type),
				20 => type switch
				{
					0 => "R_PPC_NONE",
				1 => "R_PPC_ADDR32",
				2 => "R_PPC_ADDR24",
				3 => "R_PPC_ADDR16",
				4 => "R_PPC_ADDR16_LO",
				5 => "R_PPC_ADDR16_HI",
				6 => "R_PPC_ADDR16_HA",
				10 => "R_PPC_REL24",
				11 => "R_PPC_REL14",
				14 => "R_PPC_GOT16",
				18 => "R_PPC_PLTREL24",
				19 => "R_PPC_COPY",
				20 => "R_PPC_GLOB_DAT",
				21 => "R_PPC_JMP_SLOT",
				22 => "R_PPC_RELATIVE",
				26 => "R_PPC_REL32",
				27 => "R_PPC_PLT32",
				32 => "R_PPC_REL16",
				33 => "R_PPC_REL16_LO",
				34 => "R_PPC_REL16_HI",
				35 => "R_PPC_REL16_HA",
				67 => "R_PPC_TLS_DTPMOD32",
				68 => "R_PPC_TLS_DTPREL32",
				69 => "R_PPC_TLS_TPREL32",
				70 => "R_PPC_TLS_GD",
				71 => "R_PPC_TLS_LDM",
				72 => "R_PPC_TLS_DTPREL16",
				73 => "R_PPC_TLS_DTPREL16_LO",
				74 => "R_PPC_TLS_DTPREL16_HI",
				75 => "R_PPC_TLS_DTPREL16_HA",
					76 => "R_PPC_TLS_TPREL16",
					77 => "R_PPC_TLS_TPREL16_LO",
					78 => "R_PPC_TLS_TPREL16_HI",
					79 => "R_PPC_TLS_TPREL16_HA",
					248 => "R_PPC_IRELATIVE",
					_ => FormatRelocationTypeFallback("R_PPC", type)
				},
				21 => type switch
				{
					0 => "R_PPC64_NONE",
					1 => "R_PPC64_ADDR32",
					2 => "R_PPC64_ADDR24",
					10 => "R_PPC64_REL24",
					16 => "R_PPC64_ADDR16",
					17 => "R_PPC64_ADDR16_LO",
					18 => "R_PPC64_ADDR16_HI",
					19 => "R_PPC64_ADDR16_HA",
					20 => "R_PPC64_GLOB_DAT",
					21 => "R_PPC64_JMP_SLOT",
					22 => "R_PPC64_RELATIVE",
					26 => "R_PPC64_REL32",
					44 => "R_PPC64_TOC",
					46 => "R_PPC64_PLTGOT16",
					47 => "R_PPC64_PLTGOT16_LO",
					48 => "R_PPC64_PLTGOT16_HI",
					49 => "R_PPC64_PLTGOT16_HA",
					67 => "R_PPC64_TLS_DTPMOD64",
					68 => "R_PPC64_TLS_DTPREL64",
					69 => "R_PPC64_TLS_TPREL64",
					107 => "R_PPC64_TLSDESC",
					248 => "R_PPC64_IRELATIVE",
					38 => "R_PPC64_ADDR64",
					_ => FormatRelocationTypeFallback("R_PPC64", type)
				},
				22 => type switch
				{
					0 => "R_390_NONE",
					1 => "R_390_8",
				2 => "R_390_12",
				3 => "R_390_16",
				4 => "R_390_32",
				5 => "R_390_PC32",
				6 => "R_390_GOT12",
				7 => "R_390_GOT32",
				8 => "R_390_PLT32",
				9 => "R_390_COPY",
				10 => "R_390_GLOB_DAT",
				11 => "R_390_JMP_SLOT",
				12 => "R_390_RELATIVE",
				13 => "R_390_GOTPC",
				16 => "R_390_GOT16",
				17 => "R_390_PC16",
				18 => "R_390_PC16DBL",
				19 => "R_390_PLT16DBL",
				20 => "R_390_PC32DBL",
				21 => "R_390_PLT32DBL",
				22 => "R_390_64",
				23 => "R_390_PC64",
				24 => "R_390_GOT64",
				25 => "R_390_PLT64",
				26 => "R_390_GOTENT",
					27 => "R_390_GOTPLT12",
					28 => "R_390_GOTPLT16",
					29 => "R_390_GOTPLT32",
					30 => "R_390_GOTPLT64",
					56 => "R_390_GOTPLTENT",
					57 => "R_390_GOTPLTOFF16",
					58 => "R_390_GOTPLTOFF32",
					59 => "R_390_GOTPLTOFF64",
					60 => "R_390_TLS_LOAD",
					61 => "R_390_IRELATIVE",
					_ => FormatRelocationTypeFallback("R_390", type)
				},
				2 or 43 => type switch
				{
					0 => "R_SPARC_NONE",
				1 => "R_SPARC_8",
				2 => "R_SPARC_16",
				3 => "R_SPARC_32",
				5 => "R_SPARC_DISP8",
				6 => "R_SPARC_DISP16",
				7 => "R_SPARC_DISP32",
				8 => "R_SPARC_WDISP30",
				9 => "R_SPARC_WDISP22",
				10 => "R_SPARC_HI22",
				11 => "R_SPARC_22",
				12 => "R_SPARC_13",
				13 => "R_SPARC_LO10",
				14 => "R_SPARC_GOT10",
				15 => "R_SPARC_GOT13",
				16 => "R_SPARC_GOT22",
				17 => "R_SPARC_PC10",
				18 => "R_SPARC_PC22",
				19 => "R_SPARC_COPY",
				20 => "R_SPARC_GLOB_DAT",
				21 => "R_SPARC_JMP_SLOT",
				22 => "R_SPARC_RELATIVE",
				23 => "R_SPARC_UA32",
				24 => "R_SPARC_PLT32",
				25 => "R_SPARC_HIPLT22",
				26 => "R_SPARC_LOPLT10",
				27 => "R_SPARC_PCPLT32",
				28 => "R_SPARC_PCPLT22",
				29 => "R_SPARC_PCPLT10",
				30 => "R_SPARC_10",
				31 => "R_SPARC_11",
				32 => "R_SPARC_64",
				33 => "R_SPARC_OLO10",
					34 => "R_SPARC_HH22",
					35 => "R_SPARC_HM10",
					36 => "R_SPARC_LM22",
					37 => "R_SPARC_PC_HH22",
					38 => "R_SPARC_PC_HM10",
					39 => "R_SPARC_PC_LM22",
					48 => "R_SPARC_DISP64",
					49 => "R_SPARC_PLT64",
					50 => "R_SPARC_HIX22",
					51 => "R_SPARC_LOX10",
					249 => "R_SPARC_IRELATIVE",
					_ => FormatRelocationTypeFallback("R_SPARC", type)
				},
				40 => type switch
				{
					0 => "R_ARM_NONE",
					1 => "R_ARM_PC24",
					2 => "R_ARM_ABS32",
					3 => "R_ARM_REL32",
					4 => "R_ARM_LDR_PC_G0",
					5 => "R_ARM_ABS16",
					6 => "R_ARM_ABS12",
					7 => "R_ARM_THM_ABS5",
					8 => "R_ARM_ABS8",
					9 => "R_ARM_SBREL32",
					10 => "R_ARM_THM_CALL",
					11 => "R_ARM_THM_PC8",
					12 => "R_ARM_BREL_ADJ",
					13 => "R_ARM_TLS_DESC",
					14 => "R_ARM_THM_SWI8",
					15 => "R_ARM_XPC25",
					16 => "R_ARM_THM_XPC22",
					17 => "R_ARM_TLS_DTPMOD32",
					18 => "R_ARM_TLS_DTPOFF32",
					19 => "R_ARM_TLS_TPOFF32",
					20 => "R_ARM_COPY",
					21 => "R_ARM_GLOB_DAT",
					22 => "R_ARM_JUMP_SLOT",
					23 => "R_ARM_RELATIVE",
					24 => "R_ARM_GOTOFF32",
					25 => "R_ARM_BASE_PREL",
					26 => "R_ARM_GOT_BREL",
					27 => "R_ARM_PLT32",
					28 => "R_ARM_CALL",
					29 => "R_ARM_JUMP24",
					30 => "R_ARM_THM_JUMP24",
					31 => "R_ARM_BASE_ABS",
					32 => "R_ARM_ALU_PCREL_7_0",
					33 => "R_ARM_ALU_PCREL_15_8",
					34 => "R_ARM_ALU_PCREL_23_15",
					35 => "R_ARM_LDR_SBREL_11_0_NC",
					36 => "R_ARM_ALU_SBREL_19_12_NC",
					37 => "R_ARM_ALU_SBREL_27_20_CK",
					38 => "R_ARM_TARGET1",
					39 => "R_ARM_SBREL31",
					40 => "R_ARM_V4BX",
					41 => "R_ARM_TARGET2",
					42 => "R_ARM_PREL31",
					43 => "R_ARM_MOVW_ABS_NC",
					44 => "R_ARM_MOVT_ABS",
				45 => "R_ARM_MOVW_PREL_NC",
				46 => "R_ARM_MOVT_PREL",
				47 => "R_ARM_THM_MOVW_ABS_NC",
				48 => "R_ARM_THM_MOVT_ABS",
				49 => "R_ARM_THM_MOVW_PREL_NC",
				50 => "R_ARM_THM_MOVT_PREL",
					51 => "R_ARM_THM_JUMP19",
					53 => "R_ARM_THM_ALU_PREL_11_0",
					54 => "R_ARM_THM_PC12",
					55 => "R_ARM_ABS32_NOI",
					56 => "R_ARM_REL32_NOI",
					57 => "R_ARM_ALU_PC_G0_NC",
					58 => "R_ARM_ALU_PC_G0",
					160 => "R_ARM_IRELATIVE",
					_ => FormatRelocationTypeFallback("R_ARM", type)
				},
				62 => type switch
				{
					0 => "R_X86_64_NONE",
					1 => "R_X86_64_64",
					2 => "R_X86_64_PC32",
					3 => "R_X86_64_GOT32",
					4 => "R_X86_64_PLT32",
					5 => "R_X86_64_COPY",
					6 => "R_X86_64_GLOB_DAT",
					7 => "R_X86_64_JUMP_SLOT",
					8 => "R_X86_64_RELATIVE",
					9 => "R_X86_64_GOTPCREL",
					10 => "R_X86_64_32",
					11 => "R_X86_64_32S",
					12 => "R_X86_64_16",
					13 => "R_X86_64_PC16",
					14 => "R_X86_64_8",
					15 => "R_X86_64_PC8",
					16 => "R_X86_64_DTPMOD64",
					17 => "R_X86_64_DTPOFF64",
					18 => "R_X86_64_TPOFF64",
					19 => "R_X86_64_TLSGD",
					20 => "R_X86_64_TLSLD",
					21 => "R_X86_64_DTPOFF32",
					22 => "R_X86_64_GOTTPOFF",
					23 => "R_X86_64_TPOFF32",
					24 => "R_X86_64_PC64",
					25 => "R_X86_64_GOTOFF64",
					26 => "R_X86_64_GOTPC32",
					32 => "R_X86_64_SIZE32",
					33 => "R_X86_64_SIZE64",
					37 => "R_X86_64_IRELATIVE",
					_ => FormatRelocationTypeFallback("R_X86_64", type)
				},
				183 => type switch
				{
					0 => "R_AARCH64_NONE",
					257 => "R_AARCH64_ABS64",
					258 => "R_AARCH64_ABS32",
					259 => "R_AARCH64_ABS16",
					260 => "R_AARCH64_PREL64",
					261 => "R_AARCH64_PREL32",
					262 => "R_AARCH64_PREL16",
					1024 => "R_AARCH64_COPY",
					1025 => "R_AARCH64_GLOB_DAT",
					1026 => "R_AARCH64_JUMP_SLOT",
					1027 => "R_AARCH64_RELATIVE",
					1028 => "R_AARCH64_TLS_DTPMOD64",
					1029 => "R_AARCH64_TLS_DTPREL64",
					1030 => "R_AARCH64_TLS_TPREL64",
					1031 => "R_AARCH64_TLSDESC",
					1032 => "R_AARCH64_IRELATIVE",
					_ => FormatRelocationTypeFallback("R_AARCH64", type)
				},
				243 => type switch
				{
					0 => "R_RISCV_NONE",
				1 => "R_RISCV_32",
				2 => "R_RISCV_64",
				3 => "R_RISCV_RELATIVE",
				4 => "R_RISCV_COPY",
				5 => "R_RISCV_JUMP_SLOT",
				6 => "R_RISCV_TLS_DTPMOD32",
				7 => "R_RISCV_TLS_DTPMOD64",
				8 => "R_RISCV_TLS_DTPREL32",
				9 => "R_RISCV_TLS_DTPREL64",
				10 => "R_RISCV_TLS_TPREL32",
				11 => "R_RISCV_TLS_TPREL64",
				12 => "R_RISCV_TLSDESC",
				16 => "R_RISCV_BRANCH",
				17 => "R_RISCV_JAL",
				18 => "R_RISCV_CALL",
				19 => "R_RISCV_CALL_PLT",
				20 => "R_RISCV_GOT_HI20",
				21 => "R_RISCV_TLS_GOT_HI20",
				22 => "R_RISCV_TLS_GD_HI20",
				23 => "R_RISCV_PCREL_HI20",
				24 => "R_RISCV_PCREL_LO12_I",
				25 => "R_RISCV_PCREL_LO12_S",
				26 => "R_RISCV_HI20",
				27 => "R_RISCV_LO12_I",
				28 => "R_RISCV_LO12_S",
				29 => "R_RISCV_TPREL_HI20",
				30 => "R_RISCV_TPREL_LO12_I",
				31 => "R_RISCV_TPREL_LO12_S",
				32 => "R_RISCV_TPREL_ADD",
				33 => "R_RISCV_ADD8",
				34 => "R_RISCV_ADD16",
				35 => "R_RISCV_ADD32",
				36 => "R_RISCV_ADD64",
				37 => "R_RISCV_SUB8",
				38 => "R_RISCV_SUB16",
				39 => "R_RISCV_SUB32",
				40 => "R_RISCV_SUB64",
					43 => "R_RISCV_ALIGN",
					44 => "R_RISCV_RVC_BRANCH",
					45 => "R_RISCV_RVC_JUMP",
					46 => "R_RISCV_RELAX",
					47 => "R_RISCV_SUB6",
					48 => "R_RISCV_SET6",
					49 => "R_RISCV_SET8",
					50 => "R_RISCV_SET16",
					51 => "R_RISCV_SET32",
					52 => "R_RISCV_32_PCREL",
					58 => "R_RISCV_IRELATIVE",
					_ => FormatRelocationTypeFallback("R_RISCV", type)
				},
				_ => FormatMachineRelocationTypeFallback(machine, type)
				};
			}

		private static string FormatRelocationTypeFallback(string architecturePrefix, uint type)
		{
			return $"{architecturePrefix}_UNKNOWN_{type}";
		}

		private static string FormatMachineRelocationTypeFallback(ushort machine, uint type)
		{
			return $"R_MACHINE_{machine}_{type}";
		}

	private static string GetMipsRelocationTypeName(uint type)
	{
		if (type <= 0xFF)
			return GetMipsRelocationTypeComponent((byte)type);

		var type1 = (byte)(type & 0xFF);
		var type2 = (byte)((type >> 8) & 0xFF);
		var type3 = (byte)((type >> 16) & 0xFF);
		return $"{GetMipsRelocationTypeComponent(type1)}/{GetMipsRelocationTypeComponent(type2)}/{GetMipsRelocationTypeComponent(type3)}";
	}

		private static string GetMipsRelocationTypeComponent(byte type)
		{
			return type switch
			{
			0 => "R_MIPS_NONE",
			1 => "R_MIPS_16",
			2 => "R_MIPS_32",
			3 => "R_MIPS_REL32",
			4 => "R_MIPS_26",
			5 => "R_MIPS_HI16",
			6 => "R_MIPS_LO16",
			7 => "R_MIPS_GPREL16",
			8 => "R_MIPS_LITERAL",
			9 => "R_MIPS_GOT16",
			10 => "R_MIPS_PC16",
			11 => "R_MIPS_CALL16",
			12 => "R_MIPS_GPREL32",
			16 => "R_MIPS_SHIFT5",
			17 => "R_MIPS_SHIFT6",
			18 => "R_MIPS_64",
			19 => "R_MIPS_GOT_DISP",
			20 => "R_MIPS_GOT_PAGE",
			21 => "R_MIPS_GOT_OFST",
			22 => "R_MIPS_GOT_HI16",
			23 => "R_MIPS_GOT_LO16",
			24 => "R_MIPS_SUB",
			25 => "R_MIPS_INSERT_A",
			26 => "R_MIPS_INSERT_B",
			27 => "R_MIPS_DELETE",
			28 => "R_MIPS_HIGHER",
			29 => "R_MIPS_HIGHEST",
			30 => "R_MIPS_CALL_HI16",
			31 => "R_MIPS_CALL_LO16",
			32 => "R_MIPS_SCN_DISP",
			33 => "R_MIPS_REL16",
			34 => "R_MIPS_ADD_IMMEDIATE",
			35 => "R_MIPS_PJUMP",
			36 => "R_MIPS_RELGOT",
			37 => "R_MIPS_JALR",
			38 => "R_MIPS_TLS_DTPMOD32",
			39 => "R_MIPS_TLS_DTPREL32",
			40 => "R_MIPS_TLS_DTPMOD64",
			41 => "R_MIPS_TLS_DTPREL64",
			42 => "R_MIPS_TLS_GD",
			43 => "R_MIPS_TLS_LDM",
			44 => "R_MIPS_TLS_DTPREL_HI16",
			45 => "R_MIPS_TLS_DTPREL_LO16",
			46 => "R_MIPS_TLS_GOTTPREL",
			47 => "R_MIPS_TLS_TPREL32",
			48 => "R_MIPS_TLS_TPREL64",
			49 => "R_MIPS_TLS_TPREL_HI16",
			50 => "R_MIPS_TLS_TPREL_LO16",
			51 => "R_MIPS_PC21_S2",
			52 => "R_MIPS_PC26_S2",
				53 => "R_MIPS_PC18_S3",
				54 => "R_MIPS_PC19_S2",
				55 => "R_MIPS_PCHI16",
				56 => "R_MIPS_PCLO16",
				57 => "R_MIPS_COPY",
				58 => "R_MIPS_JUMP_SLOT",
				59 => "R_MIPS_PC32",
				60 => "R_MIPS_GLOB_DAT",
				61 => "R_MIPS_TLS_DTPREL_HI16",
				62 => "R_MIPS_TLS_DTPREL_LO16",
				63 => "R_MIPS_TLS_TPREL_HI16",
				64 => "R_MIPS_TLS_TPREL_LO16",
				_ => FormatRelocationTypeFallback("R_MIPS", type)
			};
		}
	}
