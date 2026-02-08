namespace ELFInspector.Parser;

public class ElfDynamicEntry
{
	public long Tag { get; set; }
	public string TagName { get; set; }
	public ulong Value { get; set; }
	public string StringValue { get; set; }
	public string DecodedValue { get; set; }
}

public static partial class ElfReader
{
	private const long DtNull = 0;
	private const long DtNeeded = 1;
	private const long DtPltRelSz = 2;
	private const long DtHash = 4;
	private const long DtStrTab = 5;
	private const long DtSymTab = 6;
	private const long DtRela = 7;
	private const long DtRelaSz = 8;
	private const long DtRelaEnt = 9;
	private const long DtStrSz = 10;
	private const long DtSymEnt = 11;
	private const long DtPltGot = 3;
	private const long DtInit = 12;
	private const long DtFini = 13;
	private const long DtSoname = 14;
	private const long DtRPath = 15;
	private const long DtSymbolic = 16;
	private const long DtRel = 17;
	private const long DtRelSz = 18;
	private const long DtRelEnt = 19;
	private const long DtPltRel = 20;
	private const long DtDebug = 21;
	private const long DtTextRel = 22;
	private const long DtJmpRel = 23;
	private const long DtBindNow = 24;
	private const long DtInitArray = 25;
	private const long DtFiniArray = 26;
	private const long DtInitArraySz = 27;
	private const long DtFiniArraySz = 28;
	private const long DtRunPath = 29;
	private const long DtFlags = 30;
	private const long DtEncoding = 31;
	private const long DtPreInitArray = 32;
	private const long DtPreInitArraySz = 33;
	private const long DtSymTabShndx = 34;
	private const long DtRelrSz = 35;
	private const long DtRelr = 36;
	private const long DtRelrEnt = 37;
	private const long DtGnuPrelinked = 0x6FFFFDF5;
	private const long DtGnuConflictSz = 0x6FFFFDF6;
	private const long DtGnuLibListSz = 0x6FFFFDF7;
	private const long DtChecksum = 0x6FFFFDF8;
	private const long DtPltPadSz = 0x6FFFFDF9;
	private const long DtMoveEnt = 0x6FFFFDFA;
	private const long DtMoveSz = 0x6FFFFDFB;
	private const long DtFeature1 = 0x6FFFFDFC;
	private const long DtPosFlag1 = 0x6FFFFDFD;
	private const long DtSymInSz = 0x6FFFFDFE;
	private const long DtSymInEnt = 0x6FFFFDFF;
	private const long DtGnuHash = 0x6FFFFEF5;
	private const long DtTlsDescPlt = 0x6FFFFEF6;
	private const long DtTlsDescGot = 0x6FFFFEF7;
	private const long DtGnuConflict = 0x6FFFFEF8;
	private const long DtGnuLibList = 0x6FFFFEF9;
	private const long DtConfig = 0x6FFFFEFA;
	private const long DtDepAudit = 0x6FFFFEFB;
	private const long DtAudit = 0x6FFFFEFC;
	private const long DtPltPad = 0x6FFFFEFD;
	private const long DtMoveTab = 0x6FFFFEFE;
	private const long DtSymInfo = 0x6FFFFEFF;
	private const long DtFlags1 = 0x6FFFFFFB;
	private const long DtVerDef = 0x6FFFFFFC;
	private const long DtVerDefNum = 0x6FFFFFFD;
	private const long DtVerNeed = 0x6FFFFFFE;
	private const long DtVerNeedNum = 0x6FFFFFFF;
	private const long DtVerSym = 0x6FFFFFF0;
	private const long DtRelaCount = 0x6FFFFFF9;
	private const long DtRelCount = 0x6FFFFFFA;
	private const long DtAuxiliary = 0x7FFFFFFD;
	private const long DtFilter = 0x7FFFFFFF;

	private const long DtMipsRldVersion = 0x70000001;
	private const long DtMipsTimeStamp = 0x70000002;
	private const long DtMipsIchecksum = 0x70000003;
	private const long DtMipsIVersion = 0x70000004;
	private const long DtMipsFlags = 0x70000005;
	private const long DtMipsBaseAddress = 0x70000006;
	private const long DtMipsMsym = 0x70000007;
	private const long DtMipsConflict = 0x70000008;
	private const long DtMipsLibList = 0x70000009;
	private const long DtMipsLocalGotNo = 0x7000000A;
	private const long DtMipsConflictNo = 0x7000000B;
	private const long DtMipsLibListNo = 0x70000010;
	private const long DtMipsSymTabNo = 0x70000011;
	private const long DtMipsUnrefExtNo = 0x70000012;
	private const long DtMipsGotSym = 0x70000013;
	private const long DtMipsHiPageNo = 0x70000014;
	private const long DtMipsRldMap = 0x70000016;
	private const long DtMipsRldMapRel = 0x70000035;
	private const long DtMipsXHash = 0x70000036;

	private const long DtPpcGot = 0x70000000;
	private const long DtPpcOpt = 0x70000001;
	private const long DtPpc64Glink = 0x70000000;
	private const long DtPpc64Opd = 0x70000001;
	private const long DtPpc64OpdSz = 0x70000002;
	private const long DtPpc64Opt = 0x70000003;

	private const long DtValRangeLo = 0x6FFFFD00;
	private const long DtValRangeHi = 0x6FFFFDFF;
	private const long DtAddrRangeLo = 0x6FFFFE00;
	private const long DtAddrRangeHi = 0x6FFFFEFF;
	private const long DtVersionTagLo = 0x6FFFFFF0;
	private const long DtVersionTagHi = 0x6FFFFFFF;
	private const long DtProcRangeLo = 0x70000000;
	private const long DtProcRangeHi = 0x7FFFFFFF;
	private const long DtSparcRegister = 0x70000001;
	private const long DtAArch64BtiPlt = 0x70000001;
	private const long DtAArch64PacPlt = 0x70000003;
	private const long DtAArch64VariantPcs = 0x70000005;
	private const long DtRiscVVariantCc = 0x70000001;

	public static void ParseDynamic(IEndianDataSource data, ElfFile elf)
	{
		elf.DynamicEntries.Clear();
		elf.ImportLibraries.Clear();
		elf.Soname = string.Empty;
		elf.RPath = string.Empty;
		elf.RunPath = string.Empty;

		var parsed = false;
		foreach (var section in elf.Sections)
		{
			if (section.Type != ShtDynamic)
				continue;

			ParseDynamicSection(data, elf, section);
			parsed = true;
		}

		if (!parsed)
			ParseDynamicProgramHeaders(data, elf);

		ResolveDynamicStringValues(data, elf);
		AssignFallbackImportLibraries(elf);
		EnrichDynamicEntrySemantics(elf);
	}

	public static void ParseDynamic(ReadOnlySpan<byte> data, ElfFile elf)
	{
		using var source = ElfDataSourceFactory.CreateInMemory(data);
		ParseDynamic(source, elf);
	}

	private static void ParseDynamicSection(IEndianDataSource data, ElfFile elf, ElfSectionHeader section)
	{
		if (section.Size == 0)
			return;

		var entrySize = section.EntrySize;
		if (entrySize == 0)
			entrySize = elf.Header.Class == ElfClass.Elf32 ? 8UL : 16UL;

		var minEntrySize = elf.Header.Class == ElfClass.Elf32 ? 8UL : 16UL;
		if (entrySize < minEntrySize)
			throw new InvalidDataException("Invalid dynamic entry size.");

		EnsureReadableRange(data, section.Offset, section.Size, "dynamic section");
		var reader = new EndianDataReader(data, elf.Header.IsLittleEndian);
		var neededEntries = new List<ulong>();
		var entryCount = section.Size / entrySize;
		EnsureReasonableEntryCount(entryCount, "dynamic entries");

		for (ulong i = 0; i < entryCount; i++)
		{
			var entryOffset = checked(section.Offset + (i * entrySize));
			reader.Position = entryOffset;

			long tag;
			ulong value;

			if (elf.Header.Class == ElfClass.Elf32)
			{
				tag = unchecked((int)reader.ReadUInt32());
				value = reader.ReadUInt32();
			}
			else
			{
				tag = unchecked((long)reader.ReadUInt64());
				value = reader.ReadUInt64();
			}

			var stringValue = ReadDynamicStringValue(data, elf, section, tag, value);
			var entry = new ElfDynamicEntry
			{
				Tag = tag,
				TagName = GetDynamicTagName(tag, elf.Header.Machine),
				Value = value,
				StringValue = stringValue,
				DecodedValue = DecodeDynamicValue(tag, value, elf.Header.Machine)
			};
			elf.DynamicEntries.Add(entry);

			if (tag == DtNeeded)
				neededEntries.Add(value);

			if (tag == DtSoname)
				elf.Soname = stringValue;
			else if (tag == DtRPath)
				elf.RPath = stringValue;
			else if (tag == DtRunPath)
				elf.RunPath = stringValue;

			if (tag == DtNull)
				break;
		}

		ExtractImports(data, elf, section, neededEntries);
	}

	private static void ParseDynamicProgramHeaders(IEndianDataSource data, ElfFile elf)
	{
		var entrySize = elf.Header.Class == ElfClass.Elf32 ? 8UL : 16UL;

		foreach (var programHeader in elf.ProgramHeaders)
		{
			if (programHeader.Type != PtDynamic || programHeader.FileSize == 0)
				continue;

			EnsureReadableRange(data, programHeader.Offset, programHeader.FileSize, "PT_DYNAMIC");
			var entryCount = programHeader.FileSize / entrySize;
			EnsureReasonableEntryCount(entryCount, "dynamic entries");

			var reader = new EndianDataReader(data, elf.Header.IsLittleEndian);
			for (ulong i = 0; i < entryCount; i++)
			{
				reader.Position = checked(programHeader.Offset + (i * entrySize));

				long tag;
				ulong value;
				if (elf.Header.Class == ElfClass.Elf32)
				{
					tag = unchecked((int)reader.ReadUInt32());
					value = reader.ReadUInt32();
				}
				else
				{
					tag = unchecked((long)reader.ReadUInt64());
					value = reader.ReadUInt64();
				}

				elf.DynamicEntries.Add(new ElfDynamicEntry
				{
					Tag = tag,
					TagName = GetDynamicTagName(tag, elf.Header.Machine),
					Value = value,
					StringValue = string.Empty,
					DecodedValue = DecodeDynamicValue(tag, value, elf.Header.Machine)
				});

				if (tag == DtNull)
					break;
			}
		}
	}

	private static void ResolveDynamicStringValues(IEndianDataSource data, ElfFile elf)
	{
		if (elf.DynamicEntries.Count == 0)
			return;
		if (!TryGetDynamicValue(elf, DtStrTab, out var strTabVirtualAddress))
			return;
		if (!TryVirtualAddressToFileOffset(elf, strTabVirtualAddress, out var strTabFileOffset))
			return;

		var strTabSize = TryGetDynamicValue(elf, DtStrSz, out var configuredSize) ? configuredSize : 0UL;
		if (strTabSize == 0 && TryGetMappedFileRange(elf, strTabVirtualAddress, out _, out var mappedSize))
			strTabSize = mappedSize;
		if (strTabSize == 0)
			return;

		EnsureReadableRange(data, strTabFileOffset, strTabSize, "dynamic string table");

		foreach (var entry in elf.DynamicEntries)
		{
			if (!IsStringDynamicTag(entry.Tag))
				continue;
			if (!string.IsNullOrEmpty(entry.StringValue))
				continue;

			var stringValue = ReadStringFromFileOffset(data, strTabFileOffset, strTabSize, entry.Value);
			entry.StringValue = stringValue;

			if (entry.Tag == DtNeeded && !string.IsNullOrEmpty(stringValue) && !elf.ImportLibraries.Contains(stringValue))
				elf.ImportLibraries.Add(stringValue);
			else if (entry.Tag == DtSoname && string.IsNullOrEmpty(elf.Soname))
				elf.Soname = stringValue;
			else if (entry.Tag == DtRPath && string.IsNullOrEmpty(elf.RPath))
				elf.RPath = stringValue;
			else if (entry.Tag == DtRunPath && string.IsNullOrEmpty(elf.RunPath))
				elf.RunPath = stringValue;
		}
	}

	private static string ReadDynamicStringValue(IEndianDataSource data, ElfFile elf, ElfSectionHeader dynamicSection, long tag, ulong value)
	{
		if (!IsStringDynamicTag(tag))
			return string.Empty;
		if (dynamicSection.Link >= elf.Sections.Count)
			return string.Empty;
		if (value > uint.MaxValue)
			return string.Empty;

		return ReadString(data, elf, dynamicSection.Link, (uint)value);
	}

	private static bool IsStringDynamicTag(long tag)
	{
		return tag is DtNeeded or DtSoname or DtRPath or DtRunPath or DtConfig or DtDepAudit or DtAudit or DtAuxiliary or DtFilter;
	}

	private static void ExtractImports(IEndianDataSource data, ElfFile elf, ElfSectionHeader dynamicSection, List<ulong> neededEntries)
	{
		if (neededEntries.Count == 0)
			return;
		if (dynamicSection.Link >= elf.Sections.Count)
			return;

		foreach (var neededOffset in neededEntries)
		{
			if (neededOffset > uint.MaxValue)
				continue;

			var name = ReadString(data, elf, dynamicSection.Link, (uint)neededOffset);
			if (!string.IsNullOrEmpty(name) && !elf.ImportLibraries.Contains(name))
				elf.ImportLibraries.Add(name);
		}
	}

	private static string GetDynamicTagName(long tag, ushort machine)
	{
		var name = tag switch
		{
			DtNull => "DT_NULL",
			DtNeeded => "DT_NEEDED",
			DtPltRelSz => "DT_PLTRELSZ",
			DtHash => "DT_HASH",
			DtStrTab => "DT_STRTAB",
			DtSymTab => "DT_SYMTAB",
			DtRela => "DT_RELA",
			DtRelaSz => "DT_RELASZ",
			DtRelaEnt => "DT_RELAENT",
			DtPltGot => "DT_PLTGOT",
			DtStrSz => "DT_STRSZ",
			DtSymEnt => "DT_SYMENT",
			DtInit => "DT_INIT",
			DtFini => "DT_FINI",
			DtSoname => "DT_SONAME",
			DtRPath => "DT_RPATH",
			DtSymbolic => "DT_SYMBOLIC",
			DtRel => "DT_REL",
			DtRelSz => "DT_RELSZ",
			DtRelEnt => "DT_RELENT",
			DtPltRel => "DT_PLTREL",
			DtDebug => "DT_DEBUG",
			DtTextRel => "DT_TEXTREL",
			DtJmpRel => "DT_JMPREL",
			DtBindNow => "DT_BIND_NOW",
			DtInitArray => "DT_INIT_ARRAY",
			DtFiniArray => "DT_FINI_ARRAY",
			DtInitArraySz => "DT_INIT_ARRAYSZ",
			DtFiniArraySz => "DT_FINI_ARRAYSZ",
			DtRunPath => "DT_RUNPATH",
			DtFlags => "DT_FLAGS",
			DtEncoding => "DT_ENCODING",
			DtPreInitArray => "DT_PREINIT_ARRAY",
			DtPreInitArraySz => "DT_PREINIT_ARRAYSZ",
			DtSymTabShndx => "DT_SYMTAB_SHNDX",
			DtRelrSz => "DT_RELRSZ",
			DtRelr => "DT_RELR",
			DtRelrEnt => "DT_RELRENT",
			DtGnuPrelinked => "DT_GNU_PRELINKED",
			DtGnuConflictSz => "DT_GNU_CONFLICTSZ",
			DtGnuLibListSz => "DT_GNU_LIBLISTSZ",
			DtChecksum => "DT_CHECKSUM",
			DtPltPadSz => "DT_PLTPADSZ",
			DtMoveEnt => "DT_MOVEENT",
			DtMoveSz => "DT_MOVESZ",
			DtFeature1 => "DT_FEATURE_1",
			DtPosFlag1 => "DT_POSFLAG_1",
			DtSymInSz => "DT_SYMINSZ",
			DtSymInEnt => "DT_SYMINENT",
			DtGnuHash => "DT_GNU_HASH",
			DtTlsDescPlt => "DT_TLSDESC_PLT",
			DtTlsDescGot => "DT_TLSDESC_GOT",
			DtGnuConflict => "DT_GNU_CONFLICT",
			DtGnuLibList => "DT_GNU_LIBLIST",
			DtConfig => "DT_CONFIG",
			DtDepAudit => "DT_DEPAUDIT",
			DtAudit => "DT_AUDIT",
			DtPltPad => "DT_PLTPAD",
			DtMoveTab => "DT_MOVETAB",
			DtSymInfo => "DT_SYMINFO",
			DtVerSym => "DT_VERSYM",
			DtRelaCount => "DT_RELACOUNT",
			DtRelCount => "DT_RELCOUNT",
			DtFlags1 => "DT_FLAGS_1",
			DtVerDef => "DT_VERDEF",
			DtVerDefNum => "DT_VERDEFNUM",
			DtVerNeed => "DT_VERNEED",
			DtVerNeedNum => "DT_VERNEEDNUM",
			DtAuxiliary => "DT_AUXILIARY",
			DtFilter => "DT_FILTER",
			_ => string.Empty
		};

		if (!string.IsNullOrEmpty(name))
			return name;

		var procSpecificName = GetProcessorSpecificDynamicTagName(machine, tag);
		if (!string.IsNullOrEmpty(procSpecificName))
			return procSpecificName;

		if (tag >= DtVersionTagLo && tag <= DtVersionTagHi)
			return $"DT_VERSIONTAG_0x{tag:X}";
		if (tag >= DtAddrRangeLo && tag <= DtAddrRangeHi)
			return $"DT_ADDRTAG_0x{tag:X}";
		if (tag >= DtValRangeLo && tag <= DtValRangeHi)
			return $"DT_VALTAG_0x{tag:X}";
		if (tag >= DtProcRangeLo && tag <= DtProcRangeHi)
			return $"DT_PROC_0x{tag:X}";

		return $"DT_{tag}";
	}

	private static string GetProcessorSpecificDynamicTagName(ushort machine, long tag)
	{
		if (machine == EmMips)
		{
			return tag switch
			{
				DtMipsRldVersion => "DT_MIPS_RLD_VERSION",
				DtMipsTimeStamp => "DT_MIPS_TIME_STAMP",
				DtMipsIchecksum => "DT_MIPS_ICHECKSUM",
				DtMipsIVersion => "DT_MIPS_IVERSION",
				DtMipsFlags => "DT_MIPS_FLAGS",
				DtMipsBaseAddress => "DT_MIPS_BASE_ADDRESS",
				DtMipsMsym => "DT_MIPS_MSYM",
				DtMipsConflict => "DT_MIPS_CONFLICT",
				DtMipsLibList => "DT_MIPS_LIBLIST",
				DtMipsLocalGotNo => "DT_MIPS_LOCAL_GOTNO",
				DtMipsConflictNo => "DT_MIPS_CONFLICTNO",
				DtMipsLibListNo => "DT_MIPS_LIBLISTNO",
				DtMipsSymTabNo => "DT_MIPS_SYMTABNO",
				DtMipsUnrefExtNo => "DT_MIPS_UNREFEXTNO",
				DtMipsGotSym => "DT_MIPS_GOTSYM",
				DtMipsHiPageNo => "DT_MIPS_HIPAGENO",
				DtMipsRldMap => "DT_MIPS_RLD_MAP",
				DtMipsRldMapRel => "DT_MIPS_RLD_MAP_REL",
				DtMipsXHash => "DT_MIPS_XHASH",
				_ => string.Empty
			};
		}

		if (machine == EmPpc)
		{
			return tag switch
			{
				DtPpcGot => "DT_PPC_GOT",
				DtPpcOpt => "DT_PPC_OPT",
				_ => string.Empty
			};
		}

		if (machine == EmPpc64)
		{
			return tag switch
			{
				DtPpc64Glink => "DT_PPC64_GLINK",
				DtPpc64Opd => "DT_PPC64_OPD",
				DtPpc64OpdSz => "DT_PPC64_OPDSZ",
				DtPpc64Opt => "DT_PPC64_OPT",
				_ => string.Empty
			};
		}

		if (machine is EmSparc or EmSparc64)
		{
			return tag switch
			{
				DtSparcRegister => "DT_SPARC_REGISTER",
				_ => string.Empty
			};
		}

		if (machine == EmAArch64)
		{
			return tag switch
			{
				DtAArch64BtiPlt => "DT_AARCH64_BTI_PLT",
				DtAArch64PacPlt => "DT_AARCH64_PAC_PLT",
				DtAArch64VariantPcs => "DT_AARCH64_VARIANT_PCS",
				_ => string.Empty
			};
		}

		if (machine == EmRiscV)
		{
			return tag switch
			{
				DtRiscVVariantCc => "DT_RISCV_VARIANT_CC",
				_ => string.Empty
			};
		}

		return string.Empty;
	}

		private static string DecodeDynamicValue(long tag, ulong value, ushort machine)
		{
			return tag switch
			{
				DtPltRel => DecodePltRelValue(value),
				DtSymbolic or DtTextRel or DtBindNow => DecodePresenceFlag(value),
				DtFlags => DecodeFlags(value, DynamicFlagBits),
				DtFeature1 => DecodeFlags(value, DynamicFeature1Bits),
				DtPosFlag1 => DecodeFlags(value, DynamicPosFlag1Bits),
				DtRelaCount or DtRelCount => value.ToString(),
				DtFlags1 => DecodeFlags(value, DynamicFlag1Bits),
				DtMipsFlags when machine == EmMips => DecodeFlags(value, DynamicMipsFlagBits),
				DtPpcOpt when machine == EmPpc => DecodeFlags(value, DynamicPpcOptBits),
				DtPpc64Opt when machine == EmPpc64 => DecodeFlags(value, DynamicPpc64OptBits),
				DtAArch64BtiPlt when machine == EmAArch64 => DecodeBooleanState(value),
				DtAArch64PacPlt when machine == EmAArch64 => DecodeBooleanState(value),
				DtAArch64VariantPcs when machine == EmAArch64 => DecodeBooleanState(value),
				DtRiscVVariantCc when machine == EmRiscV => DecodeBooleanState(value),
				DtSparcRegister when machine is EmSparc or EmSparc64 => $"register={value}",
			_ => string.Empty
		};
	}

		private static string DecodeBooleanState(ulong value)
		{
			return value == 0 ? "disabled" : "enabled";
		}

		private static string DecodePresenceFlag(ulong value)
		{
			return value == 0 ? "present" : DecodeBooleanState(value);
		}

	private static string DecodePltRelValue(ulong value)
	{
		return value switch
		{
			(ulong)DtRel => "DT_REL",
			(ulong)DtRela => "DT_RELA",
			(ulong)DtRelr => "DT_RELR",
			_ => $"0x{value:X}"
		};
	}

	private static string DecodeFlags(ulong value, (ulong Bit, string Name)[] knownFlags)
	{
		if (value == 0)
			return "0";

		var names = new List<string>();
		var remaining = value;

		foreach (var (bit, name) in knownFlags)
		{
			if ((remaining & bit) == 0)
				continue;

			names.Add(name);
			remaining &= ~bit;
		}

		if (remaining != 0)
			names.Add($"0x{remaining:X}");

		return string.Join("|", names);
	}

	private static readonly (ulong Bit, string Name)[] DynamicFlagBits =
	{
		(0x1, "DF_ORIGIN"),
		(0x2, "DF_SYMBOLIC"),
		(0x4, "DF_TEXTREL"),
		(0x8, "DF_BIND_NOW"),
		(0x10, "DF_STATIC_TLS"),
	};

	private static readonly (ulong Bit, string Name)[] DynamicFlag1Bits =
	{
		(0x1, "DF_1_NOW"),
		(0x2, "DF_1_GLOBAL"),
		(0x4, "DF_1_GROUP"),
		(0x8, "DF_1_NODELETE"),
		(0x10, "DF_1_LOADFLTR"),
		(0x20, "DF_1_INITFIRST"),
		(0x40, "DF_1_NOOPEN"),
		(0x80, "DF_1_ORIGIN"),
		(0x100, "DF_1_DIRECT"),
		(0x200, "DF_1_TRANS"),
		(0x400, "DF_1_INTERPOSE"),
		(0x800, "DF_1_NODEFLIB"),
		(0x1000, "DF_1_NODUMP"),
		(0x2000, "DF_1_CONFALT"),
		(0x4000, "DF_1_ENDFILTEE"),
		(0x8000, "DF_1_DISPRELDNE"),
		(0x10000, "DF_1_DISPRELPND"),
		(0x20000, "DF_1_NODIRECT"),
		(0x40000, "DF_1_IGNMULDEF"),
		(0x80000, "DF_1_NOKSYMS"),
		(0x100000, "DF_1_NOHDR"),
		(0x200000, "DF_1_EDITED"),
		(0x400000, "DF_1_NORELOC"),
		(0x800000, "DF_1_SYMINTPOSE"),
		(0x1000000, "DF_1_GLOBAUDIT"),
		(0x2000000, "DF_1_SINGLETON"),
		(0x4000000, "DF_1_STUB"),
		(0x8000000, "DF_1_PIE"),
	};

	private static readonly (ulong Bit, string Name)[] DynamicFeature1Bits =
	{
		(0x1, "DTF_1_PARINIT"),
		(0x2, "DTF_1_CONFEXP"),
	};

	private static readonly (ulong Bit, string Name)[] DynamicPosFlag1Bits =
	{
		(0x1, "DF_P1_LAZYLOAD"),
		(0x2, "DF_P1_GROUPPERM"),
	};

		private static readonly (ulong Bit, string Name)[] DynamicMipsFlagBits =
		{
		(0x1, "RHF_QUICKSTART"),
		(0x2, "RHF_NOTPOT"),
		(0x4, "RHF_NO_LIBRARY_REPLACEMENT"),
		(0x8, "RHF_NO_MOVE"),
		(0x10, "RHF_SGI_ONLY"),
		(0x20, "RHF_GUARANTEE_INIT"),
		(0x40, "RHF_DELTA_C_PLUS_PLUS"),
		(0x80, "RHF_GUARANTEE_START_INIT"),
		(0x100, "RHF_PIXIE"),
		(0x200, "RHF_DEFAULT_DELAY_LOAD"),
		(0x400, "RHF_REQUICKSTART"),
		(0x800, "RHF_REQUICKSTARTED"),
		(0x1000, "RHF_CORD"),
		(0x2000, "RHF_NO_UNRES_UNDEF"),
			(0x4000, "RHF_RLD_ORDER_SAFE"),
		};

		private static readonly (ulong Bit, string Name)[] DynamicPpcOptBits =
		{
			(0x1, "PPC_OPT_TLS"),
			(0x2, "PPC_OPT_MULTI_TOC"),
		};

		private static readonly (ulong Bit, string Name)[] DynamicPpc64OptBits =
		{
			(0x1, "PPC64_OPT_TLS"),
			(0x2, "PPC64_OPT_MULTI_TOC"),
		};

		private static void EnrichDynamicEntrySemantics(ElfFile elf)
		{
		var wordSize = elf.Header.Class == ElfClass.Elf32 ? 4UL : 8UL;
		var moveEnt = TryGetDynamicValue(elf, DtMoveEnt, out var moveEntValue) ? moveEntValue : 0UL;
		var symInEnt = TryGetDynamicValue(elf, DtSymInEnt, out var symInEntValue) ? symInEntValue : 0UL;
		var relEnt = TryGetDynamicValue(elf, DtRelEnt, out var relEntValue) ? relEntValue : 0UL;
		var relaEnt = TryGetDynamicValue(elf, DtRelaEnt, out var relaEntValue) ? relaEntValue : 0UL;
		var relrEnt = TryGetDynamicValue(elf, DtRelrEnt, out var relrEntValue) ? relrEntValue : 0UL;

		foreach (var entry in elf.DynamicEntries)
		{
			var extra = GetStructuredDynamicValue(elf, entry.Tag, entry.Value, wordSize, elf.Header.Machine);
			if (entry.Tag == DtMoveSz && moveEnt > 0 && entry.Value % moveEnt == 0)
				extra = AppendDetail(extra, $"entries={entry.Value / moveEnt}");
			if (entry.Tag == DtSymInSz && symInEnt > 0 && entry.Value % symInEnt == 0)
				extra = AppendDetail(extra, $"entries={entry.Value / symInEnt}");
			if (entry.Tag == DtRelSz && relEnt > 0 && entry.Value % relEnt == 0)
				extra = AppendDetail(extra, $"entries={entry.Value / relEnt}");
			if (entry.Tag == DtRelaSz && relaEnt > 0 && entry.Value % relaEnt == 0)
				extra = AppendDetail(extra, $"entries={entry.Value / relaEnt}");
			if (entry.Tag == DtRelrSz && relrEnt > 0 && entry.Value % relrEnt == 0)
				extra = AppendDetail(extra, $"entries={entry.Value / relrEnt}");
			if ((entry.Tag == DtInitArraySz || entry.Tag == DtFiniArraySz || entry.Tag == DtPreInitArraySz)
				&& wordSize > 0
				&& entry.Value % wordSize == 0)
			{
				extra = AppendDetail(extra, $"entries={entry.Value / wordSize}");
			}

			if (string.IsNullOrEmpty(extra))
				continue;

			if (string.IsNullOrEmpty(entry.DecodedValue))
			{
				entry.DecodedValue = extra;
			}
				else if (!entry.DecodedValue.Contains(extra, StringComparison.Ordinal))
				{
					entry.DecodedValue = $"{entry.DecodedValue}; {extra}";
				}
			}

			AppendMachineSpecificDynamicCorrelations(elf);
		}

	private static string GetStructuredDynamicValue(ElfFile elf, long tag, ulong value, ulong wordSize, ushort machine)
	{
		if (IsAddressDynamicTag(machine, tag))
		{
			if (TryDescribeVirtualAddress(elf, value, out var description))
				return description;

			return $"addr=0x{value:X}";
		}

		if (IsSizeDynamicTag(machine, tag))
			return $"size={value} (0x{value:X})";

			if (IsEntrySizeDynamicTag(machine, tag))
				return $"entry_size={value}";

			if (TryGetProcessorSpecificDynamicValue(machine, tag, value, out var machineSpecific))
				return machineSpecific;

			if (IsCountDynamicTag(machine, tag))
				return $"count={value}";

		if (tag == DtChecksum)
			return $"checksum=0x{value:X}";

		if (tag == DtGnuPrelinked)
		{
			return $"timestamp={FormatUnixTimestamp(value)}";
		}

			if (tag >= DtAddrRangeLo && tag <= DtAddrRangeHi)
		{
			if (TryDescribeVirtualAddress(elf, value, out var description))
				return description;

			return $"addr=0x{value:X}";
		}

		if (tag >= DtValRangeLo && tag <= DtValRangeHi)
			return $"value=0x{value:X}";

			if (tag >= DtProcRangeLo && tag <= DtProcRangeHi)
				return $"proc_tag=0x{tag:X}, value=0x{value:X}";

			return string.Empty;
		}

	private static string FormatUnixTimestamp(ulong value)
	{
		if (value <= long.MaxValue)
		{
			try
			{
				var utc = DateTimeOffset.FromUnixTimeSeconds((long)value).UtcDateTime;
				return $"{utc:yyyy-MM-dd HH:mm:ss} UTC";
			}
			catch (ArgumentOutOfRangeException)
			{
				// Keep raw timestamp value for out-of-range values.
			}
		}

		return value.ToString();
	}

		private static bool TryGetProcessorSpecificDynamicValue(ushort machine, long tag, ulong value, out string decoded)
		{
			decoded = string.Empty;
			if (machine == EmMips)
			{
				switch (tag)
				{
					case DtMipsIchecksum:
						decoded = $"checksum=0x{value:X}";
						return true;
					case DtMipsTimeStamp:
						decoded = $"timestamp={FormatUnixTimestamp(value)}";
						return true;
					case DtMipsRldVersion:
					case DtMipsIVersion:
						decoded = $"version={value}";
						return true;
					case DtMipsMsym:
						decoded = $"symbol_index={value}";
						return true;
					case DtMipsLocalGotNo:
						decoded = $"local_got_entries={value}";
						return true;
					case DtMipsGotSym:
						decoded = $"first_global_got_symbol={value}";
						return true;
					case DtMipsSymTabNo:
						decoded = $"dynamic_symbol_count={value}";
						return true;
					case DtMipsConflictNo:
						decoded = $"conflict_count={value}";
						return true;
					case DtMipsLibListNo:
						decoded = $"liblist_count={value}";
						return true;
					case DtMipsUnrefExtNo:
						decoded = $"unresolved_external_count={value}";
						return true;
					case DtMipsHiPageNo:
						decoded = $"got_hi_page_count={value}";
						return true;
					case DtMipsRldMapRel:
						decoded = $"relative_offset=0x{value:X}";
						return true;
				}
			}
			else if (machine is EmSparc or EmSparc64)
			{
			if (tag == DtSparcRegister)
			{
				decoded = $"register={value}";
				return true;
			}
			}
			else if (machine == EmPpc)
			{
				if (tag == DtPpcOpt)
				{
					decoded = DecodeFlags(value, DynamicPpcOptBits);
					return true;
				}
			}
			else if (machine == EmPpc64)
			{
				if (tag == DtPpc64Opt)
				{
					decoded = DecodeFlags(value, DynamicPpc64OptBits);
					return true;
				}
			}
			else if (machine == EmAArch64)
			{
			if (tag is DtAArch64BtiPlt or DtAArch64PacPlt or DtAArch64VariantPcs)
			{
				decoded = DecodeBooleanState(value);
				return true;
			}
		}
		else if (machine == EmRiscV)
		{
			if (tag == DtRiscVVariantCc)
			{
				decoded = value switch
				{
					0 => "default_abi",
					1 => "variant_cc",
					_ => $"variant=0x{value:X}"
				};
				return true;
			}
		}

			return false;
		}

		private static void AppendMachineSpecificDynamicCorrelations(ElfFile elf)
		{
			if (elf.Header.Machine != EmMips)
				return;

			if (!TryGetDynamicValue(elf, DtMipsLocalGotNo, out var localGotEntries))
				return;
			if (!TryGetDynamicValue(elf, DtMipsGotSym, out var firstGlobalGotSymbol))
				return;
			if (!TryGetDynamicValue(elf, DtMipsSymTabNo, out var dynamicSymbolCount))
				return;
			if (dynamicSymbolCount < firstGlobalGotSymbol)
				return;

			var globalGotEntries = dynamicSymbolCount - firstGlobalGotSymbol;
			AppendDynamicDetailByTag(elf, DtMipsLocalGotNo, $"global_got_entries={globalGotEntries}");
			AppendDynamicDetailByTag(elf, DtMipsSymTabNo, $"got_coverage={localGotEntries + globalGotEntries}");
		}

		private static void AppendDynamicDetailByTag(ElfFile elf, long tag, string detail)
		{
			if (string.IsNullOrEmpty(detail))
				return;

			for (var i = 0; i < elf.DynamicEntries.Count; i++)
			{
				var entry = elf.DynamicEntries[i];
				if (entry.Tag != tag)
					continue;

				entry.DecodedValue = AppendDetail(entry.DecodedValue, detail);
			}
		}

	private static bool TryDescribeVirtualAddress(ElfFile elf, ulong address, out string description)
	{
		description = $"addr=0x{address:X}";
		if (address == 0)
			return true;

		if (!TryVirtualAddressToFileOffset(elf, address, out var fileOffset))
			return true;

		description = $"{description}, file_off=0x{fileOffset:X}";
		var sectionName = ResolveAllocatedSectionNameByVirtualAddress(elf, address);
		if (!string.IsNullOrEmpty(sectionName))
			description = $"{description}, section={sectionName}";

		return true;
	}

	private static string ResolveAllocatedSectionNameByVirtualAddress(ElfFile elf, ulong address)
	{
		if (address == 0)
			return string.Empty;

		const ulong shfAlloc = 0x2;
		foreach (var section in elf.Sections)
		{
			if ((section.Flags & shfAlloc) == 0 || section.Size == 0)
				continue;

			var start = section.Address;
			var end = start + section.Size;
			if (end < start)
				end = ulong.MaxValue;
			if (address < start || address >= end)
				continue;

			return section.Name ?? string.Empty;
		}

		return string.Empty;
	}

	private static string AppendDetail(string source, string detail)
	{
		if (string.IsNullOrEmpty(detail))
			return source;
		if (string.IsNullOrEmpty(source))
			return detail;
		if (source.Contains(detail, StringComparison.Ordinal))
			return source;

		return $"{source}, {detail}";
	}

	private static bool IsAddressDynamicTag(ushort machine, long tag)
	{
		if (tag is
			DtHash or DtStrTab or DtSymTab or DtRela or DtRel or DtPltGot or DtInit or DtFini or DtJmpRel
			or DtInitArray or DtFiniArray or DtPreInitArray or DtRelr
			or DtGnuHash or DtTlsDescPlt or DtTlsDescGot or DtGnuConflict or DtGnuLibList or DtConfig
			or DtDepAudit or DtAudit or DtPltPad or DtMoveTab or DtSymInfo
			or DtVerSym or DtVerDef or DtVerNeed)
		{
			return true;
		}

		return machine switch
		{
			EmMips => tag is DtMipsBaseAddress or DtMipsConflict or DtMipsLibList or DtMipsRldMap or DtMipsRldMapRel or DtMipsXHash,
			EmPpc => tag == DtPpcGot,
			EmPpc64 => tag is DtPpc64Glink or DtPpc64Opd,
			_ => false
		};
	}

	private static bool IsSizeDynamicTag(ushort machine, long tag)
	{
		if (tag is
			DtPltRelSz or DtRelaSz or DtRelSz or DtStrSz or DtInitArraySz or DtFiniArraySz or DtPreInitArraySz
			or DtRelrSz or DtGnuConflictSz or DtGnuLibListSz or DtPltPadSz or DtMoveSz or DtSymInSz)
		{
			return true;
		}

		return machine == EmPpc64 && tag == DtPpc64OpdSz;
	}

	private static bool IsEntrySizeDynamicTag(ushort machine, long tag)
	{
		return tag is DtSymEnt or DtRelaEnt or DtRelEnt or DtRelrEnt or DtMoveEnt or DtSymInEnt;
	}

	private static bool IsCountDynamicTag(ushort machine, long tag)
	{
		if (tag is DtRelCount or DtRelaCount or DtVerNeedNum or DtVerDefNum)
			return true;

		return machine == EmMips
			&& tag is DtMipsLocalGotNo or DtMipsConflictNo or DtMipsLibListNo or DtMipsSymTabNo or DtMipsUnrefExtNo or DtMipsGotSym or DtMipsHiPageNo;
	}

	private static bool TryGetDynamicValue(ElfFile elf, long tag, out ulong value)
	{
		foreach (var entry in elf.DynamicEntries)
		{
			if (entry.Tag != tag)
				continue;

			value = entry.Value;
			return true;
		}

		value = 0;
		return false;
	}

	private static void AssignFallbackImportLibraries(ElfFile elf)
	{
		if (elf.ImportLibraries.Count != 1)
			return;

		var fallbackLibrary = elf.ImportLibraries[0];
		foreach (var symbol in elf.ImportedSymbols)
		{
			if (string.IsNullOrEmpty(symbol.LibraryName))
				symbol.LibraryName = fallbackLibrary;
		}
	}
}
