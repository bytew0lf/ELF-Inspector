namespace ELFInspector.Parser;

public static partial class ElfReader
{
	private const ulong MaxParserEntryCount = 10_000_000;
	private const byte ElfCurrentVersion = 1;
	private const ushort Elf32HeaderSize = 52;
	private const ushort Elf64HeaderSize = 64;
	private const ushort Elf32ProgramHeaderEntrySize = 32;
	private const ushort Elf64ProgramHeaderEntrySize = 56;
	private const ushort Elf32SectionHeaderEntrySize = 40;
	private const ushort Elf64SectionHeaderEntrySize = 64;

	public static ElfFile Parse(ReadOnlySpan<byte> data)
	{
		return Parse(data, ElfParseOptions.StrictDefault);
	}

	public static ElfFile Parse(ReadOnlySpan<byte> data, ElfParseOptions? options)
	{
		options ??= ElfParseOptions.StrictDefault;

		// Check for ELF magic.
		if (data.Length < 16 || data[0] != 0x7F || data[1] != (byte)'E' || data[2] != (byte)'L' || data[3] != (byte)'F')
			throw new InvalidDataException("Not an ELF file");

		var header = new ElfHeader
		{
			Class = (ElfClass)data[4],
			DataEncoding = (ElfData)data[5],
			IdentVersion = data[6],
			OsAbi = data[7],
			AbiVersion = data[8]
		};

		if (header.Class is not (ElfClass.Elf32 or ElfClass.Elf64))
			throw new NotSupportedException("Unsupported ELF class");
		if (header.DataEncoding is not (ElfData.LittleEndian or ElfData.BigEndian))
			throw new NotSupportedException("Unsupported ELF data encoding");
		ValidateHeaderPrefix(data, header, options);

		var reader = new EndianBinaryReader(data, header.IsLittleEndian);

		switch (header.Class)
			{
				case ElfClass.Elf32:
					Parse32(reader, header);
					break;
				case ElfClass.Elf64:
					Parse64(reader, header);
					break;
			}
		ValidateHeaderPostParse(data, header, options);

		var elf = new ElfFile
		{
			Header = header,
			ParseOptions = options
		};

		// Parse order follows gABI relationships between tables.
		ParseSectionHeaders(data, elf);
		ParseProgramHeaders(data, elf);
		ParseDynamic(data, elf);
		ParseSymbolTables(data, elf);
		ParseSectionSpecialCases(data, elf);
		ParseUnwindData(data, elf);
		ParseDwarfIndex(data, elf);
		ParseHashTables(data, elf);
		ParseRelocations(data, elf);
		ParseNotes(data, elf);
		ParseCoreDumpInfo(data, elf);

		return elf;
	}

	private static void Parse32(EndianBinaryReader r, ElfHeader header)
	{
		r.Position = 16;
		header.Type = r.ReadUInt16();
		header.Machine = r.ReadUInt16();
		header.Version = r.ReadUInt32();
		header.EntryPoint = r.ReadUInt32();
		header.ProgramHeaderOffset = r.ReadUInt32();
		header.SectionHeaderOffset = r.ReadUInt32();
		header.Flags = r.ReadUInt32();
		header.HeaderSize = r.ReadUInt16();
		header.ProgramHeaderEntrySize = r.ReadUInt16();
		header.ProgramHeaderCount = r.ReadUInt16();
		header.SectionHeaderEntrySize = r.ReadUInt16();
		header.SectionHeaderCount = r.ReadUInt16();
		header.SectionHeaderStringIndex = r.ReadUInt16();
	}

	private static void Parse64(EndianBinaryReader r, ElfHeader header)
	{
		r.Position = 16;
		header.Type = r.ReadUInt16();
		header.Machine = r.ReadUInt16();
		header.Version = r.ReadUInt32();
		header.EntryPoint = r.ReadUInt64();
		header.ProgramHeaderOffset = r.ReadUInt64();
		header.SectionHeaderOffset = r.ReadUInt64();
		header.Flags = r.ReadUInt32();
		header.HeaderSize = r.ReadUInt16();
		header.ProgramHeaderEntrySize = r.ReadUInt16();
		header.ProgramHeaderCount = r.ReadUInt16();
		header.SectionHeaderEntrySize = r.ReadUInt16();
		header.SectionHeaderCount = r.ReadUInt16();
		header.SectionHeaderStringIndex = r.ReadUInt16();
	}

	private static int ToInt32(ulong value)
	{
		if (value > int.MaxValue)
			throw new InvalidDataException("ELF value exceeds the addressable in-memory buffer range.");

		return (int)value;
	}

	private static void EnsureReadableRange(ReadOnlySpan<byte> data, ulong offset, ulong size, string blockName)
	{
		var dataLength = (ulong)data.Length;
		if (offset > dataLength || size > dataLength - offset)
			throw new InvalidDataException($"ELF {blockName} exceeds file bounds.");
	}

	private static void EnsureReasonableEntryCount(ulong count, string blockName)
	{
		if (count > MaxParserEntryCount)
			throw new InvalidDataException($"ELF {blockName} entry count is unreasonably large.");
	}

	private static ulong AlignUp(ulong value, ulong align)
	{
		if (align == 0)
			return value;

		var remainder = value % align;
		if (remainder == 0)
			return value;

		try
		{
			return checked(value + (align - remainder));
		}
		catch (OverflowException)
		{
			throw new InvalidDataException("ELF alignment overflow.");
		}
	}

	private static void ValidateHeaderPrefix(ReadOnlySpan<byte> data, ElfHeader header, ElfParseOptions options)
	{
		if (options.HeaderValidationMode != ElfHeaderValidationMode.Strict)
			return;

		if (header.IdentVersion != ElfCurrentVersion)
			throw new InvalidDataException($"Unsupported EI_VERSION: {header.IdentVersion}.");

		for (var i = 9; i < 16; i++)
		{
			if (data[i] != 0)
				throw new InvalidDataException($"Invalid ELF identification padding at e_ident[{i}].");
		}
	}

	private static void ValidateHeaderPostParse(ReadOnlySpan<byte> data, ElfHeader header, ElfParseOptions options)
	{
		if (options.HeaderValidationMode != ElfHeaderValidationMode.Strict)
			return;

		if (header.Version != ElfCurrentVersion)
			throw new InvalidDataException($"Unsupported ELF header version (e_version): {header.Version}.");

		var expectedHeaderSize = header.Class == ElfClass.Elf64 ? Elf64HeaderSize : Elf32HeaderSize;
		if (header.HeaderSize != expectedHeaderSize)
			throw new InvalidDataException($"Unexpected ELF header size: {header.HeaderSize} (expected {expectedHeaderSize}).");

		if (header.ProgramHeaderCount != 0)
		{
			var expectedProgramHeaderEntrySize = header.Class == ElfClass.Elf64 ? Elf64ProgramHeaderEntrySize : Elf32ProgramHeaderEntrySize;
			if (header.ProgramHeaderEntrySize != expectedProgramHeaderEntrySize)
			{
				throw new InvalidDataException(
					$"Unexpected program header entry size: {header.ProgramHeaderEntrySize} (expected {expectedProgramHeaderEntrySize}).");
			}

			if (header.ProgramHeaderOffset == 0)
				throw new InvalidDataException("Program header table is declared but e_phoff is zero.");
		}

		if (header.SectionHeaderCount != 0)
		{
			var expectedSectionHeaderEntrySize = header.Class == ElfClass.Elf64 ? Elf64SectionHeaderEntrySize : Elf32SectionHeaderEntrySize;
			if (header.SectionHeaderEntrySize != expectedSectionHeaderEntrySize)
			{
				throw new InvalidDataException(
					$"Unexpected section header entry size: {header.SectionHeaderEntrySize} (expected {expectedSectionHeaderEntrySize}).");
			}

			if (header.SectionHeaderOffset == 0)
				throw new InvalidDataException("Section header table is declared but e_shoff is zero.");
		}

		if (header.HeaderSize > data.Length)
			throw new InvalidDataException("ELF header size exceeds file bounds.");

		ValidateProgramHeaderConsistency(data, header);
		ValidateSectionHeaderConsistency(data, header);
	}

	private static void ValidateProgramHeaderConsistency(ReadOnlySpan<byte> data, ElfHeader header)
	{
		var hasProgramHeaderMetadata = header.ProgramHeaderOffset != 0
			|| header.ProgramHeaderEntrySize != 0
			|| header.ProgramHeaderCount != 0;
		if (!hasProgramHeaderMetadata)
			return;

		if (header.ProgramHeaderOffset == 0)
			throw new InvalidDataException("Program header metadata is present but e_phoff is zero.");
		if (header.ProgramHeaderEntrySize == 0)
			throw new InvalidDataException("Program header metadata is present but e_phentsize is zero.");

		var declaredCount = header.ProgramHeaderCount == PnXNum ? 1UL : header.ProgramHeaderCount;
		if (declaredCount == 0)
			throw new InvalidDataException("Program header metadata is present but e_phnum is zero.");
		if (header.ProgramHeaderCount == PnXNum && (header.SectionHeaderOffset == 0 || header.SectionHeaderEntrySize == 0))
		{
			throw new InvalidDataException("Extended program header numbering requires a readable section header table.");
		}

		EnsureTableReadable(data, header.ProgramHeaderOffset, header.ProgramHeaderEntrySize, declaredCount, "program header table");
	}

	private static void ValidateSectionHeaderConsistency(ReadOnlySpan<byte> data, ElfHeader header)
	{
		var hasSectionHeaderMetadata = header.SectionHeaderOffset != 0
			|| header.SectionHeaderEntrySize != 0
			|| header.SectionHeaderCount != 0
			|| header.SectionHeaderStringIndex != 0;
		if (!hasSectionHeaderMetadata)
			return;

		if (header.SectionHeaderOffset == 0)
			throw new InvalidDataException("Section header metadata is present but e_shoff is zero.");
		if (header.SectionHeaderEntrySize == 0)
			throw new InvalidDataException("Section header metadata is present but e_shentsize is zero.");

		var declaredCount = header.SectionHeaderCount == 0 ? 1UL : header.SectionHeaderCount;
		EnsureTableReadable(data, header.SectionHeaderOffset, header.SectionHeaderEntrySize, declaredCount, "section header table");

		if (header.SectionHeaderCount != 0
			&& header.SectionHeaderStringIndex != 0
			&& header.SectionHeaderStringIndex != ShnXIndex
			&& header.SectionHeaderStringIndex >= header.SectionHeaderCount)
		{
			throw new InvalidDataException("e_shstrndx points beyond the declared section header count.");
		}
	}

	private static void EnsureTableReadable(ReadOnlySpan<byte> data, ulong tableOffset, ushort entrySize, ulong entryCount, string tableName)
	{
		ulong tableSize;
		try
		{
			tableSize = checked((ulong)entrySize * entryCount);
		}
		catch (OverflowException)
		{
			throw new InvalidDataException($"ELF {tableName} size overflows.");
		}

		EnsureReadableRange(data, tableOffset, tableSize, tableName);
	}
}
