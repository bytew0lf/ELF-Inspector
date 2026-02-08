namespace ELFInspector.Parser;

public static partial class ElfReader
{
	private const ushort ShnXIndex = 0xFFFF;
	private const ushort PnXNum = 0xFFFF;

	private const uint ShtSymTab = 2;
	private const uint ShtRela = 4;
	private const uint ShtDynamic = 6;
	private const uint ShtNote = 7;
	private const uint ShtRel = 9;
	private const uint ShtDynSym = 11;
	private const uint ShtSymTabShndx = 18;
	private const uint ShtRelr = 19;
	private const uint ShtGnuVerDef = 0x6FFFFFFD;
	private const uint ShtGnuVerNeed = 0x6FFFFFFE;
	private const uint ShtGnuVerSym = 0x6FFFFFFF;

	private const uint PtLoad = 1;
	private const uint PtDynamic = 2;
	private const uint PtInterp = 3;
	private const uint PtNote = 4;
	private const ulong MaxInterpreterPathProbeBytes = 16UL * 1024UL;

	private static void ParseSectionHeaders(IEndianDataSource data, ElfFile elf)
	{
		var header = elf.Header;
		if (header.SectionHeaderOffset == 0 || header.SectionHeaderEntrySize == 0)
			return;

		var minimumSize = header.Class == ElfClass.Elf32 ? 40 : 64;
		if (header.SectionHeaderEntrySize < minimumSize)
			throw new InvalidDataException("Invalid section header entry size.");

		ulong sectionCount = header.SectionHeaderCount;
		uint shStringIndex = header.SectionHeaderStringIndex;

		// Extended numbering values are stored in section header #0.
		var sectionZero = ReadSectionHeaderEntry(data, header, 0);
		if (sectionCount == 0)
			sectionCount = sectionZero.Size;
		if (shStringIndex == ShnXIndex)
			shStringIndex = sectionZero.Link;

		var sectionTableSize = checked(sectionCount * header.SectionHeaderEntrySize);
		EnsureReadableRange(data, header.SectionHeaderOffset, sectionTableSize, "section header table");
		EnsureReasonableEntryCount(sectionCount, "section headers");

		for (ulong i = 0; i < sectionCount; i++)
		{
			var sh = ReadSectionHeaderEntry(data, header, i);
			elf.Sections.Add(sh);
		}

		if (shStringIndex >= elf.Sections.Count)
			return;

		for (var i = 0; i < elf.Sections.Count; i++)
		{
			var section = elf.Sections[i];
			section.Name = ReadString(data, elf, shStringIndex, section.NameIndex);
		}
	}

	private static ElfSectionHeader ReadSectionHeaderEntry(IEndianDataSource data, ElfHeader header, ulong index)
	{
		var entryOffset = checked(header.SectionHeaderOffset + (index * header.SectionHeaderEntrySize));
		EnsureReadableRange(data, entryOffset, header.SectionHeaderEntrySize, "section header");

		var reader = new EndianDataReader(data, header.IsLittleEndian)
		{
			Position = entryOffset
		};

		if (header.Class == ElfClass.Elf32)
		{
			return new ElfSectionHeader
			{
				NameIndex = reader.ReadUInt32(),
				Type = reader.ReadUInt32(),
				Flags = reader.ReadUInt32(),
				Address = reader.ReadUInt32(),
				Offset = reader.ReadUInt32(),
				Size = reader.ReadUInt32(),
				Link = reader.ReadUInt32(),
				Info = reader.ReadUInt32(),
				AddressAlign = reader.ReadUInt32(),
				EntrySize = reader.ReadUInt32()
			};
		}

		return new ElfSectionHeader
		{
			NameIndex = reader.ReadUInt32(),
			Type = reader.ReadUInt32(),
			Flags = reader.ReadUInt64(),
			Address = reader.ReadUInt64(),
			Offset = reader.ReadUInt64(),
			Size = reader.ReadUInt64(),
			Link = reader.ReadUInt32(),
			Info = reader.ReadUInt32(),
			AddressAlign = reader.ReadUInt64(),
			EntrySize = reader.ReadUInt64()
		};
	}

	private static void ParseProgramHeaders(IEndianDataSource data, ElfFile elf)
	{
		var header = elf.Header;
		if (header.ProgramHeaderOffset == 0 || header.ProgramHeaderEntrySize == 0)
			return;

		var minimumSize = header.Class == ElfClass.Elf32 ? 32 : 56;
		if (header.ProgramHeaderEntrySize < minimumSize)
			throw new InvalidDataException("Invalid program header entry size.");

		ulong programHeaderCount = header.ProgramHeaderCount;
		if (programHeaderCount == PnXNum && elf.Sections.Count > 0)
			programHeaderCount = elf.Sections[0].Info;

		var programTableSize = checked(programHeaderCount * header.ProgramHeaderEntrySize);
		EnsureReadableRange(data, header.ProgramHeaderOffset, programTableSize, "program header table");
		EnsureReasonableEntryCount(programHeaderCount, "program headers");

		for (ulong i = 0; i < programHeaderCount; i++)
		{
			var ph = ReadProgramHeaderEntry(data, header, i);
			elf.ProgramHeaders.Add(ph);
		}

		ResolveInterpreterPath(data, elf);
	}

	private static ElfProgramHeader ReadProgramHeaderEntry(IEndianDataSource data, ElfHeader header, ulong index)
	{
		var entryOffset = checked(header.ProgramHeaderOffset + (index * header.ProgramHeaderEntrySize));
		EnsureReadableRange(data, entryOffset, header.ProgramHeaderEntrySize, "program header");

		var reader = new EndianDataReader(data, header.IsLittleEndian)
		{
			Position = entryOffset
		};

		if (header.Class == ElfClass.Elf32)
		{
			return new ElfProgramHeader
			{
				Type = reader.ReadUInt32(),
				Offset = reader.ReadUInt32(),
				VirtualAddress = reader.ReadUInt32(),
				PhysicalAddress = reader.ReadUInt32(),
				FileSize = reader.ReadUInt32(),
				MemorySize = reader.ReadUInt32(),
				Flags = reader.ReadUInt32(),
				Align = reader.ReadUInt32()
			};
		}

		return new ElfProgramHeader
		{
			Type = reader.ReadUInt32(),
			Flags = reader.ReadUInt32(),
			Offset = reader.ReadUInt64(),
			VirtualAddress = reader.ReadUInt64(),
			PhysicalAddress = reader.ReadUInt64(),
			FileSize = reader.ReadUInt64(),
			MemorySize = reader.ReadUInt64(),
			Align = reader.ReadUInt64()
		};
	}

	private static void ResolveInterpreterPath(IEndianDataSource data, ElfFile elf)
	{
		var interp = elf.ProgramHeaders.FirstOrDefault(ph => ph.Type == PtInterp);
		if (interp == null || interp.FileSize == 0)
			return;

		EnsureReadableRange(data, interp.Offset, interp.FileSize, "PT_INTERP");
		var bytesToRead = Math.Min(interp.FileSize, MaxInterpreterPathProbeBytes);
		if (!TryGetManagedBufferLength(bytesToRead, "PT_INTERP", out var probeLength, out _))
			return;

		var probe = new byte[probeLength];
		data.ReadAt(interp.Offset, probe);

		var end = Array.IndexOf(probe, (byte)0);
		if (end < 0)
			end = probe.Length;

		elf.InterpreterPath = Encoding.ASCII.GetString(probe.AsSpan(0, end));
	}
}
