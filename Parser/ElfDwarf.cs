namespace ELFInspector.Parser;

/// <summary>
/// Represents a public API member.
/// </summary>
public static partial class ElfReader
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public static void ParseDwarfIndex(IEndianDataSource data, ElfFile elf)
	{
		var dwarf = new ElfDwarfIndexInfo();

		var debugInfoSection = FindDebugSection(elf, ".debug_info");
		var debugAbbrevSection = FindDebugSection(elf, ".debug_abbrev");
		var debugLineSection = FindDebugSection(elf, ".debug_line");
		var debugStrSection = FindDebugSection(elf, ".debug_str");
		var debugRangesSection = FindDebugSection(elf, ".debug_ranges");
		var debugAddrSection = FindDebugSection(elf, ".debug_addr");
		var debugStrOffsetsSection = FindDebugSection(elf, ".debug_str_offsets");
		var debugRngListsSection = FindDebugSection(elf, ".debug_rnglists");
		var debugLocListsSection = FindDebugSection(elf, ".debug_loclists");

		dwarf.HasDebugInfo = debugInfoSection != null;
		dwarf.HasDebugAbbrev = debugAbbrevSection != null;
		dwarf.HasDebugLine = debugLineSection != null;
		dwarf.HasDebugStr = debugStrSection != null;
		dwarf.HasDebugRanges = debugRangesSection != null;
		dwarf.HasDebugAddr = debugAddrSection != null;
		dwarf.HasDebugStrOffsets = debugStrOffsetsSection != null;
		dwarf.HasDebugRngLists = debugRngListsSection != null;
		dwarf.HasDebugLocLists = debugLocListsSection != null;

		if (debugInfoSection != null
			&& TryReadSectionPayload(
				data,
				elf,
				debugInfoSection,
				out var infoPayload,
				out _,
				out _,
				out _,
				out _,
				out _,
				out _))
		{
			ParseDwarfCompileUnits(infoPayload, elf.Header.IsLittleEndian, dwarf.CompileUnits);
		}

		if (debugLineSection != null
			&& TryReadSectionPayload(
				data,
				elf,
				debugLineSection,
				out var linePayload,
				out _,
				out _,
				out _,
				out _,
				out _,
				out _))
		{
			ParseDwarfLineTables(linePayload, elf.Header.IsLittleEndian, dwarf.LineTables);
		}

		ParseDwarfSemantics(data, elf, dwarf, debugInfoSection, debugAbbrevSection);

		elf.Dwarf = dwarf;
	}

	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public static void ParseDwarfIndex(ReadOnlySpan<byte> data, ElfFile elf)
	{
		using var source = ElfDataSourceFactory.CreateInMemory(data);
		ParseDwarfIndex(source, elf);
	}

	private static ElfSectionHeader FindDebugSection(ElfFile elf, string canonicalName)
	{
		var zdebugName = ".z" + canonicalName.TrimStart('.');
		return elf.Sections.FirstOrDefault(section =>
			string.Equals(section.Name, canonicalName, StringComparison.Ordinal)
			|| string.Equals(section.Name, zdebugName, StringComparison.Ordinal));
	}

	private static void ParseDwarfCompileUnits(ReadOnlySpan<byte> payload, bool isLittleEndian, List<ElfDwarfCompileUnitInfo> result)
	{
		result.Clear();
		var cursor = 0;
		var iterations = 0UL;

		while (cursor + 4 <= payload.Length && iterations < MaxParserEntryCount)
		{
			iterations++;
			var unitOffset = cursor;
			if (!TryReadDwarfUnitLength(payload, isLittleEndian, ref cursor, out var unitLength, out var isDwarf64))
				break;
			if (unitLength == 0)
				break;
			if (!TryGetUnitEnd(payload.Length, cursor, unitLength, out var unitEnd))
				break;
			if (cursor + 2 > unitEnd)
				break;

			var version = ReadUInt16WithEndian(payload.Slice(cursor, 2), isLittleEndian);
			cursor += 2;

			byte? unitType = null;
			ulong abbrevOffset;
			byte addressSize;

			if (version >= 5)
			{
				if (cursor + 2 > unitEnd)
					break;
				unitType = payload[cursor++];
				addressSize = payload[cursor++];
				if (!TryReadDwarfOffset(payload, isLittleEndian, isDwarf64, ref cursor, unitEnd, out abbrevOffset))
					break;
			}
			else
			{
				if (!TryReadDwarfOffset(payload, isLittleEndian, isDwarf64, ref cursor, unitEnd, out abbrevOffset))
					break;
				if (cursor + 1 > unitEnd)
					break;
				addressSize = payload[cursor++];
			}

			result.Add(new ElfDwarfCompileUnitInfo
			{
				Offset = (ulong)unitOffset,
				UnitLength = unitLength,
				IsDwarf64 = isDwarf64,
				Version = version,
				UnitType = unitType,
				AbbrevOffset = abbrevOffset,
				AddressSize = addressSize
			});

			cursor = unitEnd;
		}
	}

	private static void ParseDwarfLineTables(ReadOnlySpan<byte> payload, bool isLittleEndian, List<ElfDwarfLineTableInfo> result)
	{
		result.Clear();
		var cursor = 0;
		var iterations = 0UL;

		while (cursor + 4 <= payload.Length && iterations < MaxParserEntryCount)
		{
			iterations++;
			var unitOffset = cursor;
			if (!TryReadDwarfUnitLength(payload, isLittleEndian, ref cursor, out var unitLength, out var isDwarf64))
				break;
			if (unitLength == 0)
				break;
			if (!TryGetUnitEnd(payload.Length, cursor, unitLength, out var unitEnd))
				break;
			if (cursor + 2 > unitEnd)
				break;

			var version = ReadUInt16WithEndian(payload.Slice(cursor, 2), isLittleEndian);
			cursor += 2;

			byte addressSize = 0;
			byte segmentSelectorSize = 0;
			if (version >= 5)
			{
				if (cursor + 2 > unitEnd)
					break;
				addressSize = payload[cursor++];
				segmentSelectorSize = payload[cursor++];
			}

			if (!TryReadDwarfOffset(payload, isLittleEndian, isDwarf64, ref cursor, unitEnd, out var headerLength))
				break;
			if (headerLength > (ulong)(unitEnd - cursor))
				break;

			var minimumInstructionLength = ReadByteIfInBounds(payload, ref cursor, unitEnd);
			if (!minimumInstructionLength.HasValue)
				break;
			var maximumOperationsPerInstruction = (byte)1;
			if (version >= 4)
			{
				var maxOps = ReadByteIfInBounds(payload, ref cursor, unitEnd);
				if (!maxOps.HasValue)
					break;
				maximumOperationsPerInstruction = maxOps.Value;
			}

			var defaultIsStmt = ReadByteIfInBounds(payload, ref cursor, unitEnd);
			var lineBaseRaw = ReadByteIfInBounds(payload, ref cursor, unitEnd);
			var lineRange = ReadByteIfInBounds(payload, ref cursor, unitEnd);
			var opcodeBase = ReadByteIfInBounds(payload, ref cursor, unitEnd);
			if (!defaultIsStmt.HasValue || !lineBaseRaw.HasValue || !lineRange.HasValue || !opcodeBase.HasValue)
				break;

			var standardOpcodeLengthCount = Math.Max(0, opcodeBase.Value - 1);
			if (cursor + standardOpcodeLengthCount > unitEnd)
				break;
			cursor += standardOpcodeLengthCount;

			ulong includeDirectoryCount = 0;
			ulong fileNameEntryCount = 0;
			if (version <= 4)
			{
				if (!TryParseDwarfLineTableV4EntryCounts(payload, ref cursor, unitEnd, out includeDirectoryCount, out fileNameEntryCount))
				{
					includeDirectoryCount = 0;
					fileNameEntryCount = 0;
				}
			}
			else
			{
				if (!TryParseDwarfLineTableV5EntryCounts(payload, isLittleEndian, isDwarf64, ref cursor, unitEnd, addressSize, out includeDirectoryCount, out fileNameEntryCount))
				{
					includeDirectoryCount = 0;
					fileNameEntryCount = 0;
				}
			}

			result.Add(new ElfDwarfLineTableInfo
			{
				Offset = (ulong)unitOffset,
				UnitLength = unitLength,
				IsDwarf64 = isDwarf64,
				Version = version,
				AddressSize = addressSize,
				SegmentSelectorSize = segmentSelectorSize,
				HeaderLength = headerLength,
				MinimumInstructionLength = minimumInstructionLength.Value,
				MaximumOperationsPerInstruction = maximumOperationsPerInstruction,
				DefaultIsStmt = defaultIsStmt.Value != 0,
				LineBase = unchecked((sbyte)lineBaseRaw.Value),
				LineRange = lineRange.Value,
				OpcodeBase = opcodeBase.Value,
				IncludeDirectoryCount = includeDirectoryCount,
				FileNameEntryCount = fileNameEntryCount
			});

			cursor = unitEnd;
		}
	}

	private static bool TryParseDwarfLineTableV4EntryCounts(
		ReadOnlySpan<byte> payload,
		ref int cursor,
		int unitEnd,
		out ulong includeDirectoryCount,
		out ulong fileNameEntryCount)
	{
		includeDirectoryCount = 0;
		fileNameEntryCount = 0;

		while (cursor < unitEnd)
		{
			if (!TryReadNullTerminatedAscii(payload, ref cursor, unitEnd, out var directory))
				return false;
			if (string.IsNullOrEmpty(directory))
				break;

			includeDirectoryCount++;
		}

		while (cursor < unitEnd)
		{
			if (!TryReadNullTerminatedAscii(payload, ref cursor, unitEnd, out var fileName))
				return false;
			if (string.IsNullOrEmpty(fileName))
				break;
			if (!TryReadUleb128Bounded(payload, ref cursor, unitEnd, out _))
				return false;
			if (!TryReadUleb128Bounded(payload, ref cursor, unitEnd, out _))
				return false;
			if (!TryReadUleb128Bounded(payload, ref cursor, unitEnd, out _))
				return false;

			fileNameEntryCount++;
		}

		return true;
	}

	private static bool TryParseDwarfLineTableV5EntryCounts(
		ReadOnlySpan<byte> payload,
		bool isLittleEndian,
		bool isDwarf64,
		ref int cursor,
		int unitEnd,
		byte addressSize,
		out ulong includeDirectoryCount,
		out ulong fileNameEntryCount)
	{
		includeDirectoryCount = 0;
		fileNameEntryCount = 0;

		if (!TryReadLineTableFormats(payload, ref cursor, unitEnd, out var directoryForms))
			return false;
		if (!TryReadUleb128Bounded(payload, ref cursor, unitEnd, out includeDirectoryCount))
			return false;
		for (ulong i = 0; i < includeDirectoryCount; i++)
		{
			for (var formIndex = 0; formIndex < directoryForms.Count; formIndex++)
			{
				if (!TrySkipDwarfFormValue(payload, isLittleEndian, isDwarf64, ref cursor, unitEnd, addressSize, directoryForms[formIndex]))
					return false;
			}
		}

		if (!TryReadLineTableFormats(payload, ref cursor, unitEnd, out var fileForms))
			return false;
		if (!TryReadUleb128Bounded(payload, ref cursor, unitEnd, out fileNameEntryCount))
			return false;

		return true;
	}

	private static bool TryReadLineTableFormats(ReadOnlySpan<byte> payload, ref int cursor, int unitEnd, out List<ulong> forms)
	{
		forms = new List<ulong>();
		if (!TryReadUleb128Bounded(payload, ref cursor, unitEnd, out var formatCount))
			return false;

		for (ulong i = 0; i < formatCount; i++)
		{
			if (!TryReadUleb128Bounded(payload, ref cursor, unitEnd, out _))
				return false;
			if (!TryReadUleb128Bounded(payload, ref cursor, unitEnd, out var form))
				return false;

			forms.Add(form);
		}

		return true;
	}

	private static bool TrySkipDwarfFormValue(
		ReadOnlySpan<byte> payload,
		bool isLittleEndian,
		bool isDwarf64,
		ref int cursor,
		int unitEnd,
		byte addressSize,
		ulong form)
	{
		var offsetSize = isDwarf64 ? 8 : 4;
		switch (form)
		{
			case 0x01: // DW_FORM_addr
				return TryAdvance(ref cursor, unitEnd, addressSize == 0 ? offsetSize : addressSize);
				case 0x03: // DW_FORM_block2
					if (!TryReadUnsigned(payload, isLittleEndian, ref cursor, unitEnd, 2, out var block2Len))
						return false;
					return TryAdvance(ref cursor, unitEnd, (int)block2Len);
				case 0x04: // DW_FORM_block4
					if (!TryReadUnsigned(payload, isLittleEndian, ref cursor, unitEnd, 4, out var block4Len))
						return false;
					return TryAdvance(ref cursor, unitEnd, block4Len);
			case 0x05: // DW_FORM_data2
				return TryAdvance(ref cursor, unitEnd, 2);
			case 0x06: // DW_FORM_data4
				return TryAdvance(ref cursor, unitEnd, 4);
			case 0x07: // DW_FORM_data8
				return TryAdvance(ref cursor, unitEnd, 8);
				case 0x08: // DW_FORM_string
					return TryReadNullTerminatedAscii(payload, ref cursor, unitEnd, out _);
				case 0x09: // DW_FORM_block
					if (!TryReadUleb128Bounded(payload, ref cursor, unitEnd, out var blockLen))
						return false;
					return TryAdvance(ref cursor, unitEnd, blockLen);
			case 0x0A: // DW_FORM_block1
				if (!TryReadUnsigned(payload, isLittleEndian, ref cursor, unitEnd, 1, out var block1Len))
					return false;
				return TryAdvance(ref cursor, unitEnd, (int)block1Len);
			case 0x0B: // DW_FORM_data1
			case 0x0C: // DW_FORM_flag
				return TryAdvance(ref cursor, unitEnd, 1);
			case 0x0D: // DW_FORM_sdata
				return TryReadSleb128Bounded(payload, ref cursor, unitEnd, out _);
			case 0x0E: // DW_FORM_strp
			case 0x17: // DW_FORM_sec_offset
			case 0x1F: // DW_FORM_line_strp
				return TryAdvance(ref cursor, unitEnd, offsetSize);
			case 0x0F: // DW_FORM_udata
			case 0x15: // DW_FORM_ref_udata
			case 0x1A: // DW_FORM_strx
			case 0x1B: // DW_FORM_addrx
			case 0x22: // DW_FORM_loclistx
			case 0x23: // DW_FORM_rnglistx
				return TryReadUleb128Bounded(payload, ref cursor, unitEnd, out _);
			case 0x1C: // DW_FORM_ref_sup4
				return TryAdvance(ref cursor, unitEnd, 4);
			case 0x1D: // DW_FORM_strp_sup
				return TryAdvance(ref cursor, unitEnd, offsetSize);
			case 0x10: // DW_FORM_ref_addr
				return TryAdvance(ref cursor, unitEnd, offsetSize);
			case 0x11: // DW_FORM_ref1
				return TryAdvance(ref cursor, unitEnd, 1);
			case 0x12: // DW_FORM_ref2
				return TryAdvance(ref cursor, unitEnd, 2);
			case 0x13: // DW_FORM_ref4
				return TryAdvance(ref cursor, unitEnd, 4);
			case 0x14: // DW_FORM_ref8
			case 0x20: // DW_FORM_ref_sig8
				return TryAdvance(ref cursor, unitEnd, 8);
				case 0x16: // DW_FORM_indirect
					if (!TryReadUleb128Bounded(payload, ref cursor, unitEnd, out var actualForm))
						return false;
					return TrySkipDwarfFormValue(payload, isLittleEndian, isDwarf64, ref cursor, unitEnd, addressSize, actualForm);
				case 0x18: // DW_FORM_exprloc
					if (!TryReadUleb128Bounded(payload, ref cursor, unitEnd, out var exprLen))
						return false;
					return TryAdvance(ref cursor, unitEnd, exprLen);
			case 0x19: // DW_FORM_flag_present
			case 0x21: // DW_FORM_implicit_const
				return true;
			case 0x24: // DW_FORM_ref_sup8
				return TryAdvance(ref cursor, unitEnd, 8);
			case 0x1E: // DW_FORM_data16
				return TryAdvance(ref cursor, unitEnd, 16);
			case 0x25: // DW_FORM_strx1
			case 0x29: // DW_FORM_addrx1
				return TryAdvance(ref cursor, unitEnd, 1);
			case 0x26: // DW_FORM_strx2
			case 0x2A: // DW_FORM_addrx2
				return TryAdvance(ref cursor, unitEnd, 2);
			case 0x27: // DW_FORM_strx3
			case 0x2B: // DW_FORM_addrx3
				return TryAdvance(ref cursor, unitEnd, 3);
			case 0x28: // DW_FORM_strx4
			case 0x2C: // DW_FORM_addrx4
				return TryAdvance(ref cursor, unitEnd, 4);
			default:
			{
				if (TryReadUleb128Bounded(payload, ref cursor, unitEnd, out _))
					return true;

				return TryAdvance(ref cursor, unitEnd, 1);
			}
		}
	}

	private static bool TryReadDwarfUnitLength(
		ReadOnlySpan<byte> payload,
		bool isLittleEndian,
		ref int cursor,
		out ulong unitLength,
		out bool isDwarf64)
	{
		unitLength = 0;
		isDwarf64 = false;
		if (cursor + 4 > payload.Length)
			return false;

		var initialLength = ReadUInt32WithEndian(payload.Slice(cursor, 4), isLittleEndian);
		cursor += 4;
		if (initialLength == uint.MaxValue)
		{
			if (cursor + 8 > payload.Length)
				return false;
			unitLength = ReadUInt64WithEndian(payload.Slice(cursor, 8), isLittleEndian);
			cursor += 8;
			isDwarf64 = true;
			return true;
		}

		unitLength = initialLength;
		return true;
	}

	private static bool TryReadDwarfOffset(
		ReadOnlySpan<byte> payload,
		bool isLittleEndian,
		bool isDwarf64,
		ref int cursor,
		int unitEnd,
		out ulong value)
	{
		value = 0;
		if (isDwarf64)
		{
			if (cursor + 8 > unitEnd)
				return false;
			value = ReadUInt64WithEndian(payload.Slice(cursor, 8), isLittleEndian);
			cursor += 8;
			return true;
		}

		if (cursor + 4 > unitEnd)
			return false;
		value = ReadUInt32WithEndian(payload.Slice(cursor, 4), isLittleEndian);
		cursor += 4;
		return true;
	}

	private static bool TryGetUnitEnd(int payloadLength, int contentCursor, ulong unitLength, out int unitEnd)
	{
		unitEnd = 0;
		if (unitLength > (ulong)(payloadLength - contentCursor))
			return false;

		unitEnd = checked(contentCursor + (int)unitLength);
		return unitEnd >= contentCursor && unitEnd <= payloadLength;
	}

	private static bool TryReadUleb128Bounded(ReadOnlySpan<byte> payload, ref int cursor, int unitEnd, out ulong value)
	{
		value = 0;
		var shift = 0;
		while (cursor < unitEnd && shift <= 63)
		{
			var b = payload[cursor++];
			value |= (ulong)(b & 0x7F) << shift;
			if ((b & 0x80) == 0)
				return true;
			shift += 7;
		}

		return false;
	}

	private static bool TryReadSleb128Bounded(ReadOnlySpan<byte> payload, ref int cursor, int unitEnd, out long value)
	{
		value = 0;
		var shift = 0;
		byte b;
		do
		{
			if (cursor >= unitEnd || shift > 63)
				return false;

			b = payload[cursor++];
			value |= ((long)(b & 0x7F)) << shift;
			shift += 7;
		}
		while ((b & 0x80) != 0);

		if (shift < 64 && (b & 0x40) != 0)
			value |= -1L << shift;

		return true;
	}

	private static bool TryReadNullTerminatedAscii(ReadOnlySpan<byte> payload, ref int cursor, int unitEnd, out string value)
	{
		value = string.Empty;
		if (cursor >= unitEnd)
			return false;

		var local = payload.Slice(cursor, unitEnd - cursor);
		var zeroIndex = local.IndexOf((byte)0);
		if (zeroIndex < 0)
			return false;

		value = Encoding.ASCII.GetString(local.Slice(0, zeroIndex));
		cursor = checked(cursor + zeroIndex + 1);
		return true;
	}

	private static byte? ReadByteIfInBounds(ReadOnlySpan<byte> payload, ref int cursor, int unitEnd)
	{
		if (cursor >= unitEnd)
			return null;

		return payload[cursor++];
	}

	private static bool TryReadUnsigned(
		ReadOnlySpan<byte> payload,
		bool isLittleEndian,
		ref int cursor,
		int unitEnd,
		int size,
		out ulong value)
	{
		value = 0;
		if (size <= 0 || cursor + size > unitEnd)
			return false;

		switch (size)
		{
			case 1:
				value = payload[cursor];
				break;
			case 2:
				value = ReadUInt16WithEndian(payload.Slice(cursor, 2), isLittleEndian);
				break;
			case 4:
				value = ReadUInt32WithEndian(payload.Slice(cursor, 4), isLittleEndian);
				break;
			case 8:
				value = ReadUInt64WithEndian(payload.Slice(cursor, 8), isLittleEndian);
				break;
			default:
				return false;
		}

		cursor += size;
		return true;
	}

	private static bool TryAdvance(ref int cursor, int unitEnd, int count)
	{
		if (count < 0)
			return false;

		return TryAdvance(ref cursor, unitEnd, (ulong)count);
	}

	private static bool TryAdvance(ref int cursor, int unitEnd, ulong count)
	{
		if (cursor < 0 || unitEnd < cursor)
			return false;

		var remaining = (ulong)(unitEnd - cursor);
		if (count > remaining)
			return false;

		cursor += (int)count;
		return true;
	}
}
