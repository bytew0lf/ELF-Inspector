namespace ELFInspector.Parser;

public static partial class ElfReader
{
	private const byte DwEhPeOmit = 0xFF;
	private const byte DwEhPeAbsPtr = 0x00;
	private const byte DwEhPeUleb128 = 0x01;
	private const byte DwEhPeUData2 = 0x02;
	private const byte DwEhPeUData4 = 0x03;
	private const byte DwEhPeUData8 = 0x04;
	private const byte DwEhPeSleb128 = 0x09;
	private const byte DwEhPeSData2 = 0x0A;
	private const byte DwEhPeSData4 = 0x0B;
	private const byte DwEhPeSData8 = 0x0C;
	private const byte DwEhPeFormatMask = 0x0F;
	private const byte DwEhPePcrel = 0x10;
	private const byte DwEhPeTextRel = 0x20;
	private const byte DwEhPeDataRel = 0x30;
	private const byte DwEhPeFuncrel = 0x40;
	private const byte DwEhPeAligned = 0x50;
	private const byte DwEhPeApplicationMask = 0x70;
	private const byte DwEhPeIndirect = 0x80;

	private const byte DwCfaNop = 0x00;
	private const byte DwCfaSetLoc = 0x01;
	private const byte DwCfaAdvanceLoc1 = 0x02;
	private const byte DwCfaAdvanceLoc2 = 0x03;
	private const byte DwCfaAdvanceLoc4 = 0x04;
	private const byte DwCfaOffsetExtended = 0x05;
	private const byte DwCfaRestoreExtended = 0x06;
	private const byte DwCfaUndefined = 0x07;
	private const byte DwCfaSameValue = 0x08;
	private const byte DwCfaRegister = 0x09;
	private const byte DwCfaRememberState = 0x0A;
	private const byte DwCfaRestoreState = 0x0B;
	private const byte DwCfaDefCfa = 0x0C;
	private const byte DwCfaDefCfaRegister = 0x0D;
	private const byte DwCfaDefCfaOffset = 0x0E;
	private const byte DwCfaDefCfaExpression = 0x0F;
	private const byte DwCfaExpression = 0x10;
	private const byte DwCfaOffsetExtendedSf = 0x11;
	private const byte DwCfaDefCfaSf = 0x12;
	private const byte DwCfaDefCfaOffsetSf = 0x13;
	private const byte DwCfaValOffset = 0x14;
	private const byte DwCfaValOffsetSf = 0x15;
	private const byte DwCfaValExpression = 0x16;
	private const byte DwCfaGnuWindowSave = 0x2D;
	private const byte DwCfaGnuArgsSize = 0x2E;
	private const byte DwCfaGnuNegativeOffsetExtended = 0x2F;

	private sealed class CfiInterpreterState
	{
		public bool HasCfaRule { get; set; }
		public ulong CfaRegister { get; set; }
		public long CfaOffset { get; set; }
		public bool HasReturnAddressOffset { get; set; }
		public long ReturnAddressOffset { get; set; }

		public CfiInterpreterState Clone()
		{
			return new CfiInterpreterState
			{
				HasCfaRule = HasCfaRule,
				CfaRegister = CfaRegister,
				CfaOffset = CfaOffset,
				HasReturnAddressOffset = HasReturnAddressOffset,
				ReturnAddressOffset = ReturnAddressOffset
			};
		}
	}

	private sealed class EhFrameCieParseState
	{
		public ulong EntryOffset { get; set; }
		public int Index { get; set; }
		public ulong CodeAlignmentFactor { get; set; }
		public long DataAlignmentFactor { get; set; }
		public ulong ReturnAddressRegister { get; set; }
		public byte FdePointerEncoding { get; set; } = DwEhPeAbsPtr;
		public bool HasAugmentationData { get; set; }
		public CfiInterpreterState InitialState { get; } = new();
	}

	public static void ParseUnwindData(IEndianDataSource data, ElfFile elf)
	{
		var unwind = new ElfUnwindInfo();
		ParseEhFrameData(data, elf, unwind.EhFrame);
		ParseEhFrameHeaderData(data, elf, unwind.EhFrameHeader);
		ParseDebugSections(data, elf, unwind.DebugSections);
		elf.Unwind = unwind;
	}

	public static void ParseUnwindData(ReadOnlySpan<byte> data, ElfFile elf)
	{
		using var source = ElfDataSourceFactory.CreateInMemory(data);
		ParseUnwindData(source, elf);
	}

	private static void ParseEhFrameData(IEndianDataSource data, ElfFile elf, ElfEhFrameInfo result)
	{
		var ehFrameSection = elf.Sections.FirstOrDefault(section => string.Equals(section.Name, ".eh_frame", StringComparison.Ordinal));
		if (ehFrameSection == null)
			return;

		result.Present = true;
		result.Address = ehFrameSection.Address;
		result.Size = ehFrameSection.Size;

		if (!TryReadSectionPayload(
			data,
			elf,
			ehFrameSection,
			out var payload,
			out _,
			out _,
			out _,
			out _,
			out _,
			out _))
		{
			return;
		}

		var wordSize = elf.Header.Class == ElfClass.Elf64 ? 8 : 4;
		ParseEhFrameEntries(payload, elf.Header.IsLittleEndian, wordSize, ehFrameSection.Address, result);
	}

	private static void ParseEhFrameEntries(
		ReadOnlySpan<byte> payload,
		bool isLittleEndian,
		int wordSize,
		ulong sectionAddress,
		ElfEhFrameInfo result)
	{
		result.CieEntries.Clear();
		result.FdeEntries.Clear();
		result.CieCount = 0;
		result.FdeCount = 0;
		result.TerminatorSeen = false;

		var cieByOffset = new Dictionary<ulong, EhFrameCieParseState>();
		var cursor = 0;
		var iteration = 0UL;
		while (cursor + 4 <= payload.Length && iteration < MaxParserEntryCount)
		{
			iteration++;
			var entryOffset = (ulong)cursor;
			var length32 = ReadUInt32WithEndian(payload.Slice(cursor, 4), isLittleEndian);
			cursor += 4;

			if (length32 == 0)
			{
				result.TerminatorSeen = true;
				break;
			}

			var isDwarf64 = false;
			ulong contentLength = length32;
			if (length32 == uint.MaxValue)
			{
				if (cursor + 8 > payload.Length)
					break;

				contentLength = ReadUInt64WithEndian(payload.Slice(cursor, 8), isLittleEndian);
				cursor += 8;
				isDwarf64 = true;
			}

			if (contentLength < 4UL)
				break;

			if (contentLength > int.MaxValue)
				break;
			var contentLengthInt = (int)contentLength;
			if (cursor + contentLengthInt > payload.Length)
				break;

			var contentStart = cursor;
			var contentEnd = cursor + contentLengthInt;
			var id = ReadUInt32WithEndian(payload.Slice(contentStart, 4), isLittleEndian);
			if (id == 0)
			{
				var cieInfo = new ElfEhFrameCieInfo
				{
					Index = result.CieEntries.Count,
					Offset = entryOffset,
					ContentLength = contentLength,
					IsDwarf64 = isDwarf64,
					CieId = id,
					Augmentation = string.Empty
				};

				if (TryParseEhFrameCie(
					payload,
					isLittleEndian,
					wordSize,
					sectionAddress,
					contentStart,
					contentEnd,
					cieInfo,
					out var cieState))
				{
					result.CieEntries.Add(cieInfo);
					cieByOffset[cieState.EntryOffset] = cieState;
				}
			}
			else
			{
				var fdeInfo = new ElfEhFrameFdeInfo
				{
					Index = result.FdeEntries.Count,
					Offset = entryOffset,
					ContentLength = contentLength,
					IsDwarf64 = isDwarf64,
					CiePointer = id
				};
				TryParseEhFrameFde(
					payload,
					isLittleEndian,
					wordSize,
					sectionAddress,
					contentStart,
					contentEnd,
					id,
					cieByOffset,
					fdeInfo);
				result.FdeEntries.Add(fdeInfo);
			}

			cursor = contentEnd;
		}

		result.CieCount = (uint)result.CieEntries.Count;
		result.FdeCount = (uint)result.FdeEntries.Count;
	}

	private static bool TryParseEhFrameCie(
		ReadOnlySpan<byte> payload,
		bool isLittleEndian,
		int wordSize,
		ulong sectionAddress,
		int contentStart,
		int contentEnd,
		ElfEhFrameCieInfo cieInfo,
		out EhFrameCieParseState cieState)
	{
		cieState = new EhFrameCieParseState
		{
			EntryOffset = cieInfo.Offset,
			Index = cieInfo.Index
		};

		var cursor = checked(contentStart + 4); // skip CIE ID
		if (cursor >= contentEnd)
			return false;

		cieInfo.Version = payload[cursor++];
		if (!TryReadNullTerminatedAsciiEh(payload, ref cursor, contentEnd, out var augmentation))
			return false;
		cieInfo.Augmentation = augmentation;

		if (!TryReadUleb128Bounded(payload, ref cursor, contentEnd, out var codeAlign))
			return false;
		if (!TryReadSleb128Bounded(payload, ref cursor, contentEnd, out var dataAlign))
			return false;
		cieInfo.CodeAlignmentFactor = codeAlign;
		cieInfo.DataAlignmentFactor = dataAlign;
		cieState.CodeAlignmentFactor = codeAlign;
		cieState.DataAlignmentFactor = dataAlign;

		ulong returnAddressRegister;
		if (cieInfo.Version == 1)
		{
			if (cursor >= contentEnd)
				return false;
			returnAddressRegister = payload[cursor++];
		}
		else
		{
			if (!TryReadUleb128Bounded(payload, ref cursor, contentEnd, out returnAddressRegister))
				return false;
		}
		cieInfo.ReturnAddressRegister = returnAddressRegister;
		cieState.ReturnAddressRegister = returnAddressRegister;

		var pointerEncoding = DwEhPeAbsPtr;
		if (!TryParseCieAugmentationData(
			payload,
			isLittleEndian,
			wordSize,
			sectionAddress,
			augmentation,
			ref cursor,
			contentEnd,
			ref pointerEncoding))
		{
			return false;
		}

		cieInfo.FdePointerEncoding = pointerEncoding;
		cieState.FdePointerEncoding = pointerEncoding;
		cieState.HasAugmentationData = !string.IsNullOrEmpty(augmentation) && augmentation[0] == 'z';

		ParseCfiInstructions(
			payload,
			ref cursor,
			contentEnd,
			isLittleEndian,
			wordSize,
			codeAlign,
			dataAlign,
			returnAddressRegister,
			cieState.InitialState,
			cieInfo.Instructions);

		return true;
	}

	private static bool TryParseEhFrameFde(
		ReadOnlySpan<byte> payload,
		bool isLittleEndian,
		int wordSize,
		ulong sectionAddress,
		int contentStart,
		int contentEnd,
		uint ciePointer,
		Dictionary<ulong, EhFrameCieParseState> cieByOffset,
		ElfEhFrameFdeInfo fdeInfo)
	{
		var cursor = checked(contentStart + 4); // skip CIE pointer field
		var cieOffset = ciePointer <= (uint)contentStart ? (ulong)(contentStart - (int)ciePointer) : ulong.MaxValue;
		cieByOffset.TryGetValue(cieOffset, out var cieState);
		if (cieState != null)
			fdeInfo.CieIndex = cieState.Index;

		var pointerEncoding = cieState?.FdePointerEncoding ?? DwEhPeAbsPtr;
		if (pointerEncoding == DwEhPeOmit)
			pointerEncoding = DwEhPeAbsPtr;

		if (!TryReadEhEncodedPointer(
			payload,
			isLittleEndian,
			wordSize,
			pointerEncoding,
			sectionAddress,
			sectionAddress,
			ref cursor,
			out var initialLocation))
		{
			return false;
		}
		fdeInfo.InitialLocation = initialLocation;

		if (!TryReadEhFrameAddressRange(payload, isLittleEndian, wordSize, pointerEncoding, ref cursor, out var addressRange))
			return false;
		fdeInfo.AddressRange = addressRange;
		try
		{
			fdeInfo.EndLocation = checked(initialLocation + addressRange);
		}
		catch (OverflowException)
		{
			fdeInfo.EndLocation = ulong.MaxValue;
		}

		if (cieState?.HasAugmentationData == true && !SkipFdeAugmentationIfPresent(payload, ref cursor, contentEnd))
			return false;

		var finalState = cieState?.InitialState.Clone() ?? new CfiInterpreterState();
		ParseCfiInstructions(
			payload,
			ref cursor,
			contentEnd,
			isLittleEndian,
			wordSize,
			cieState?.CodeAlignmentFactor ?? 1,
			cieState?.DataAlignmentFactor ?? -1,
			cieState?.ReturnAddressRegister ?? 0,
			finalState,
			fdeInfo.Instructions);

		fdeInfo.CfaRuleAvailable = finalState.HasCfaRule;
		fdeInfo.CfaRegister = finalState.CfaRegister;
		fdeInfo.CfaOffset = finalState.CfaOffset;
		fdeInfo.ReturnAddressOffsetAvailable = finalState.HasReturnAddressOffset;
		fdeInfo.ReturnAddressOffset = finalState.ReturnAddressOffset;
		return true;
	}

	private static bool TryReadNullTerminatedAsciiEh(ReadOnlySpan<byte> payload, ref int cursor, int end, out string value)
	{
		value = string.Empty;
		if (cursor < 0 || cursor >= end)
			return false;

		var start = cursor;
		while (cursor < end && payload[cursor] != 0)
			cursor++;
		if (cursor >= end)
			return false;

		value = Encoding.ASCII.GetString(payload.Slice(start, cursor - start));
		cursor++;
		return true;
	}

	private static bool TryParseCieAugmentationData(
		ReadOnlySpan<byte> payload,
		bool isLittleEndian,
		int wordSize,
		ulong sectionAddress,
		string augmentation,
		ref int cursor,
		int contentEnd,
		ref byte pointerEncoding)
	{
		if (string.IsNullOrEmpty(augmentation) || augmentation[0] != 'z')
			return true;

		if (!TryReadUleb128Bounded(payload, ref cursor, contentEnd, out var augmentationLength))
			return false;
		if (augmentationLength > int.MaxValue)
			return false;
		var length = (int)augmentationLength;
		if (length > contentEnd - cursor)
			return false;

		var augmentationEnd = cursor + length;
		for (var i = 1; i < augmentation.Length && cursor <= augmentationEnd; i++)
		{
			switch (augmentation[i])
			{
				case 'R':
					if (cursor >= augmentationEnd)
						return false;
					pointerEncoding = payload[cursor++];
					break;
				case 'L':
					if (cursor >= augmentationEnd)
						return false;
					cursor++;
					break;
				case 'P':
					if (cursor >= augmentationEnd)
						return false;
					var personalityEncoding = payload[cursor++];
					if (!TryReadEhEncodedPointer(
						payload,
						isLittleEndian,
						wordSize,
						personalityEncoding,
						sectionAddress,
						sectionAddress,
						ref cursor,
						out _))
					{
						return false;
					}
					break;
				case 'S':
					break;
				default:
					break;
			}
		}

		cursor = augmentationEnd;
		return true;
	}

	private static bool SkipFdeAugmentationIfPresent(ReadOnlySpan<byte> payload, ref int cursor, int contentEnd)
	{
		if (!TryReadUleb128Bounded(payload, ref cursor, contentEnd, out var augmentationLength))
			return false;
		if (augmentationLength > int.MaxValue)
			return false;
		var length = (int)augmentationLength;
		if (length > contentEnd - cursor)
			return false;

		cursor += length;
		return true;
	}

	private static bool TryReadEhFrameAddressRange(
		ReadOnlySpan<byte> payload,
		bool isLittleEndian,
		int wordSize,
		byte pointerEncoding,
		ref int cursor,
		out ulong value)
	{
		value = 0;
		var format = (byte)(pointerEncoding & DwEhPeFormatMask);
		if (format == DwEhPeOmit)
			return false;

		if (format == DwEhPeAbsPtr)
			return TryReadUnsignedWord(payload, isLittleEndian, wordSize, ref cursor, out value);

		if (!TryReadEhEncodedInteger(payload, isLittleEndian, wordSize, format, ref cursor, out var unsignedValue, out var signedValue, out var isSigned))
			return false;

		if (!isSigned)
		{
			value = unsignedValue;
			return true;
		}

		if (signedValue < 0)
			return false;

		value = (ulong)signedValue;
		return true;
	}

	private static void ParseCfiInstructions(
		ReadOnlySpan<byte> payload,
		ref int cursor,
		int end,
		bool isLittleEndian,
		int wordSize,
		ulong codeAlignmentFactor,
		long dataAlignmentFactor,
		ulong returnAddressRegister,
		CfiInterpreterState state,
		List<string> instructions)
	{
		instructions.Clear();
		var savedStates = new Stack<CfiInterpreterState>();
		var iterations = 0UL;

		while (cursor < end && iterations < MaxParserEntryCount)
		{
			iterations++;
			var opcode = payload[cursor++];

			if ((opcode & 0xC0) == 0x40)
			{
				var delta = (uint)(opcode & 0x3F);
				instructions.Add($"DW_CFA_advance_loc {delta}");
				continue;
			}

			if ((opcode & 0xC0) == 0x80)
			{
				var register = (ulong)(opcode & 0x3F);
				if (!TryReadUleb128Bounded(payload, ref cursor, end, out var rawOffset))
				{
					AppendTruncated("DW_CFA_offset");
					break;
				}
				var offset = MultiplyAlign(rawOffset, dataAlignmentFactor);
				if (register == returnAddressRegister)
				{
					state.HasReturnAddressOffset = true;
					state.ReturnAddressOffset = offset;
				}

				instructions.Add($"DW_CFA_offset r{register}, {offset}");
				continue;
			}

			if ((opcode & 0xC0) == 0xC0)
			{
				var register = (ulong)(opcode & 0x3F);
				instructions.Add($"DW_CFA_restore r{register}");
				continue;
			}

			switch (opcode)
			{
				case DwCfaNop:
					instructions.Add("DW_CFA_nop");
					break;
				case DwCfaSetLoc:
					if (!TryReadUnsignedWord(payload, isLittleEndian, wordSize, ref cursor, out var loc))
					{
						AppendTruncated("DW_CFA_set_loc");
						break;
					}
					instructions.Add($"DW_CFA_set_loc 0x{loc:X}");
					break;
				case DwCfaAdvanceLoc1:
				{
					if (!TryReadUnsigned(payload, isLittleEndian, ref cursor, end, 1, out var delta))
					{
						AppendTruncated("DW_CFA_advance_loc1");
						break;
					}
					instructions.Add($"DW_CFA_advance_loc1 {delta}");
					break;
				}
				case DwCfaAdvanceLoc2:
				{
					if (!TryReadUnsigned(payload, isLittleEndian, ref cursor, end, 2, out var delta))
					{
						AppendTruncated("DW_CFA_advance_loc2");
						break;
					}
					instructions.Add($"DW_CFA_advance_loc2 {delta}");
					break;
				}
				case DwCfaAdvanceLoc4:
				{
					if (!TryReadUnsigned(payload, isLittleEndian, ref cursor, end, 4, out var delta))
					{
						AppendTruncated("DW_CFA_advance_loc4");
						break;
					}
					instructions.Add($"DW_CFA_advance_loc4 {delta}");
					break;
				}
				case DwCfaOffsetExtended:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var register))
					{
						AppendTruncated("DW_CFA_offset_extended");
						break;
					}
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var rawOffset))
					{
						AppendTruncated("DW_CFA_offset_extended");
						break;
					}
					var offset = MultiplyAlign(rawOffset, dataAlignmentFactor);
					if (register == returnAddressRegister)
					{
						state.HasReturnAddressOffset = true;
						state.ReturnAddressOffset = offset;
					}
					instructions.Add($"DW_CFA_offset_extended r{register}, {offset}");
					break;
				}
				case DwCfaRestoreExtended:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var register))
					{
						AppendTruncated("DW_CFA_restore_extended");
						break;
					}
					instructions.Add($"DW_CFA_restore_extended r{register}");
					break;
				}
				case DwCfaUndefined:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var register))
					{
						AppendTruncated("DW_CFA_undefined");
						break;
					}
					if (register == returnAddressRegister)
						state.HasReturnAddressOffset = false;
					instructions.Add($"DW_CFA_undefined r{register}");
					break;
				}
				case DwCfaSameValue:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var register))
					{
						AppendTruncated("DW_CFA_same_value");
						break;
					}
					instructions.Add($"DW_CFA_same_value r{register}");
					break;
				}
				case DwCfaRegister:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var register1))
					{
						AppendTruncated("DW_CFA_register");
						break;
					}
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var register2))
					{
						AppendTruncated("DW_CFA_register");
						break;
					}
					instructions.Add($"DW_CFA_register r{register1} -> r{register2}");
					break;
				}
				case DwCfaRememberState:
					savedStates.Push(state.Clone());
					instructions.Add("DW_CFA_remember_state");
					break;
				case DwCfaRestoreState:
					if (savedStates.Count > 0)
					{
						var restored = savedStates.Pop();
						state.HasCfaRule = restored.HasCfaRule;
						state.CfaRegister = restored.CfaRegister;
						state.CfaOffset = restored.CfaOffset;
						state.HasReturnAddressOffset = restored.HasReturnAddressOffset;
						state.ReturnAddressOffset = restored.ReturnAddressOffset;
					}
					instructions.Add("DW_CFA_restore_state");
					break;
				case DwCfaDefCfa:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var register))
					{
						AppendTruncated("DW_CFA_def_cfa");
						break;
					}
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var offset))
					{
						AppendTruncated("DW_CFA_def_cfa");
						break;
					}
					state.HasCfaRule = true;
					state.CfaRegister = register;
					state.CfaOffset = unchecked((long)offset);
					instructions.Add($"DW_CFA_def_cfa r{register}, {offset}");
					break;
				}
				case DwCfaDefCfaRegister:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var register))
					{
						AppendTruncated("DW_CFA_def_cfa_register");
						break;
					}
					state.HasCfaRule = true;
					state.CfaRegister = register;
					instructions.Add($"DW_CFA_def_cfa_register r{register}");
					break;
				}
				case DwCfaDefCfaOffset:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var offset))
					{
						AppendTruncated("DW_CFA_def_cfa_offset");
						break;
					}
					state.HasCfaRule = true;
					state.CfaOffset = unchecked((long)offset);
					instructions.Add($"DW_CFA_def_cfa_offset {offset}");
					break;
				}
				case DwCfaDefCfaExpression:
				{
					if (!TrySkipCfiBlock(payload, ref cursor, end, out var expressionLength))
					{
						AppendTruncated("DW_CFA_def_cfa_expression");
						break;
					}
					state.HasCfaRule = false;
					instructions.Add($"DW_CFA_def_cfa_expression len={expressionLength}");
					break;
				}
				case DwCfaExpression:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var register))
					{
						AppendTruncated("DW_CFA_expression");
						break;
					}
					if (!TrySkipCfiBlock(payload, ref cursor, end, out var expressionLength))
					{
						AppendTruncated("DW_CFA_expression");
						break;
					}
					instructions.Add($"DW_CFA_expression r{register}, len={expressionLength}");
					break;
				}
				case DwCfaOffsetExtendedSf:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var register))
					{
						AppendTruncated("DW_CFA_offset_extended_sf");
						break;
					}
					if (!TryReadSleb128Bounded(payload, ref cursor, end, out var rawOffset))
					{
						AppendTruncated("DW_CFA_offset_extended_sf");
						break;
					}
					var offset = MultiplyAlignSigned(rawOffset, dataAlignmentFactor);
					if (register == returnAddressRegister)
					{
						state.HasReturnAddressOffset = true;
						state.ReturnAddressOffset = offset;
					}
					instructions.Add($"DW_CFA_offset_extended_sf r{register}, {offset}");
					break;
				}
				case DwCfaDefCfaSf:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var register))
					{
						AppendTruncated("DW_CFA_def_cfa_sf");
						break;
					}
					if (!TryReadSleb128Bounded(payload, ref cursor, end, out var rawOffset))
					{
						AppendTruncated("DW_CFA_def_cfa_sf");
						break;
					}
					var offset = MultiplyAlignSigned(rawOffset, dataAlignmentFactor);
					state.HasCfaRule = true;
					state.CfaRegister = register;
					state.CfaOffset = offset;
					instructions.Add($"DW_CFA_def_cfa_sf r{register}, {offset}");
					break;
				}
				case DwCfaDefCfaOffsetSf:
				{
					if (!TryReadSleb128Bounded(payload, ref cursor, end, out var rawOffset))
					{
						AppendTruncated("DW_CFA_def_cfa_offset_sf");
						break;
					}
					var offset = MultiplyAlignSigned(rawOffset, dataAlignmentFactor);
					state.HasCfaRule = true;
					state.CfaOffset = offset;
					instructions.Add($"DW_CFA_def_cfa_offset_sf {offset}");
					break;
				}
				case DwCfaValOffset:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var register))
					{
						AppendTruncated("DW_CFA_val_offset");
						break;
					}
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var rawOffset))
					{
						AppendTruncated("DW_CFA_val_offset");
						break;
					}
					var offset = MultiplyAlign(rawOffset, dataAlignmentFactor);
					if (register == returnAddressRegister)
					{
						state.HasReturnAddressOffset = true;
						state.ReturnAddressOffset = offset;
					}
					instructions.Add($"DW_CFA_val_offset r{register}, {offset}");
					break;
				}
				case DwCfaValOffsetSf:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var register))
					{
						AppendTruncated("DW_CFA_val_offset_sf");
						break;
					}
					if (!TryReadSleb128Bounded(payload, ref cursor, end, out var rawOffset))
					{
						AppendTruncated("DW_CFA_val_offset_sf");
						break;
					}
					var offset = MultiplyAlignSigned(rawOffset, dataAlignmentFactor);
					if (register == returnAddressRegister)
					{
						state.HasReturnAddressOffset = true;
						state.ReturnAddressOffset = offset;
					}
					instructions.Add($"DW_CFA_val_offset_sf r{register}, {offset}");
					break;
				}
				case DwCfaValExpression:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var register))
					{
						AppendTruncated("DW_CFA_val_expression");
						break;
					}
					if (!TrySkipCfiBlock(payload, ref cursor, end, out var expressionLength))
					{
						AppendTruncated("DW_CFA_val_expression");
						break;
					}
					instructions.Add($"DW_CFA_val_expression r{register}, len={expressionLength}");
					break;
				}
				case DwCfaGnuWindowSave:
					instructions.Add("DW_CFA_GNU_window_save");
					break;
				case DwCfaGnuArgsSize:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var size))
					{
						AppendTruncated("DW_CFA_GNU_args_size");
						break;
					}
					instructions.Add($"DW_CFA_GNU_args_size {size}");
					break;
				}
				case DwCfaGnuNegativeOffsetExtended:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var register))
					{
						AppendTruncated("DW_CFA_GNU_negative_offset_extended");
						break;
					}
					if (!TryReadUleb128Bounded(payload, ref cursor, end, out var rawOffset))
					{
						AppendTruncated("DW_CFA_GNU_negative_offset_extended");
						break;
					}
					var offset = -MultiplyAlign(rawOffset, dataAlignmentFactor);
					if (register == returnAddressRegister)
					{
						state.HasReturnAddressOffset = true;
						state.ReturnAddressOffset = offset;
					}
					instructions.Add($"DW_CFA_GNU_negative_offset_extended r{register}, {offset}");
					break;
				}
				default:
					instructions.Add($"DW_CFA_unknown_0x{opcode:X2}");
					break;
			}
		}

		if (iterations >= MaxParserEntryCount && cursor < end)
			instructions.Add("DW_CFA_parser_limit_reached");

		void AppendTruncated(string opcodeName)
		{
			instructions.Add($"{opcodeName} <truncated>");
		}

		static long MultiplyAlign(ulong value, long align)
		{
			if (align == 0 || value == 0)
				return 0;
			if (value > long.MaxValue)
				return align > 0 ? long.MaxValue : long.MinValue;

			try
			{
				return checked((long)value * align);
			}
			catch (OverflowException)
			{
				return align > 0 ? long.MaxValue : long.MinValue;
			}
		}

		static long MultiplyAlignSigned(long value, long align)
		{
			if (align == 0 || value == 0)
				return 0;

			try
			{
				return checked(value * align);
			}
			catch (OverflowException)
			{
				if ((value > 0 && align > 0) || (value < 0 && align < 0))
					return long.MaxValue;
				return long.MinValue;
			}
		}
	}

	private static bool TrySkipCfiBlock(ReadOnlySpan<byte> payload, ref int cursor, int end, out ulong length)
	{
		length = 0;
		if (!TryReadUleb128Bounded(payload, ref cursor, end, out length))
			return false;
		if (length > int.MaxValue)
			return false;
		var blockLength = (int)length;
		if (blockLength > end - cursor)
			return false;

		cursor += blockLength;
		return true;
	}

	private static void ParseEhFrameHeaderData(IEndianDataSource data, ElfFile elf, ElfEhFrameHeaderInfo result)
	{
		var ehFrameHeaderSection = elf.Sections.FirstOrDefault(section => string.Equals(section.Name, ".eh_frame_hdr", StringComparison.Ordinal));
		if (ehFrameHeaderSection == null)
			return;

		result.Present = true;

		if (!TryReadSectionPayload(
			data,
			elf,
			ehFrameHeaderSection,
			out var payload,
			out _,
			out _,
			out _,
			out _,
			out _,
			out _))
		{
			return;
		}

		if (payload.Length < 4)
			return;

		result.Version = payload[0];
		result.EhFramePointerEncoding = payload[1];
		result.FdeCountEncoding = payload[2];
		result.TableEncoding = payload[3];

		var cursor = 4;
		var wordSize = elf.Header.Class == ElfClass.Elf64 ? 8 : 4;

		if (result.EhFramePointerEncoding != DwEhPeOmit
			&& TryReadEhEncodedPointer(
				payload,
				elf.Header.IsLittleEndian,
				wordSize,
				result.EhFramePointerEncoding,
				ehFrameHeaderSection.Address,
				ehFrameHeaderSection.Address,
				ref cursor,
				out var ehFramePointer))
		{
			result.EhFramePointerDecoded = true;
			result.EhFramePointer = ehFramePointer;
		}

		if (result.FdeCountEncoding != DwEhPeOmit
			&& TryReadEhEncodedPointer(
				payload,
				elf.Header.IsLittleEndian,
				wordSize,
				result.FdeCountEncoding,
				ehFrameHeaderSection.Address,
				ehFrameHeaderSection.Address,
				ref cursor,
				out var fdeCount))
		{
			result.FdeCountDecoded = true;
			result.FdeCount = fdeCount;
		}

		if (!result.FdeCountDecoded || result.TableEncoding == DwEhPeOmit)
			return;

		var parsedEntries = 0U;
		var maxEntries = Math.Min(result.FdeCount, 4096UL);
		for (ulong i = 0; i < maxEntries; i++)
		{
			var parsedPc = TryReadEhEncodedPointer(
				payload,
				elf.Header.IsLittleEndian,
				wordSize,
				result.TableEncoding,
				ehFrameHeaderSection.Address,
				ehFrameHeaderSection.Address,
				ref cursor,
				out _);
			var parsedFde = TryReadEhEncodedPointer(
				payload,
				elf.Header.IsLittleEndian,
				wordSize,
				result.TableEncoding,
				ehFrameHeaderSection.Address,
				ehFrameHeaderSection.Address,
				ref cursor,
				out _);
			if (!parsedPc || !parsedFde)
				break;

			parsedEntries++;
		}

		result.ParsedTableEntries = parsedEntries;
	}

	private static bool TryReadEhEncodedPointer(
		ReadOnlySpan<byte> payload,
		bool isLittleEndian,
		int wordSize,
		byte encoding,
		ulong sectionAddress,
		ulong dataRelativeBaseAddress,
		ref int cursor,
		out ulong value)
	{
		value = 0;
		if (encoding == DwEhPeOmit)
			return false;
		if ((encoding & DwEhPeIndirect) != 0)
			return false;

		var format = (byte)(encoding & DwEhPeFormatMask);
		var application = (byte)(encoding & DwEhPeApplicationMask);

		if (application == DwEhPeAligned)
		{
			if (wordSize <= 0)
				return false;

			var mask = wordSize - 1;
			if ((cursor & mask) != 0)
				cursor = checked((cursor + mask) & ~mask);

			format = DwEhPeAbsPtr;
			application = 0;
		}

		if (application is not (0 or DwEhPePcrel or DwEhPeDataRel))
			return false;

		var valueAddress = checked(sectionAddress + (ulong)cursor);

		if (!TryReadEhEncodedInteger(payload, isLittleEndian, wordSize, format, ref cursor, out var unsignedValue, out var signedValue, out var isSigned))
			return false;

		try
		{
			if (application == 0)
			{
				value = isSigned ? unchecked((ulong)signedValue) : unsignedValue;
				return true;
			}

			if (application == DwEhPePcrel)
			{
				var addend = isSigned ? signedValue : unchecked((long)unsignedValue);
				value = unchecked((ulong)(checked((long)valueAddress + addend)));
				return true;
			}

			if (application == DwEhPeDataRel)
			{
				var addend = isSigned ? signedValue : unchecked((long)unsignedValue);
				value = unchecked((ulong)(checked((long)dataRelativeBaseAddress + addend)));
				return true;
			}
		}
		catch (OverflowException)
		{
			return false;
		}

		return false;
	}

	private static bool TryReadEhEncodedInteger(
		ReadOnlySpan<byte> payload,
		bool isLittleEndian,
		int wordSize,
		byte format,
		ref int cursor,
		out ulong unsignedValue,
		out long signedValue,
		out bool isSigned)
	{
		unsignedValue = 0;
		signedValue = 0;
		isSigned = false;

		switch (format)
		{
			case DwEhPeAbsPtr:
				if (!TryReadUnsignedWord(payload, isLittleEndian, wordSize, ref cursor, out unsignedValue))
					return false;
				return true;

			case DwEhPeUleb128:
				if (!TryReadUleb128(payload, ref cursor, out unsignedValue))
					return false;
				return true;

			case DwEhPeUData2:
				if (cursor + 2 > payload.Length)
					return false;
				unsignedValue = ReadUInt16WithEndian(payload.Slice(cursor, 2), isLittleEndian);
				cursor += 2;
				return true;

			case DwEhPeUData4:
				if (cursor + 4 > payload.Length)
					return false;
				unsignedValue = ReadUInt32WithEndian(payload.Slice(cursor, 4), isLittleEndian);
				cursor += 4;
				return true;

			case DwEhPeUData8:
				if (cursor + 8 > payload.Length)
					return false;
				unsignedValue = ReadUInt64WithEndian(payload.Slice(cursor, 8), isLittleEndian);
				cursor += 8;
				return true;

			case DwEhPeSleb128:
				if (!TryReadSleb128(payload, ref cursor, out signedValue))
					return false;
				isSigned = true;
				return true;

			case DwEhPeSData2:
				if (cursor + 2 > payload.Length)
					return false;
				signedValue = ReadInt16WithEndian(payload.Slice(cursor, 2), isLittleEndian);
				cursor += 2;
				isSigned = true;
				return true;

			case DwEhPeSData4:
				if (cursor + 4 > payload.Length)
					return false;
				signedValue = ReadInt32WithEndian(payload.Slice(cursor, 4), isLittleEndian);
				cursor += 4;
				isSigned = true;
				return true;

			case DwEhPeSData8:
				if (cursor + 8 > payload.Length)
					return false;
				signedValue = ReadInt64WithEndian(payload.Slice(cursor, 8), isLittleEndian);
				cursor += 8;
				isSigned = true;
				return true;

			default:
				return false;
		}
	}

	private static bool TryReadUnsignedWord(ReadOnlySpan<byte> payload, bool isLittleEndian, int wordSize, ref int cursor, out ulong value)
	{
		value = 0;
		if (wordSize == 4)
		{
			if (cursor + 4 > payload.Length)
				return false;
			value = ReadUInt32WithEndian(payload.Slice(cursor, 4), isLittleEndian);
			cursor += 4;
			return true;
		}

		if (wordSize == 8)
		{
			if (cursor + 8 > payload.Length)
				return false;
			value = ReadUInt64WithEndian(payload.Slice(cursor, 8), isLittleEndian);
			cursor += 8;
			return true;
		}

		return false;
	}

	private static bool TryReadUleb128(ReadOnlySpan<byte> payload, ref int cursor, out ulong value)
	{
		value = 0;
		var shift = 0;
		while (cursor < payload.Length && shift <= 63)
		{
			var b = payload[cursor++];
			value |= (ulong)(b & 0x7F) << shift;
			if ((b & 0x80) == 0)
				return true;
			shift += 7;
		}

		return false;
	}

	private static bool TryReadSleb128(ReadOnlySpan<byte> payload, ref int cursor, out long value)
	{
		value = 0;
		var shift = 0;
		byte b;
		do
		{
			if (cursor >= payload.Length || shift > 63)
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

	private static ushort ReadUInt16WithEndian(ReadOnlySpan<byte> span, bool isLittleEndian)
	{
		return isLittleEndian
			? BinaryPrimitives.ReadUInt16LittleEndian(span)
			: BinaryPrimitives.ReadUInt16BigEndian(span);
	}

	private static uint ReadUInt32WithEndian(ReadOnlySpan<byte> span, bool isLittleEndian)
	{
		return isLittleEndian
			? BinaryPrimitives.ReadUInt32LittleEndian(span)
			: BinaryPrimitives.ReadUInt32BigEndian(span);
	}

	private static ulong ReadUInt64WithEndian(ReadOnlySpan<byte> span, bool isLittleEndian)
	{
		return isLittleEndian
			? BinaryPrimitives.ReadUInt64LittleEndian(span)
			: BinaryPrimitives.ReadUInt64BigEndian(span);
	}

	private static short ReadInt16WithEndian(ReadOnlySpan<byte> span, bool isLittleEndian)
	{
		return isLittleEndian
			? BinaryPrimitives.ReadInt16LittleEndian(span)
			: BinaryPrimitives.ReadInt16BigEndian(span);
	}

	private static int ReadInt32WithEndian(ReadOnlySpan<byte> span, bool isLittleEndian)
	{
		return isLittleEndian
			? BinaryPrimitives.ReadInt32LittleEndian(span)
			: BinaryPrimitives.ReadInt32BigEndian(span);
	}

	private static long ReadInt64WithEndian(ReadOnlySpan<byte> span, bool isLittleEndian)
	{
		return isLittleEndian
			? BinaryPrimitives.ReadInt64LittleEndian(span)
			: BinaryPrimitives.ReadInt64BigEndian(span);
	}

	private static void ParseDebugSections(IEndianDataSource data, ElfFile elf, List<ElfDebugSectionInfo> result)
	{
		result.Clear();

		foreach (var section in elf.Sections)
		{
			if (string.IsNullOrEmpty(section.Name))
				continue;
			if (!section.Name.StartsWith(".debug_", StringComparison.Ordinal)
				&& !section.Name.StartsWith(".zdebug", StringComparison.Ordinal))
			{
				continue;
			}

			var parsed = TryReadSectionPayload(
				data,
				elf,
				section,
				out var payload,
				out var isCompressed,
				out _,
				out var declaredUncompressedSize,
				out _,
				out _,
				out _);

			var uncompressedSize = parsed
				? (ulong)payload.Length
				: (isCompressed && declaredUncompressedSize != 0 ? declaredUncompressedSize : section.Size);

			result.Add(new ElfDebugSectionInfo
			{
				Name = section.Name,
				Size = section.Size,
				IsCompressed = isCompressed,
				UncompressedSize = uncompressedSize
			});
		}
	}
}
