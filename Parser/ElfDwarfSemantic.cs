namespace ELFInspector.Parser;

public static partial class ElfReader
{
	private const ulong DwTagCompileUnit = 0x11;
	private const ulong DwTagSubprogram = 0x2E;
	private const ulong DwTagInlinedSubroutine = 0x1D;
	private const ulong DwTagVariable = 0x34;
	private const ulong DwTagFormalParameter = 0x05;
	private const ulong DwTagLabel = 0x0A;
	private const ulong DwTagLexicalBlock = 0x0B;
	private const ulong DwTagNamespace = 0x39;
	private const ulong DwTagStructureType = 0x13;
	private const ulong DwTagClassType = 0x02;
	private const ulong DwTagTypedef = 0x16;

	private const ulong DwAtName = 0x03;
	private const ulong DwAtLocation = 0x02;
	private const ulong DwAtLowPc = 0x11;
	private const ulong DwAtHighPc = 0x12;
	private const ulong DwAtLanguage = 0x13;
	private const ulong DwAtVisibility = 0x17;
	private const ulong DwAtInline = 0x20;
	private const ulong DwAtAccessibility = 0x32;
	private const ulong DwAtCallingConvention = 0x36;
	private const ulong DwAtEncoding = 0x3E;
	private const ulong DwAtVirtuality = 0x4C;
	private const ulong DwAtEndianity = 0x65;
	private const ulong DwAtLinkageName = 0x6E;
	private const ulong DwAtMipsLinkageName = 0x2007;
	private const ulong DwAtRanges = 0x55;
	private const ulong DwAtDeclaration = 0x3C;
	private const ulong DwAtStrOffsetsBase = 0x72;
	private const ulong DwAtAddrBase = 0x73;
	private const ulong DwAtRnglistsBase = 0x74;
	private const ulong DwAtLoclistsBase = 0x8B;

	private const byte DwRleEndOfList = 0x00;
	private const byte DwRleBaseAddressx = 0x01;
	private const byte DwRleStartxEndx = 0x02;
	private const byte DwRleStartxLength = 0x03;
	private const byte DwRleOffsetPair = 0x04;
	private const byte DwRleBaseAddress = 0x05;
	private const byte DwRleStartEnd = 0x06;
	private const byte DwRleStartLength = 0x07;

	private const byte DwLleEndOfList = 0x00;
	private const byte DwLleBaseAddressx = 0x01;
	private const byte DwLleStartxEndx = 0x02;
	private const byte DwLleStartxLength = 0x03;
	private const byte DwLleOffsetPair = 0x04;
	private const byte DwLleDefaultLocation = 0x05;
	private const byte DwLleBaseAddress = 0x06;
	private const byte DwLleStartEnd = 0x07;
	private const byte DwLleStartLength = 0x08;

	private const ulong DwFormAddr = 0x01;
	private const ulong DwFormBlock2 = 0x03;
	private const ulong DwFormBlock4 = 0x04;
	private const ulong DwFormData2 = 0x05;
	private const ulong DwFormData4 = 0x06;
	private const ulong DwFormData8 = 0x07;
	private const ulong DwFormString = 0x08;
	private const ulong DwFormBlock = 0x09;
	private const ulong DwFormBlock1 = 0x0A;
	private const ulong DwFormData1 = 0x0B;
	private const ulong DwFormFlag = 0x0C;
	private const ulong DwFormSData = 0x0D;
	private const ulong DwFormStrp = 0x0E;
	private const ulong DwFormUData = 0x0F;
	private const ulong DwFormRefAddr = 0x10;
	private const ulong DwFormRef1 = 0x11;
	private const ulong DwFormRef2 = 0x12;
	private const ulong DwFormRef4 = 0x13;
	private const ulong DwFormRef8 = 0x14;
	private const ulong DwFormRefUData = 0x15;
	private const ulong DwFormIndirect = 0x16;
	private const ulong DwFormSecOffset = 0x17;
	private const ulong DwFormExprLoc = 0x18;
	private const ulong DwFormFlagPresent = 0x19;
	private const ulong DwFormStrx = 0x1A;
	private const ulong DwFormAddrx = 0x1B;
	private const ulong DwFormRefSup4 = 0x1C;
	private const ulong DwFormStrpSup = 0x1D;
	private const ulong DwFormData16 = 0x1E;
	private const ulong DwFormLineStrp = 0x1F;
	private const ulong DwFormRefSig8 = 0x20;
	private const ulong DwFormImplicitConst = 0x21;
	private const ulong DwFormLoclistx = 0x22;
	private const ulong DwFormRnglistx = 0x23;
	private const ulong DwFormRefSup8 = 0x24;
	private const ulong DwFormStrx1 = 0x25;
	private const ulong DwFormStrx2 = 0x26;
	private const ulong DwFormStrx3 = 0x27;
	private const ulong DwFormStrx4 = 0x28;
	private const ulong DwFormAddrx1 = 0x29;
	private const ulong DwFormAddrx2 = 0x2A;
	private const ulong DwFormAddrx3 = 0x2B;
	private const ulong DwFormAddrx4 = 0x2C;
	private const ulong DwFormGnuRefAlt = 0x1F20;
	private const ulong DwFormGnuStrpAlt = 0x1F21;
	private const ulong DwTagLoUser = 0x4080;
	private const ulong DwTagHiUser = 0xFFFF;
	private const ulong DwAtLoUser = 0x2000;
	private const ulong DwAtHiUser = 0x3FFF;
	private const ulong DwFormLoUser = 0x1F00;
	private const ulong DwFormHiUser = 0x1FFF;

	private sealed class DwarfAbbrevAttributeSpec
	{
		public ulong Name { get; init; }
		public ulong Form { get; init; }
		public long? ImplicitConstValue { get; init; }
	}

	private sealed class DwarfAbbrevEntry
	{
		public ulong Code { get; init; }
		public ulong Tag { get; init; }
		public bool HasChildren { get; init; }
		public List<DwarfAbbrevAttributeSpec> Attributes { get; } = new();
	}

	private sealed class DwarfDieSymbolCandidate
	{
		public ElfDwarfDie Die { get; init; }
		public string Name { get; init; }
		public string LinkageName { get; init; }
		public List<(ulong Start, ulong End)> AddressRanges { get; } = new();
	}

	private sealed class DwarfMappingSectionContext
	{
		public bool IsLittleEndian { get; init; }
		public byte[] DebugStrPayload { get; init; }
		public byte[] DebugAddrPayload { get; init; }
		public byte[] DebugStrOffsetsPayload { get; init; }
		public byte[] DebugRangesPayload { get; init; }
		public byte[] DebugRnglistsPayload { get; init; }
		public byte[] DebugLoclistsPayload { get; init; }
	}

	private sealed class DwarfUnitMappingContext
	{
		public bool IsLittleEndian { get; init; }
		public bool IsDwarf64 { get; init; }
		public byte AddressSize { get; init; }
		public byte[] DebugStrPayload { get; init; }
		public byte[] DebugAddrPayload { get; init; }
		public byte[] DebugStrOffsetsPayload { get; init; }
		public byte[] DebugRangesPayload { get; init; }
		public byte[] DebugRnglistsPayload { get; init; }
		public byte[] DebugLoclistsPayload { get; init; }
		public ulong? LowPcBaseAddress { get; init; }
		public ulong? AddrBase { get; init; }
		public ulong? StrOffsetsBase { get; init; }
		public ulong? RnglistsBase { get; init; }
		public ulong? LoclistsBase { get; init; }
	}

	private static void ParseDwarfSemantics(
		IEndianDataSource data,
		ElfFile elf,
		ElfDwarfIndexInfo dwarf,
		ElfSectionHeader debugInfoSection,
		ElfSectionHeader debugAbbrevSection)
	{
		dwarf.SemanticUnits.Clear();
		dwarf.SymbolMappings.Clear();

		if (debugInfoSection == null || debugAbbrevSection == null)
			return;

		if (!TryReadSectionPayload(
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
			return;
		}

		if (!TryReadSectionPayload(
			data,
			elf,
			debugAbbrevSection,
			out var abbrevPayload,
			out _,
			out _,
			out _,
			out _,
			out _,
			out _))
		{
			return;
		}

		var debugStrPayload = TryReadOptionalDebugSectionPayload(data, elf, FindDebugSection(elf, ".debug_str"));
		var debugLineStrPayload = TryReadOptionalDebugSectionPayload(data, elf, FindDebugSection(elf, ".debug_line_str"));
		var debugAddrPayload = TryReadOptionalDebugSectionPayload(data, elf, FindDebugSection(elf, ".debug_addr"));
		var debugStrOffsetsPayload = TryReadOptionalDebugSectionPayload(data, elf, FindDebugSection(elf, ".debug_str_offsets"));
		var debugRangesPayload = TryReadOptionalDebugSectionPayload(data, elf, FindDebugSection(elf, ".debug_ranges"));
		var debugRnglistsPayload = TryReadOptionalDebugSectionPayload(data, elf, FindDebugSection(elf, ".debug_rnglists"));
		var debugLoclistsPayload = TryReadOptionalDebugSectionPayload(data, elf, FindDebugSection(elf, ".debug_loclists"));
		var abbrevTables = ParseDwarfAbbreviationTables(abbrevPayload, elf.Header.IsLittleEndian);
		if (abbrevTables.Count == 0)
			return;

		ParseDwarfSemanticUnits(infoPayload, elf.Header.IsLittleEndian, abbrevTables, debugStrPayload, debugLineStrPayload, dwarf.SemanticUnits);
		var mappingContext = new DwarfMappingSectionContext
		{
			IsLittleEndian = elf.Header.IsLittleEndian,
			DebugStrPayload = debugStrPayload,
			DebugAddrPayload = debugAddrPayload,
			DebugStrOffsetsPayload = debugStrOffsetsPayload,
			DebugRangesPayload = debugRangesPayload,
			DebugRnglistsPayload = debugRnglistsPayload,
			DebugLoclistsPayload = debugLoclistsPayload
		};
		BuildDwarfSymbolMappings(elf, dwarf.SemanticUnits, dwarf.SymbolMappings, mappingContext);
	}

	private static byte[] TryReadOptionalDebugSectionPayload(IEndianDataSource data, ElfFile elf, ElfSectionHeader section)
	{
		if (section == null)
			return Array.Empty<byte>();

		return TryReadSectionPayload(
			data,
			elf,
			section,
			out var payload,
			out _,
			out _,
			out _,
			out _,
			out _,
			out _)
			? payload
			: Array.Empty<byte>();
	}

	private static Dictionary<ulong, Dictionary<ulong, DwarfAbbrevEntry>> ParseDwarfAbbreviationTables(ReadOnlySpan<byte> payload, bool isLittleEndian)
	{
		var result = new Dictionary<ulong, Dictionary<ulong, DwarfAbbrevEntry>>();
		var cursor = 0;
		var tableOffset = 0UL;
		var table = new Dictionary<ulong, DwarfAbbrevEntry>();
		var iterations = 0UL;

		while (cursor < payload.Length && iterations < MaxParserEntryCount)
		{
			iterations++;
			if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var code))
				break;

			if (code == 0)
			{
				if (table.Count > 0)
					result[tableOffset] = table;

				tableOffset = (ulong)cursor;
				table = new Dictionary<ulong, DwarfAbbrevEntry>();
				continue;
			}

			if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var tag))
				break;
			if (cursor >= payload.Length)
				break;

			var hasChildren = payload[cursor++] != 0;
			var entry = new DwarfAbbrevEntry
			{
				Code = code,
				Tag = tag,
				HasChildren = hasChildren
			};

			while (cursor < payload.Length)
			{
				if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var name))
					break;
				if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var form))
					break;

				if (name == 0 && form == 0)
					break;

				long? implicitConst = null;
				if (form == DwFormImplicitConst)
				{
					if (!TryReadSleb128Bounded(payload, ref cursor, payload.Length, out var value))
						break;
					implicitConst = value;
				}

				entry.Attributes.Add(new DwarfAbbrevAttributeSpec
				{
					Name = name,
					Form = form,
					ImplicitConstValue = implicitConst
				});
			}

			table[entry.Code] = entry;
		}

		if (table.Count > 0)
			result[tableOffset] = table;

		return result;
	}

	private static void ParseDwarfSemanticUnits(
		ReadOnlySpan<byte> infoPayload,
		bool isLittleEndian,
		Dictionary<ulong, Dictionary<ulong, DwarfAbbrevEntry>> abbrevTables,
		ReadOnlySpan<byte> debugStrPayload,
		ReadOnlySpan<byte> debugLineStrPayload,
		List<ElfDwarfSemanticCompilationUnit> output)
	{
		output.Clear();
		var cursor = 0;
		var units = 0UL;

		while (cursor + 4 <= infoPayload.Length && units < MaxParserEntryCount)
		{
			units++;
			var unitOffset = cursor;
			if (!TryReadDwarfUnitLength(infoPayload, isLittleEndian, ref cursor, out var unitLength, out var isDwarf64))
				break;
			if (unitLength == 0)
				break;
			if (!TryGetUnitEnd(infoPayload.Length, cursor, unitLength, out var unitEnd))
				break;
			if (cursor + 2 > unitEnd)
				break;

			var version = ReadUInt16WithEndian(infoPayload.Slice(cursor, 2), isLittleEndian);
			cursor += 2;

			byte? unitType = null;
			ulong abbrevOffset;
			byte addressSize;
			if (version >= 5)
			{
				if (cursor + 2 > unitEnd)
					break;
				unitType = infoPayload[cursor++];
				addressSize = infoPayload[cursor++];
				if (!TryReadDwarfOffset(infoPayload, isLittleEndian, isDwarf64, ref cursor, unitEnd, out abbrevOffset))
					break;
			}
			else
			{
				if (!TryReadDwarfOffset(infoPayload, isLittleEndian, isDwarf64, ref cursor, unitEnd, out abbrevOffset))
					break;
				if (cursor + 1 > unitEnd)
					break;
				addressSize = infoPayload[cursor++];
			}

			var unit = new ElfDwarfSemanticCompilationUnit
			{
				Offset = (ulong)unitOffset,
				UnitLength = unitLength,
				IsDwarf64 = isDwarf64,
				Version = version,
				UnitType = unitType,
				AbbrevOffset = abbrevOffset,
				AddressSize = addressSize
			};
			output.Add(unit);

			if (abbrevTables.TryGetValue(abbrevOffset, out var abbrevTable))
			{
				ParseDwarfDieTree(
					infoPayload,
					ref cursor,
					unitEnd,
					isLittleEndian,
					isDwarf64,
					version,
					addressSize,
					(ulong)unitOffset,
					abbrevTable,
					debugStrPayload,
					debugLineStrPayload,
					unit.RootDies,
					unit.PreservedRegions);
			}
			else
			{
				cursor = unitEnd;
			}

			if (cursor < unitEnd)
				cursor = unitEnd;
		}
	}

	private static void ParseDwarfDieTree(
		ReadOnlySpan<byte> infoPayload,
		ref int cursor,
		int unitEnd,
		bool isLittleEndian,
		bool isDwarf64,
		ushort version,
		byte addressSize,
		ulong unitOffset,
		Dictionary<ulong, DwarfAbbrevEntry> abbrevTable,
		ReadOnlySpan<byte> debugStrPayload,
		ReadOnlySpan<byte> debugLineStrPayload,
		List<ElfDwarfDie> roots,
		List<ElfDwarfPreservedRegion> preservedRegions)
	{
		roots.Clear();
		var stack = new Stack<ElfDwarfDie>();
		var entries = 0UL;

		while (cursor < unitEnd && entries < MaxParserEntryCount)
		{
			entries++;
			var dieOffset = cursor;
			if (!TryReadUleb128Bounded(infoPayload, ref cursor, unitEnd, out var abbrevCode))
				break;

			if (abbrevCode == 0)
			{
				if (stack.Count > 0)
				{
					stack.Pop();
					continue;
				}

				// End marker at the top level: ignore and continue with next bytes.
				continue;
			}

			if (!abbrevTable.TryGetValue(abbrevCode, out var abbrevEntry))
				break;

			var die = new ElfDwarfDie
			{
				Offset = (ulong)dieOffset,
				AbbrevCode = abbrevCode,
				Tag = abbrevEntry.Tag,
				TagText = GetDwarfTagName(abbrevEntry.Tag),
				HasChildren = abbrevEntry.HasChildren
			};

				var parseFailed = false;
				for (var i = 0; i < abbrevEntry.Attributes.Count; i++)
				{
					var spec = abbrevEntry.Attributes[i];
					var attributeValueOffset = cursor;
					if (!TryReadDwarfAttributeValue(
						infoPayload,
						ref cursor,
						unitEnd,
					isLittleEndian,
					isDwarf64,
					version,
					addressSize,
					unitOffset,
						spec,
						debugStrPayload,
						debugLineStrPayload,
						out var attribute))
					{
						var relativeOffset = attributeValueOffset >= (int)unitOffset
							? (ulong)(attributeValueOffset - (int)unitOffset)
							: 0UL;
						die.Attributes.Add(CreateDwarfDecodeErrorAttribute(spec, relativeOffset));
						PreserveDwarfUnitRegion(
							infoPayload,
							unitOffset,
							attributeValueOffset,
							unitEnd,
							$"attribute-decode-failure:{GetDwarfAttributeName(spec.Name)}:{GetDwarfFormName(spec.Form)}",
							preservedRegions);
						parseFailed = true;
						break;
					}

					ApplyDwarfAttributeSemanticHints(attribute);
					die.Attributes.Add(attribute);
				}

			if (parseFailed)
			{
				// Preserve the partially decoded DIE in the semantic model and stop this unit.
				if (stack.Count == 0)
					roots.Add(die);
				else
					stack.Peek().Children.Add(die);
				cursor = unitEnd;
				break;
			}

			if (stack.Count == 0)
				roots.Add(die);
			else
				stack.Peek().Children.Add(die);

			if (abbrevEntry.HasChildren)
				stack.Push(die);
		}
	}

	private static bool TryReadDwarfAttributeValue(
		ReadOnlySpan<byte> payload,
		ref int cursor,
		int unitEnd,
		bool isLittleEndian,
		bool isDwarf64,
		ushort version,
		byte addressSize,
		ulong unitOffset,
		DwarfAbbrevAttributeSpec spec,
		ReadOnlySpan<byte> debugStrPayload,
		ReadOnlySpan<byte> debugLineStrPayload,
		out ElfDwarfAttributeValue value)
	{
		var valueStart = cursor;
		value = new ElfDwarfAttributeValue
		{
			Name = spec.Name,
			NameText = GetDwarfAttributeName(spec.Name),
			Form = spec.Form,
			FormText = GetDwarfFormName(spec.Form),
			Kind = ElfDwarfAttributeValueKind.None,
			StringValue = string.Empty,
			BytesValue = Array.Empty<byte>(),
			UnitRelativeValueOffset = valueStart >= (int)unitOffset ? (ulong)(valueStart - (int)unitOffset) : 0,
			ConsumedByteCount = 0,
			DecodeStatus = ElfDwarfDecodeStatus.Exact,
			DecodeNote = string.Empty
		};

		var offsetSize = isDwarf64 ? 8 : 4;
		switch (spec.Form)
		{
			case DwFormAddr:
			{
				var size = addressSize == 0 ? offsetSize : addressSize;
						if (!TryReadUnsigned(payload, isLittleEndian, ref cursor, unitEnd, size, out var addr))
							return false;
						value.Kind = ElfDwarfAttributeValueKind.Address;
						value.UnsignedValue = addr;
						return CompleteDwarfAttributeValue(ref value, cursor, valueStart);
					}
					case DwFormData1:
					case DwFormData2:
					case DwFormData4:
			case DwFormData8:
			{
				var size = spec.Form switch
				{
					DwFormData1 => 1,
					DwFormData2 => 2,
					DwFormData4 => 4,
					_ => 8
				};
						if (!TryReadUnsigned(payload, isLittleEndian, ref cursor, unitEnd, size, out var data))
							return false;
						value.Kind = ElfDwarfAttributeValueKind.Unsigned;
						value.UnsignedValue = data;
						return CompleteDwarfAttributeValue(ref value, cursor, valueStart);
					}
					case DwFormUData:
					case DwFormStrx:
					case DwFormAddrx:
			case DwFormLoclistx:
			case DwFormRnglistx:
			{
						if (!TryReadUleb128Bounded(payload, ref cursor, unitEnd, out var data))
							return false;
						value.Kind = ElfDwarfAttributeValueKind.Unsigned;
						value.UnsignedValue = data;
						return CompleteDwarfAttributeValue(ref value, cursor, valueStart);
					}
					case DwFormSData:
					{
						if (!TryReadSleb128Bounded(payload, ref cursor, unitEnd, out var data))
							return false;
						value.Kind = ElfDwarfAttributeValueKind.Signed;
						value.SignedValue = data;
						return CompleteDwarfAttributeValue(ref value, cursor, valueStart);
					}
					case DwFormFlag:
					{
					if (!TryReadUnsigned(payload, isLittleEndian, ref cursor, unitEnd, 1, out var flag))
						return false;
						value.Kind = ElfDwarfAttributeValueKind.Flag;
						value.BoolValue = flag != 0;
						value.UnsignedValue = flag;
						return CompleteDwarfAttributeValue(ref value, cursor, valueStart);
					}
					case DwFormFlagPresent:
					{
						value.Kind = ElfDwarfAttributeValueKind.Flag;
						value.BoolValue = true;
						value.UnsignedValue = 1;
						return CompleteDwarfAttributeValue(ref value, cursor, valueStart);
					}
					case DwFormString:
					{
						if (!TryReadNullTerminatedAscii(payload, ref cursor, unitEnd, out var text))
							return false;
						value.Kind = ElfDwarfAttributeValueKind.String;
						value.StringValue = text;
						return CompleteDwarfAttributeValue(ref value, cursor, valueStart);
					}
					case DwFormStrp:
					case DwFormLineStrp:
				{
				if (!TryReadUnsigned(payload, isLittleEndian, ref cursor, unitEnd, offsetSize, out var offset))
					return false;

				var table = spec.Form == DwFormLineStrp ? debugLineStrPayload : debugStrPayload;
					if (!TryReadDwarfStringAtOffset(table, offset, out var text))
					{
							text = $"<str@0x{offset:X}>";
							value.Kind = ElfDwarfAttributeValueKind.String;
							value.UnsignedValue = offset;
							value.StringValue = text;
							return CompleteDwarfAttributeValue(ref value, cursor, valueStart, ElfDwarfDecodeStatus.Partial, "string table lookup failed");
						}

						value.Kind = ElfDwarfAttributeValueKind.String;
						value.UnsignedValue = offset;
						value.StringValue = text;
						return CompleteDwarfAttributeValue(ref value, cursor, valueStart);
					}
					case DwFormStrx1:
				case DwFormStrx2:
				case DwFormStrx3:
			case DwFormStrx4:
			case DwFormAddrx1:
			case DwFormAddrx2:
			case DwFormAddrx3:
			case DwFormAddrx4:
			{
				var size = spec.Form switch
				{
					DwFormStrx1 or DwFormAddrx1 => 1,
					DwFormStrx2 or DwFormAddrx2 => 2,
					DwFormStrx3 or DwFormAddrx3 => 3,
					_ => 4
				};
						if (!TryReadUnsigned(payload, isLittleEndian, ref cursor, unitEnd, size, out var idx))
							return false;
						value.Kind = ElfDwarfAttributeValueKind.Unsigned;
						value.UnsignedValue = idx;
						return CompleteDwarfAttributeValue(ref value, cursor, valueStart);
					}
					case DwFormRef1:
					case DwFormRef2:
				case DwFormRef4:
			case DwFormRef8:
			{
				var size = spec.Form switch
				{
					DwFormRef1 => 1,
					DwFormRef2 => 2,
					DwFormRef4 => 4,
					_ => 8
				};
					if (!TryReadUnsigned(payload, isLittleEndian, ref cursor, unitEnd, size, out var localRef))
						return false;
						value.Kind = ElfDwarfAttributeValueKind.Reference;
						value.UnsignedValue = unitOffset + localRef;
						value.StringValue = $"die_ref=0x{value.UnsignedValue:X}";
						return CompleteDwarfAttributeValue(ref value, cursor, valueStart);
					}
					case DwFormRefUData:
					{
						if (!TryReadUleb128Bounded(payload, ref cursor, unitEnd, out var localRef))
							return false;
						value.Kind = ElfDwarfAttributeValueKind.Reference;
						value.UnsignedValue = unitOffset + localRef;
						value.StringValue = $"die_ref=0x{value.UnsignedValue:X}";
						return CompleteDwarfAttributeValue(ref value, cursor, valueStart);
					}
					case DwFormRefAddr:
					{
					var size = version <= 2 ? (addressSize == 0 ? offsetSize : addressSize) : offsetSize;
					if (!TryReadUnsigned(payload, isLittleEndian, ref cursor, unitEnd, size, out var refAddr))
						return false;
						value.Kind = ElfDwarfAttributeValueKind.Reference;
						value.UnsignedValue = refAddr;
						value.StringValue = $"die_ref=0x{value.UnsignedValue:X}";
						return CompleteDwarfAttributeValue(ref value, cursor, valueStart);
					}
				case DwFormRefSig8:
				case DwFormSecOffset:
				case DwFormRefSup4:
				case DwFormRefSup8:
				case DwFormGnuRefAlt:
				{
					var size = spec.Form switch
					{
						DwFormRefSig8 => 8,
						DwFormRefSup4 => 4,
						DwFormRefSup8 => 8,
						DwFormGnuRefAlt => offsetSize,
						_ => offsetSize
					};
					if (!TryReadUnsigned(payload, isLittleEndian, ref cursor, unitEnd, size, out var refValue))
						return false;
					value.Kind = spec.Form is DwFormRefSig8
						? ElfDwarfAttributeValueKind.Unsigned
						: ElfDwarfAttributeValueKind.Reference;
						value.UnsignedValue = refValue;
						if (value.Kind == ElfDwarfAttributeValueKind.Reference)
							value.StringValue = $"die_ref=0x{value.UnsignedValue:X}";
						return CompleteDwarfAttributeValue(ref value, cursor, valueStart);
					}
				case DwFormStrpSup:
				case DwFormGnuStrpAlt:
				{
					if (!TryReadUnsigned(payload, isLittleEndian, ref cursor, unitEnd, offsetSize, out var offset))
						return false;
					value.Kind = ElfDwarfAttributeValueKind.String;
						value.UnsignedValue = offset;
						value.StringValue = spec.Form == DwFormGnuStrpAlt
							? $"<str_alt@0x{offset:X}>"
							: $"<str_sup@0x{offset:X}>";
						return CompleteDwarfAttributeValue(ref value, cursor, valueStart, ElfDwarfDecodeStatus.Partial, "supplementary string table not available");
					}
				case DwFormExprLoc:
				case DwFormBlock:
				case DwFormBlock1:
			case DwFormBlock2:
			case DwFormBlock4:
			{
				ulong blockLength;
				if (spec.Form == DwFormExprLoc || spec.Form == DwFormBlock)
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, unitEnd, out blockLength))
						return false;
				}
				else
				{
					var size = spec.Form switch
					{
						DwFormBlock1 => 1,
						DwFormBlock2 => 2,
						_ => 4
					};
					if (!TryReadUnsigned(payload, isLittleEndian, ref cursor, unitEnd, size, out blockLength))
						return false;
				}

				if (blockLength > (ulong)(unitEnd - cursor))
					return false;
				if (blockLength > int.MaxValue)
					return false;

				var bytes = payload.Slice(cursor, (int)blockLength).ToArray();
					cursor = checked(cursor + (int)blockLength);
						value.Kind = ElfDwarfAttributeValueKind.Bytes;
						value.BytesValue = bytes;
						value.UnsignedValue = blockLength;
						return CompleteDwarfAttributeValue(ref value, cursor, valueStart);
					}
					case DwFormImplicitConst:
					{
						value.Kind = ElfDwarfAttributeValueKind.Signed;
						value.SignedValue = spec.ImplicitConstValue ?? 0;
						return CompleteDwarfAttributeValue(ref value, cursor, valueStart);
					}
					case DwFormData16:
					{
				if (cursor + 16 > unitEnd)
					return false;
					value.Kind = ElfDwarfAttributeValueKind.Bytes;
						value.BytesValue = payload.Slice(cursor, 16).ToArray();
						value.UnsignedValue = 16;
						cursor += 16;
						return CompleteDwarfAttributeValue(ref value, cursor, valueStart);
					}
				case DwFormIndirect:
				{
				if (!TryReadUleb128Bounded(payload, ref cursor, unitEnd, out var actualForm))
					return false;

				var indirectSpec = new DwarfAbbrevAttributeSpec
				{
					Name = spec.Name,
					Form = actualForm,
					ImplicitConstValue = spec.ImplicitConstValue
				};
				return TryReadDwarfAttributeValue(
					payload,
					ref cursor,
					unitEnd,
					isLittleEndian,
					isDwarf64,
					version,
					addressSize,
					unitOffset,
					indirectSpec,
						debugStrPayload,
						debugLineStrPayload,
						out value);
				}
				default:
				{
					var formName = GetDwarfFormName(spec.Form);
					var fallbackStart = cursor;
					if (TryReadUleb128Bounded(payload, ref cursor, unitEnd, out var rawUleb))
					{
						value.Kind = ElfDwarfAttributeValueKind.Unsigned;
						value.UnsignedValue = rawUleb;
						var consumed = cursor - fallbackStart;
							if (consumed > 0)
								value.BytesValue = payload.Slice(fallbackStart, consumed).ToArray();
							value.StringValue = $"<unknown-form-fallback:uleb128:form={formName}>";
							return CompleteDwarfAttributeValue(ref value, cursor, valueStart, ElfDwarfDecodeStatus.PreservedUnknown, "unknown form preserved via uleb128");
						}

					if (cursor < unitEnd)
					{
						value.Kind = ElfDwarfAttributeValueKind.Bytes;
							value.BytesValue = new[] { payload[cursor++] };
							value.UnsignedValue = 1;
							value.StringValue = $"<unknown-form-fallback:byte:form={formName}>";
							return CompleteDwarfAttributeValue(ref value, cursor, valueStart, ElfDwarfDecodeStatus.PreservedUnknown, "unknown form preserved via single-byte fallback");
						}

					return false;
				}
		}
	}

	private static bool CompleteDwarfAttributeValue(
		ref ElfDwarfAttributeValue value,
		int cursor,
		int valueStart,
		ElfDwarfDecodeStatus status = ElfDwarfDecodeStatus.Exact,
		string note = "")
	{
		value.ConsumedByteCount = cursor >= valueStart ? (ulong)(cursor - valueStart) : 0UL;
		value.DecodeStatus = status;
		if (!string.IsNullOrEmpty(note))
			value.DecodeNote = note;

		return true;
	}

	private static void ApplyDwarfAttributeSemanticHints(ElfDwarfAttributeValue attribute)
	{
		if (!TryGetUnsignedDwarfAttributeScalar(attribute, out var rawValue))
			return;
		if (!TryGetDwarfAttributeSemanticText(attribute.Name, rawValue, out var semanticText))
			return;

		attribute.StringValue = $"{semanticText} (0x{rawValue:X})";
	}

	private static bool TryGetUnsignedDwarfAttributeScalar(ElfDwarfAttributeValue attribute, out ulong value)
	{
		value = 0;
		if (attribute == null)
			return false;

		if (attribute.Kind == ElfDwarfAttributeValueKind.Unsigned)
		{
			value = attribute.UnsignedValue;
			return true;
		}

		if (attribute.Kind == ElfDwarfAttributeValueKind.Signed && attribute.SignedValue >= 0)
		{
			value = (ulong)attribute.SignedValue;
			return true;
		}

		return false;
	}

	private static bool TryGetDwarfAttributeSemanticText(ulong attributeName, ulong value, out string text)
	{
		text = string.Empty;
		switch (attributeName)
		{
			case DwAtLanguage:
				text = GetDwarfLanguageName(value);
				return true;
			case DwAtEncoding:
				text = GetDwarfEncodingName(value);
				return true;
			case DwAtInline:
				text = GetDwarfInlineName(value);
				return true;
			case DwAtAccessibility:
				text = GetDwarfAccessibilityName(value);
				return true;
			case DwAtVisibility:
				text = GetDwarfVisibilityName(value);
				return true;
			case DwAtCallingConvention:
				text = GetDwarfCallingConventionName(value);
				return true;
			case DwAtVirtuality:
				text = GetDwarfVirtualityName(value);
				return true;
			case DwAtEndianity:
				text = GetDwarfEndianityName(value);
				return true;
			default:
				return false;
		}
	}

	private static string GetDwarfLanguageName(ulong value)
	{
		return value switch
		{
			0x0001 => "DW_LANG_C89",
			0x0002 => "DW_LANG_C",
			0x0003 => "DW_LANG_Ada83",
			0x0004 => "DW_LANG_C_plus_plus",
			0x0005 => "DW_LANG_Cobol74",
			0x0006 => "DW_LANG_Cobol85",
			0x0007 => "DW_LANG_Fortran77",
			0x0008 => "DW_LANG_Fortran90",
			0x0009 => "DW_LANG_Pascal83",
			0x000A => "DW_LANG_Modula2",
			0x000B => "DW_LANG_Java",
			0x000C => "DW_LANG_C99",
			0x000D => "DW_LANG_Ada95",
			0x000E => "DW_LANG_Fortran95",
			0x000F => "DW_LANG_PLI",
			0x0010 => "DW_LANG_ObjC",
			0x0011 => "DW_LANG_ObjC_plus_plus",
			0x0012 => "DW_LANG_UPC",
			0x0013 => "DW_LANG_D",
			0x0014 => "DW_LANG_Python",
			0x0015 => "DW_LANG_OpenCL",
			0x0016 => "DW_LANG_Go",
			0x0017 => "DW_LANG_Modula3",
			0x0018 => "DW_LANG_Haskell",
			0x0019 => "DW_LANG_C_plus_plus_03",
			0x001A => "DW_LANG_C_plus_plus_11",
			0x001B => "DW_LANG_OCaml",
			0x001C => "DW_LANG_Rust",
			0x001D => "DW_LANG_C11",
			0x001E => "DW_LANG_Swift",
			0x001F => "DW_LANG_Julia",
			0x0020 => "DW_LANG_Dylan",
			0x0021 => "DW_LANG_C_plus_plus_14",
			0x0022 => "DW_LANG_Fortran03",
			0x0023 => "DW_LANG_Fortran08",
			0x0024 => "DW_LANG_RenderScript",
			0x0025 => "DW_LANG_BLISS",
			0x0026 => "DW_LANG_Kotlin",
			0x0027 => "DW_LANG_Zig",
			0x0028 => "DW_LANG_Crystal",
			0x0029 => "DW_LANG_C_plus_plus_17",
			0x002A => "DW_LANG_C_plus_plus_20",
			_ => FormatUnknownDwarfCode("DW_LANG", value, 0x8000, 0xFFFF)
		};
	}

	private static string GetDwarfEncodingName(ulong value)
	{
		return value switch
		{
			0x01 => "DW_ATE_address",
			0x02 => "DW_ATE_boolean",
			0x03 => "DW_ATE_complex_float",
			0x04 => "DW_ATE_float",
			0x05 => "DW_ATE_signed",
			0x06 => "DW_ATE_signed_char",
			0x07 => "DW_ATE_unsigned",
			0x08 => "DW_ATE_unsigned_char",
			0x09 => "DW_ATE_imaginary_float",
			0x0A => "DW_ATE_packed_decimal",
			0x0B => "DW_ATE_numeric_string",
			0x0C => "DW_ATE_edited",
			0x0D => "DW_ATE_signed_fixed",
			0x0E => "DW_ATE_unsigned_fixed",
			0x0F => "DW_ATE_decimal_float",
			0x10 => "DW_ATE_UTF",
			0x11 => "DW_ATE_UCS",
			0x12 => "DW_ATE_ASCII",
			_ => FormatUnknownDwarfCode("DW_ATE", value, 0x80, 0xFF)
		};
	}

	private static string GetDwarfInlineName(ulong value)
	{
		return value switch
		{
			0 => "DW_INL_not_inlined",
			1 => "DW_INL_inlined",
			2 => "DW_INL_declared_not_inlined",
			3 => "DW_INL_declared_inlined",
			_ => $"DW_INL_0x{value:X}"
		};
	}

	private static string GetDwarfAccessibilityName(ulong value)
	{
		return value switch
		{
			1 => "DW_ACCESS_public",
			2 => "DW_ACCESS_protected",
			3 => "DW_ACCESS_private",
			_ => $"DW_ACCESS_0x{value:X}"
		};
	}

	private static string GetDwarfVisibilityName(ulong value)
	{
		return value switch
		{
			1 => "DW_VIS_local",
			2 => "DW_VIS_exported",
			3 => "DW_VIS_qualified",
			_ => $"DW_VIS_0x{value:X}"
		};
	}

	private static string GetDwarfCallingConventionName(ulong value)
	{
		return value switch
		{
			1 => "DW_CC_normal",
			2 => "DW_CC_program",
			3 => "DW_CC_nocall",
			4 => "DW_CC_pass_by_reference",
			5 => "DW_CC_pass_by_value",
			_ => FormatUnknownDwarfCode("DW_CC", value, 0x40, 0xFF)
		};
	}

	private static string GetDwarfVirtualityName(ulong value)
	{
		return value switch
		{
			0 => "DW_VIRTUALITY_none",
			1 => "DW_VIRTUALITY_virtual",
			2 => "DW_VIRTUALITY_pure_virtual",
			_ => $"DW_VIRTUALITY_0x{value:X}"
		};
	}

	private static string GetDwarfEndianityName(ulong value)
	{
		return value switch
		{
			0 => "DW_END_default",
			1 => "DW_END_big",
			2 => "DW_END_little",
			_ => FormatUnknownDwarfCode("DW_END", value, 0x40, 0xFF)
		};
	}

	private static ElfDwarfAttributeValue CreateDwarfDecodeErrorAttribute(DwarfAbbrevAttributeSpec spec, ulong unitRelativeOffset)
	{
		return new ElfDwarfAttributeValue
		{
			Name = spec.Name,
			NameText = GetDwarfAttributeName(spec.Name),
			Form = spec.Form,
			FormText = GetDwarfFormName(spec.Form),
			Kind = ElfDwarfAttributeValueKind.None,
			StringValue = "<decode-error>",
			BytesValue = Array.Empty<byte>(),
			UnitRelativeValueOffset = unitRelativeOffset,
			ConsumedByteCount = 0,
			DecodeStatus = ElfDwarfDecodeStatus.DecodeError,
			DecodeNote = "attribute decode failed"
		};
	}

	private static void PreserveDwarfUnitRegion(
		ReadOnlySpan<byte> payload,
		ulong unitOffset,
		int startOffset,
		int endOffset,
		string reason,
		List<ElfDwarfPreservedRegion> output)
	{
		if (output == null || startOffset < 0 || endOffset < startOffset || endOffset > payload.Length)
			return;

		var previewLength = Math.Min(32, endOffset - startOffset);
		var previewHex = previewLength <= 0
			? string.Empty
			: Convert.ToHexString(payload.Slice(startOffset, previewLength));
		var relativeOffset = startOffset >= (int)unitOffset
			? (ulong)(startOffset - (int)unitOffset)
			: 0UL;
		var length = (ulong)(endOffset - startOffset);

		output.Add(new ElfDwarfPreservedRegion
		{
			UnitRelativeOffset = relativeOffset,
			UnitRelativeLength = length,
			Reason = reason ?? string.Empty,
			PreviewHex = previewHex
		});
	}

	private static bool TryReadDwarfStringAtOffset(ReadOnlySpan<byte> table, ulong offset, out string text)
	{
		text = string.Empty;
		if (table.Length == 0)
			return false;
		if (offset > int.MaxValue || offset >= (ulong)table.Length)
			return false;

		var cursor = (int)offset;
		var zero = table.Slice(cursor).IndexOf((byte)0);
		if (zero < 0)
			return false;

		text = Encoding.UTF8.GetString(table.Slice(cursor, zero));
		return true;
	}

	private static void BuildDwarfSymbolMappings(
		ElfFile elf,
		List<ElfDwarfSemanticCompilationUnit> units,
		List<ElfDwarfSymbolMapping> output,
		DwarfMappingSectionContext context)
	{
		output.Clear();
		if (units.Count == 0 || elf.Symbols.Count == 0)
			return;

		var candidates = new List<DwarfDieSymbolCandidate>();
		for (var unitIndex = 0; unitIndex < units.Count; unitIndex++)
		{
			var unit = units[unitIndex];
			var unitContext = CreateUnitMappingContext(unit, context);
			CollectDwarfSymbolCandidates(unit.RootDies, unitContext, candidates);
		}

		if (candidates.Count == 0)
			return;

		var byLinkageName = new Dictionary<string, List<DwarfDieSymbolCandidate>>(StringComparer.Ordinal);
		var byName = new Dictionary<string, List<DwarfDieSymbolCandidate>>(StringComparer.Ordinal);
		for (var i = 0; i < candidates.Count; i++)
		{
			var candidate = candidates[i];
			if (!string.IsNullOrEmpty(candidate.LinkageName))
				AddCandidate(byLinkageName, candidate.LinkageName, candidate);
			if (!string.IsNullOrEmpty(candidate.Name))
				AddCandidate(byName, candidate.Name, candidate);
		}

		var mappedKeys = new HashSet<string>(StringComparer.Ordinal);
		for (var i = 0; i < elf.Symbols.Count; i++)
		{
			var symbol = elf.Symbols[i];
			if (string.IsNullOrEmpty(symbol.Name))
				continue;

			var mapping = ResolveDwarfSymbolMapping(symbol, byLinkageName, byName, candidates);
			if (mapping == null)
				continue;

			var key = $"{symbol.Name}\0{symbol.Value:X16}\0{mapping.DieOffset:X16}\0{mapping.MatchType}";
			if (!mappedKeys.Add(key))
				continue;

			output.Add(mapping);
		}
	}

	private static ElfDwarfSymbolMapping ResolveDwarfSymbolMapping(
		ElfSymbol symbol,
		Dictionary<string, List<DwarfDieSymbolCandidate>> byLinkageName,
		Dictionary<string, List<DwarfDieSymbolCandidate>> byName,
		List<DwarfDieSymbolCandidate> allCandidates)
	{
		if (byLinkageName.TryGetValue(symbol.Name, out var linkageMatches))
		{
			var byAddress = ChooseCandidateByAddress(linkageMatches, symbol.Value);
			return CreateDwarfSymbolMapping(symbol, byAddress ?? linkageMatches[0], byAddress != null ? "linkage+address" : "linkage");
		}

		if (byName.TryGetValue(symbol.Name, out var nameMatches))
		{
			var byAddress = ChooseCandidateByAddress(nameMatches, symbol.Value);
			return CreateDwarfSymbolMapping(symbol, byAddress ?? nameMatches[0], byAddress != null ? "name+address" : "name");
		}

		if (symbol.Value != 0)
		{
			var addressMatch = ChooseCandidateByAddress(allCandidates, symbol.Value);
			if (addressMatch != null)
				return CreateDwarfSymbolMapping(symbol, addressMatch, "address");
		}

		return null;
	}

	private static ElfDwarfSymbolMapping CreateDwarfSymbolMapping(ElfSymbol symbol, DwarfDieSymbolCandidate candidate, string matchType)
	{
		return new ElfDwarfSymbolMapping
		{
			SymbolName = symbol.Name ?? string.Empty,
			SymbolAddress = symbol.Value,
			DieOffset = candidate.Die.Offset,
			DieTagText = candidate.Die.TagText ?? string.Empty,
			MatchType = matchType
		};
	}

	private static DwarfDieSymbolCandidate ChooseCandidateByAddress(List<DwarfDieSymbolCandidate> candidates, ulong address)
	{
		if (address == 0 || candidates == null || candidates.Count == 0)
			return null;

		for (var i = 0; i < candidates.Count; i++)
		{
			var candidate = candidates[i];
			if (candidate.AddressRanges.Count == 0)
				continue;

			for (var rangeIndex = 0; rangeIndex < candidate.AddressRanges.Count; rangeIndex++)
			{
				var range = candidate.AddressRanges[rangeIndex];
				if (address >= range.Start && address < range.End)
					return candidate;
			}
		}

		return null;
	}

	private static DwarfUnitMappingContext CreateUnitMappingContext(
		ElfDwarfSemanticCompilationUnit unit,
		DwarfMappingSectionContext context)
	{
		var rootDie = unit.RootDies.Count > 0 ? unit.RootDies[0] : null;
		var addrBase = rootDie == null ? null : GetDwarfAttributeUnsigned(rootDie, DwAtAddrBase);
		var strOffsetsBase = rootDie == null ? null : GetDwarfAttributeUnsigned(rootDie, DwAtStrOffsetsBase);
		var rnglistsBase = rootDie == null ? null : GetDwarfAttributeUnsigned(rootDie, DwAtRnglistsBase);
		var loclistsBase = rootDie == null ? null : GetDwarfAttributeUnsigned(rootDie, DwAtLoclistsBase);

		var provisionalContext = new DwarfUnitMappingContext
		{
			IsLittleEndian = context.IsLittleEndian,
			IsDwarf64 = unit.IsDwarf64,
			AddressSize = unit.AddressSize,
			DebugStrPayload = context.DebugStrPayload,
			DebugAddrPayload = context.DebugAddrPayload,
			DebugStrOffsetsPayload = context.DebugStrOffsetsPayload,
			DebugRangesPayload = context.DebugRangesPayload,
			DebugRnglistsPayload = context.DebugRnglistsPayload,
			DebugLoclistsPayload = context.DebugLoclistsPayload,
			AddrBase = addrBase,
			StrOffsetsBase = strOffsetsBase,
			RnglistsBase = rnglistsBase,
			LoclistsBase = loclistsBase
		};

		var lowPcBase = rootDie == null ? null : GetDwarfAttributeAddress(rootDie, DwAtLowPc, provisionalContext);
		return new DwarfUnitMappingContext
		{
			IsLittleEndian = context.IsLittleEndian,
			IsDwarf64 = unit.IsDwarf64,
			AddressSize = unit.AddressSize,
			DebugStrPayload = context.DebugStrPayload,
			DebugAddrPayload = context.DebugAddrPayload,
			DebugStrOffsetsPayload = context.DebugStrOffsetsPayload,
			DebugRangesPayload = context.DebugRangesPayload,
			DebugRnglistsPayload = context.DebugRnglistsPayload,
			DebugLoclistsPayload = context.DebugLoclistsPayload,
			LowPcBaseAddress = lowPcBase,
			AddrBase = addrBase,
			StrOffsetsBase = strOffsetsBase,
			RnglistsBase = rnglistsBase,
			LoclistsBase = loclistsBase
		};
	}

	private static void CollectDwarfSymbolCandidates(
		List<ElfDwarfDie> dies,
		DwarfUnitMappingContext context,
		List<DwarfDieSymbolCandidate> output)
	{
		for (var i = 0; i < dies.Count; i++)
		{
			var die = dies[i];
			var shouldConsider =
				die.Tag == DwTagSubprogram
				|| die.Tag == DwTagInlinedSubroutine
				|| die.Tag == DwTagVariable
				|| die.Tag == DwTagFormalParameter
				|| die.Tag == DwTagLabel
				|| die.Tag == DwTagNamespace
				|| die.Tag == DwTagClassType
				|| die.Tag == DwTagStructureType
				|| die.Tag == DwTagTypedef;

			if (shouldConsider)
			{
				var declaration = GetDwarfAttributeFlag(die, DwAtDeclaration);
				if (!declaration)
				{
					var name = GetDwarfAttributeString(die, DwAtName, context);
					var linkageName = GetDwarfAttributeString(die, DwAtLinkageName, context);
					if (string.IsNullOrEmpty(linkageName))
						linkageName = GetDwarfAttributeString(die, DwAtMipsLinkageName, context);

					var ranges = GetDwarfAddressRanges(die, context);
					if (!string.IsNullOrEmpty(name) || !string.IsNullOrEmpty(linkageName) || ranges.Count > 0)
					{
						var candidate = new DwarfDieSymbolCandidate
						{
							Die = die,
							Name = name ?? string.Empty,
							LinkageName = linkageName ?? string.Empty
						};
						for (var rangeIndex = 0; rangeIndex < ranges.Count; rangeIndex++)
							candidate.AddressRanges.Add(ranges[rangeIndex]);
						output.Add(candidate);
					}
				}
			}

			if (die.Children.Count > 0)
				CollectDwarfSymbolCandidates(die.Children, context, output);
		}
	}

	private static List<(ulong Start, ulong End)> GetDwarfAddressRanges(ElfDwarfDie die, DwarfUnitMappingContext context)
	{
		var ranges = new List<(ulong Start, ulong End)>();
		var lowHighRange = GetDwarfLowHighRange(die, context);
		if (lowHighRange.LowPc.HasValue && lowHighRange.HighPc.HasValue)
			TryAddAddressRange(ranges, lowHighRange.LowPc.Value, lowHighRange.HighPc.Value);

		if (TryGetDwarfAttribute(die, DwAtRanges, out var rangesAttribute))
		{
			var decodedRanges = ParseDwarfRangesAttribute(rangesAttribute, context);
			for (var i = 0; i < decodedRanges.Count; i++)
				TryAddAddressRange(ranges, decodedRanges[i].Start, decodedRanges[i].End);
		}

		if (TryGetDwarfAttribute(die, DwAtLocation, out var locationAttribute))
		{
			var decodedRanges = ParseDwarfLocationRanges(locationAttribute, context);
			for (var i = 0; i < decodedRanges.Count; i++)
				TryAddAddressRange(ranges, decodedRanges[i].Start, decodedRanges[i].End);
		}

		return ranges;
	}

	private static (ulong? LowPc, ulong? HighPc) GetDwarfLowHighRange(ElfDwarfDie die, DwarfUnitMappingContext context)
	{
		ulong? lowPc = null;
		ulong? highPc = null;

		for (var i = 0; i < die.Attributes.Count; i++)
		{
			var attribute = die.Attributes[i];
			if (attribute.Name == DwAtLowPc)
			{
				var lowPcValue = GetDwarfAttributeAddressValue(attribute, context);
				if (lowPcValue.HasValue)
					lowPc = lowPcValue.Value;
			}
			else if (attribute.Name == DwAtHighPc)
			{
				var highPcValue = GetDwarfAttributeAddressValue(attribute, context);
				if (highPcValue.HasValue && IsDwarfAddressForm(attribute.Form))
				{
					highPc = highPcValue.Value;
				}
				else if (attribute.Kind == ElfDwarfAttributeValueKind.Unsigned && lowPc.HasValue)
				{
					highPc = checked(lowPc.Value + attribute.UnsignedValue);
				}
				else if (attribute.Kind == ElfDwarfAttributeValueKind.Signed && lowPc.HasValue && attribute.SignedValue >= 0)
				{
					highPc = checked(lowPc.Value + (ulong)attribute.SignedValue);
				}
			}
		}

		return (lowPc, highPc);
	}

	private static string GetDwarfAttributeString(ElfDwarfDie die, ulong name, DwarfUnitMappingContext context)
	{
		for (var i = 0; i < die.Attributes.Count; i++)
		{
			var attribute = die.Attributes[i];
			if (attribute.Name != name)
				continue;
			if (attribute.Kind == ElfDwarfAttributeValueKind.String)
				return attribute.StringValue;

			if (TryResolveDwarfStringAttribute(attribute, context, out var text))
				return text;
		}

		return string.Empty;
	}

	private static bool TryGetDwarfAttribute(ElfDwarfDie die, ulong name, out ElfDwarfAttributeValue attribute)
	{
		for (var i = 0; i < die.Attributes.Count; i++)
		{
			var candidate = die.Attributes[i];
			if (candidate.Name != name)
				continue;
			attribute = candidate;
			return true;
		}

		attribute = null;
		return false;
	}

	private static ulong? GetDwarfAttributeUnsigned(ElfDwarfDie die, ulong name)
	{
		if (!TryGetDwarfAttribute(die, name, out var attribute))
			return null;

		return attribute.Kind switch
		{
			ElfDwarfAttributeValueKind.Unsigned => attribute.UnsignedValue,
			ElfDwarfAttributeValueKind.Address => attribute.UnsignedValue,
			ElfDwarfAttributeValueKind.Reference => attribute.UnsignedValue,
			ElfDwarfAttributeValueKind.Signed when attribute.SignedValue >= 0 => (ulong)attribute.SignedValue,
			_ => null
		};
	}

	private static ulong? GetDwarfAttributeAddress(ElfDwarfDie die, ulong name, DwarfUnitMappingContext context)
	{
		if (!TryGetDwarfAttribute(die, name, out var attribute))
			return null;

		return GetDwarfAttributeAddressValue(attribute, context);
	}

	private static ulong? GetDwarfAttributeAddressValue(ElfDwarfAttributeValue attribute, DwarfUnitMappingContext context)
	{
		if (attribute == null)
			return null;

		if (attribute.Kind == ElfDwarfAttributeValueKind.Address)
			return attribute.UnsignedValue;

		if (attribute.Kind == ElfDwarfAttributeValueKind.Unsigned && IsDwarfAddrIndexForm(attribute.Form))
		{
			if (TryResolveDebugAddrIndex(context, attribute.UnsignedValue, out var resolvedAddress))
				return resolvedAddress;
			return null;
		}

		if (attribute.Kind == ElfDwarfAttributeValueKind.Unsigned)
			return attribute.UnsignedValue;

		if (attribute.Kind == ElfDwarfAttributeValueKind.Signed && attribute.SignedValue >= 0)
			return (ulong)attribute.SignedValue;

		return null;
	}

	private static bool TryResolveDwarfStringAttribute(ElfDwarfAttributeValue attribute, DwarfUnitMappingContext context, out string text)
	{
		text = string.Empty;
		if (attribute == null || !IsDwarfStrIndexForm(attribute.Form))
			return false;
		if (context.DebugStrPayload == null || context.DebugStrPayload.Length == 0)
			return false;
		if (!context.StrOffsetsBase.HasValue)
			return false;

		if (!TryResolveOffsetTableIndex(
			context.DebugStrOffsetsPayload,
			context.IsLittleEndian,
			context.IsDwarf64,
			context.StrOffsetsBase.Value,
			attribute.UnsignedValue,
			out var stringOffset))
		{
			return false;
		}

		return TryReadDwarfStringAtOffset(context.DebugStrPayload, stringOffset, out text);
	}

	private static bool IsDwarfAddressForm(ulong form)
	{
		return form == DwFormAddr
			|| IsDwarfAddrIndexForm(form);
	}

	private static bool IsDwarfAddrIndexForm(ulong form)
	{
		return form is DwFormAddrx or DwFormAddrx1 or DwFormAddrx2 or DwFormAddrx3 or DwFormAddrx4;
	}

	private static bool IsDwarfStrIndexForm(ulong form)
	{
		return form is DwFormStrx or DwFormStrx1 or DwFormStrx2 or DwFormStrx3 or DwFormStrx4;
	}

	private static int GetDwarfAddressByteSize(DwarfUnitMappingContext context)
	{
		if (context.AddressSize is >= 1 and <= 8)
			return context.AddressSize;
		return context.IsDwarf64 ? 8 : 4;
	}

	private static bool TryResolveDebugAddrIndex(DwarfUnitMappingContext context, ulong index, out ulong address)
	{
		address = 0;
		if (context.DebugAddrPayload == null || context.DebugAddrPayload.Length == 0)
			return false;

		var addressSize = GetDwarfAddressByteSize(context);
		var baseOffset = context.AddrBase ?? 0;
		if (TryReadAddressEntryAt(context.DebugAddrPayload, context.IsLittleEndian, baseOffset, index, addressSize, out address))
			return true;

		var contributionHeaderSize = context.IsDwarf64 ? 16UL : 8UL;
		if (baseOffset <= ulong.MaxValue - contributionHeaderSize
			&& TryReadAddressEntryAt(
				context.DebugAddrPayload,
				context.IsLittleEndian,
				baseOffset + contributionHeaderSize,
				index,
				addressSize,
				out address))
		{
			return true;
		}

		return false;
	}

	private static bool TryReadAddressEntryAt(
		byte[] payload,
		bool isLittleEndian,
		ulong entriesStart,
		ulong index,
		int addressSize,
		out ulong address)
	{
		address = 0;
		if (payload == null || payload.Length == 0)
			return false;
		if (addressSize is < 1 or > 8)
			return false;
		if (index > int.MaxValue)
			return false;
		if (entriesStart > int.MaxValue)
			return false;

		var indexOffset = checked((ulong)addressSize * index);
		if (entriesStart > ulong.MaxValue - indexOffset)
			return false;
		var entryOffset = entriesStart + indexOffset;

		return TryReadUnsignedAt(payload, isLittleEndian, entryOffset, addressSize, out address);
	}

	private static bool TryResolveOffsetTableIndex(
		byte[] payload,
		bool isLittleEndian,
		bool isDwarf64,
		ulong baseOffset,
		ulong index,
		out ulong value)
	{
		value = 0;
		if (payload == null || payload.Length == 0)
			return false;

		var entrySize = isDwarf64 ? 8 : 4;
		if (TryReadOffsetEntry(payload, isLittleEndian, baseOffset, index, entrySize, out value))
			return true;

		var contributionHeaderSize = isDwarf64 ? 16UL : 8UL;
		if (baseOffset <= ulong.MaxValue - contributionHeaderSize
			&& TryReadOffsetEntry(payload, isLittleEndian, baseOffset + contributionHeaderSize, index, entrySize, out value))
		{
			return true;
		}

		return false;
	}

	private static bool TryReadOffsetEntry(
		byte[] payload,
		bool isLittleEndian,
		ulong tableStart,
		ulong index,
		int entrySize,
		out ulong value)
	{
		value = 0;
		if (entrySize is not (4 or 8))
			return false;
		if (tableStart > int.MaxValue || index > int.MaxValue)
			return false;

		var indexBytes = checked((ulong)entrySize * index);
		if (tableStart > ulong.MaxValue - indexBytes)
			return false;
		var entryOffset = tableStart + indexBytes;
		return TryReadUnsignedAt(payload, isLittleEndian, entryOffset, entrySize, out value);
	}

	private static bool TryReadUnsignedAt(ReadOnlySpan<byte> payload, bool isLittleEndian, ulong offset, int size, out ulong value)
	{
		value = 0;
		if (size is < 1 or > 8)
			return false;
		if (offset > int.MaxValue)
			return false;

		var cursor = (int)offset;
		if (cursor < 0 || cursor + size > payload.Length)
			return false;

		return TryReadUnsigned(payload, isLittleEndian, ref cursor, payload.Length, size, out value);
	}

	private static List<(ulong Start, ulong End)> ParseDwarfRangesAttribute(
		ElfDwarfAttributeValue attribute,
		DwarfUnitMappingContext context)
	{
		var ranges = new List<(ulong Start, ulong End)>();
		if (attribute == null)
			return ranges;

		if (context.DebugRnglistsPayload != null
			&& context.DebugRnglistsPayload.Length > 0
			&& (attribute.Form == DwFormRnglistx || attribute.Form == DwFormSecOffset))
		{
			if (TryResolveRngListStartOffset(attribute, context, out var listOffset))
				ParseDwarfRngListAtOffset(context, listOffset, ranges);
			return ranges;
		}

		if (context.DebugRangesPayload != null
			&& context.DebugRangesPayload.Length > 0
			&& (attribute.Kind is ElfDwarfAttributeValueKind.Unsigned or ElfDwarfAttributeValueKind.Reference))
		{
			ParseLegacyDebugRanges(context, attribute.UnsignedValue, ranges);
		}

		return ranges;
	}

	private static bool TryResolveRngListStartOffset(
		ElfDwarfAttributeValue attribute,
		DwarfUnitMappingContext context,
		out ulong listOffset)
	{
		listOffset = 0;
		var payloadLength = context.DebugRnglistsPayload == null ? 0UL : (ulong)context.DebugRnglistsPayload.Length;
		if (payloadLength == 0)
			return false;

		if (attribute.Form == DwFormRnglistx)
		{
			if (!context.RnglistsBase.HasValue)
				return false;

			if (!TryResolveOffsetTableIndex(
				context.DebugRnglistsPayload,
				context.IsLittleEndian,
				context.IsDwarf64,
				context.RnglistsBase.Value,
				attribute.UnsignedValue,
				out var indexValue))
			{
				return false;
			}

			if (indexValue < payloadLength)
			{
				listOffset = indexValue;
				return true;
			}

			if (context.RnglistsBase.Value <= ulong.MaxValue - indexValue)
			{
				var relative = context.RnglistsBase.Value + indexValue;
				if (relative < payloadLength)
				{
					listOffset = relative;
					return true;
				}
			}

			return false;
		}

		if (attribute.Form == DwFormSecOffset)
		{
			if (attribute.UnsignedValue < payloadLength)
			{
				listOffset = attribute.UnsignedValue;
				return true;
			}
		}

		return false;
	}

	private static void ParseDwarfRngListAtOffset(
		DwarfUnitMappingContext context,
		ulong listOffset,
		List<(ulong Start, ulong End)> ranges)
	{
		if (listOffset > int.MaxValue)
			return;
		if (context.DebugRnglistsPayload == null || context.DebugRnglistsPayload.Length == 0)
			return;

		var payload = context.DebugRnglistsPayload.AsSpan();
		var cursor = (int)listOffset;
		var addressSize = GetDwarfAddressByteSize(context);
		var baseAddress = context.LowPcBaseAddress ?? 0;
		var hasBaseAddress = context.LowPcBaseAddress.HasValue;
		var iterations = 0UL;

		while (cursor < payload.Length && iterations < MaxParserEntryCount)
		{
			iterations++;
			var kind = payload[cursor++];
			switch (kind)
			{
				case DwRleEndOfList:
					return;
				case DwRleBaseAddressx:
					if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var baseIndex))
						return;
					if (!TryResolveDebugAddrIndex(context, baseIndex, out baseAddress))
						return;
					hasBaseAddress = true;
					break;
				case DwRleBaseAddress:
					if (!TryReadUnsigned(payload, context.IsLittleEndian, ref cursor, payload.Length, addressSize, out baseAddress))
						return;
					hasBaseAddress = true;
					break;
				case DwRleStartxEndx:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var startIndex))
						return;
					if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var endIndex))
						return;
					if (!TryResolveDebugAddrIndex(context, startIndex, out var startAddress))
						return;
					if (!TryResolveDebugAddrIndex(context, endIndex, out var endAddress))
						return;
					TryAddAddressRange(ranges, startAddress, endAddress);
					break;
				}
				case DwRleStartxLength:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var startIndex))
						return;
					if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var length))
						return;
					if (!TryResolveDebugAddrIndex(context, startIndex, out var startAddress))
						return;
					if (!TryAddUnsigned(startAddress, length, out var endAddress))
						return;
					TryAddAddressRange(ranges, startAddress, endAddress);
					break;
				}
				case DwRleOffsetPair:
				{
					if (!hasBaseAddress)
						return;
					if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var startOffset))
						return;
					if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var endOffset))
						return;
					if (!TryAddUnsigned(baseAddress, startOffset, out var startAddress))
						return;
					if (!TryAddUnsigned(baseAddress, endOffset, out var endAddress))
						return;
					TryAddAddressRange(ranges, startAddress, endAddress);
					break;
				}
				case DwRleStartEnd:
				{
					if (!TryReadUnsigned(payload, context.IsLittleEndian, ref cursor, payload.Length, addressSize, out var startAddress))
						return;
					if (!TryReadUnsigned(payload, context.IsLittleEndian, ref cursor, payload.Length, addressSize, out var endAddress))
						return;
					TryAddAddressRange(ranges, startAddress, endAddress);
					break;
				}
				case DwRleStartLength:
				{
					if (!TryReadUnsigned(payload, context.IsLittleEndian, ref cursor, payload.Length, addressSize, out var startAddress))
						return;
					if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var length))
						return;
					if (!TryAddUnsigned(startAddress, length, out var endAddress))
						return;
					TryAddAddressRange(ranges, startAddress, endAddress);
					break;
				}
				default:
					return;
			}
		}
	}

	private static void ParseLegacyDebugRanges(
		DwarfUnitMappingContext context,
		ulong listOffset,
		List<(ulong Start, ulong End)> ranges)
	{
		if (listOffset > int.MaxValue)
			return;
		if (context.DebugRangesPayload == null || context.DebugRangesPayload.Length == 0)
			return;

		var payload = context.DebugRangesPayload.AsSpan();
		var addressSize = GetDwarfAddressByteSize(context);
		var maxAddressValue = GetDwarfAddressAllOnes(addressSize);
		var cursor = (int)listOffset;
		var baseAddress = context.LowPcBaseAddress ?? 0;
		var hasBaseAddress = context.LowPcBaseAddress.HasValue;
		var iterations = 0UL;

		while (cursor < payload.Length && iterations < MaxParserEntryCount)
		{
			iterations++;
			if (!TryReadUnsigned(payload, context.IsLittleEndian, ref cursor, payload.Length, addressSize, out var start))
				return;
			if (!TryReadUnsigned(payload, context.IsLittleEndian, ref cursor, payload.Length, addressSize, out var end))
				return;

			if (start == 0 && end == 0)
				return;

			if (start == maxAddressValue)
			{
				baseAddress = end;
				hasBaseAddress = true;
				continue;
			}

			if (hasBaseAddress)
			{
				if (!TryAddUnsigned(baseAddress, start, out start))
					return;
				if (!TryAddUnsigned(baseAddress, end, out end))
					return;
			}

			TryAddAddressRange(ranges, start, end);
		}
	}

	private static List<(ulong Start, ulong End)> ParseDwarfLocationRanges(
		ElfDwarfAttributeValue attribute,
		DwarfUnitMappingContext context)
	{
		var ranges = new List<(ulong Start, ulong End)>();
		if (attribute == null || context.DebugLoclistsPayload == null || context.DebugLoclistsPayload.Length == 0)
			return ranges;

		if (attribute.Form != DwFormLoclistx && attribute.Form != DwFormSecOffset)
			return ranges;

		if (!TryResolveLocListStartOffset(attribute, context, out var listOffset))
			return ranges;

		ParseDwarfLocListAtOffset(context, listOffset, ranges);
		return ranges;
	}

	private static bool TryResolveLocListStartOffset(
		ElfDwarfAttributeValue attribute,
		DwarfUnitMappingContext context,
		out ulong listOffset)
	{
		listOffset = 0;
		var payloadLength = context.DebugLoclistsPayload == null ? 0UL : (ulong)context.DebugLoclistsPayload.Length;
		if (payloadLength == 0)
			return false;

		if (attribute.Form == DwFormLoclistx)
		{
			if (!context.LoclistsBase.HasValue)
				return false;
			if (!TryResolveOffsetTableIndex(
				context.DebugLoclistsPayload,
				context.IsLittleEndian,
				context.IsDwarf64,
				context.LoclistsBase.Value,
				attribute.UnsignedValue,
				out var indexValue))
			{
				return false;
			}

			if (indexValue < payloadLength)
			{
				listOffset = indexValue;
				return true;
			}

			if (context.LoclistsBase.Value <= ulong.MaxValue - indexValue)
			{
				var relative = context.LoclistsBase.Value + indexValue;
				if (relative < payloadLength)
				{
					listOffset = relative;
					return true;
				}
			}

			return false;
		}

		if (attribute.Form == DwFormSecOffset && attribute.UnsignedValue < payloadLength)
		{
			listOffset = attribute.UnsignedValue;
			return true;
		}

		return false;
	}

	private static void ParseDwarfLocListAtOffset(
		DwarfUnitMappingContext context,
		ulong listOffset,
		List<(ulong Start, ulong End)> ranges)
	{
		if (listOffset > int.MaxValue)
			return;
		if (context.DebugLoclistsPayload == null || context.DebugLoclistsPayload.Length == 0)
			return;

		var payload = context.DebugLoclistsPayload.AsSpan();
		var cursor = (int)listOffset;
		var addressSize = GetDwarfAddressByteSize(context);
		var baseAddress = context.LowPcBaseAddress ?? 0;
		var hasBaseAddress = context.LowPcBaseAddress.HasValue;
		var iterations = 0UL;

		while (cursor < payload.Length && iterations < MaxParserEntryCount)
		{
			iterations++;
			var kind = payload[cursor++];
			switch (kind)
			{
				case DwLleEndOfList:
					return;
				case DwLleBaseAddressx:
					if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var baseIndex))
						return;
					if (!TryResolveDebugAddrIndex(context, baseIndex, out baseAddress))
						return;
					hasBaseAddress = true;
					break;
				case DwLleBaseAddress:
					if (!TryReadUnsigned(payload, context.IsLittleEndian, ref cursor, payload.Length, addressSize, out baseAddress))
						return;
					hasBaseAddress = true;
					break;
				case DwLleDefaultLocation:
					if (!TrySkipLocationExpression(payload, ref cursor))
						return;
					break;
				case DwLleStartxEndx:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var startIndex))
						return;
					if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var endIndex))
						return;
					if (!TryResolveDebugAddrIndex(context, startIndex, out var startAddress))
						return;
					if (!TryResolveDebugAddrIndex(context, endIndex, out var endAddress))
						return;
					if (!TrySkipLocationExpression(payload, ref cursor))
						return;
					TryAddAddressRange(ranges, startAddress, endAddress);
					break;
				}
				case DwLleStartxLength:
				{
					if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var startIndex))
						return;
					if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var length))
						return;
					if (!TryResolveDebugAddrIndex(context, startIndex, out var startAddress))
						return;
					if (!TryAddUnsigned(startAddress, length, out var endAddress))
						return;
					if (!TrySkipLocationExpression(payload, ref cursor))
						return;
					TryAddAddressRange(ranges, startAddress, endAddress);
					break;
				}
				case DwLleOffsetPair:
				{
					if (!hasBaseAddress)
						return;
					if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var startOffset))
						return;
					if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var endOffset))
						return;
					if (!TrySkipLocationExpression(payload, ref cursor))
						return;
					if (!TryAddUnsigned(baseAddress, startOffset, out var startAddress))
						return;
					if (!TryAddUnsigned(baseAddress, endOffset, out var endAddress))
						return;
					TryAddAddressRange(ranges, startAddress, endAddress);
					break;
				}
				case DwLleStartEnd:
				{
					if (!TryReadUnsigned(payload, context.IsLittleEndian, ref cursor, payload.Length, addressSize, out var startAddress))
						return;
					if (!TryReadUnsigned(payload, context.IsLittleEndian, ref cursor, payload.Length, addressSize, out var endAddress))
						return;
					if (!TrySkipLocationExpression(payload, ref cursor))
						return;
					TryAddAddressRange(ranges, startAddress, endAddress);
					break;
				}
				case DwLleStartLength:
				{
					if (!TryReadUnsigned(payload, context.IsLittleEndian, ref cursor, payload.Length, addressSize, out var startAddress))
						return;
					if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var length))
						return;
					if (!TrySkipLocationExpression(payload, ref cursor))
						return;
					if (!TryAddUnsigned(startAddress, length, out var endAddress))
						return;
					TryAddAddressRange(ranges, startAddress, endAddress);
					break;
				}
				default:
					return;
			}
		}
	}

	private static bool TrySkipLocationExpression(ReadOnlySpan<byte> payload, ref int cursor)
	{
		if (!TryReadUleb128Bounded(payload, ref cursor, payload.Length, out var expressionLength))
			return false;
		if (expressionLength > int.MaxValue)
			return false;
		var length = (int)expressionLength;
		if (length > payload.Length - cursor)
			return false;

		cursor += length;
		return true;
	}

	private static ulong GetDwarfAddressAllOnes(int addressSize)
	{
		return addressSize switch
		{
			1 => byte.MaxValue,
			2 => ushort.MaxValue,
			3 => 0x00FFFFFFUL,
			4 => uint.MaxValue,
			5 => 0xFFFFFFFFFFUL,
			6 => 0xFFFFFFFFFFFFUL,
			7 => 0xFFFFFFFFFFFFFFUL,
			_ => ulong.MaxValue
		};
	}

	private static bool TryAddUnsigned(ulong left, ulong right, out ulong value)
	{
		value = 0;
		try
		{
			value = checked(left + right);
			return true;
		}
		catch (OverflowException)
		{
			return false;
		}
	}

	private static void TryAddAddressRange(List<(ulong Start, ulong End)> ranges, ulong start, ulong end)
	{
		if (end <= start)
			return;

		for (var i = 0; i < ranges.Count; i++)
		{
			var current = ranges[i];
			if (current.Start == start && current.End == end)
				return;
		}

		ranges.Add((start, end));
	}

	private static bool GetDwarfAttributeFlag(ElfDwarfDie die, ulong name)
	{
		for (var i = 0; i < die.Attributes.Count; i++)
		{
			var attribute = die.Attributes[i];
			if (attribute.Name != name)
				continue;
			if (attribute.Kind != ElfDwarfAttributeValueKind.Flag)
				continue;
			return attribute.BoolValue;
		}

		return false;
	}

	private static void AddCandidate(
		Dictionary<string, List<DwarfDieSymbolCandidate>> map,
		string key,
		DwarfDieSymbolCandidate candidate)
	{
		if (!map.TryGetValue(key, out var list))
		{
			list = new List<DwarfDieSymbolCandidate>();
			map[key] = list;
		}

		list.Add(candidate);
	}

	private static string GetDwarfTagName(ulong tag)
	{
		return tag switch
		{
			0x01 => "DW_TAG_array_type",
			0x02 => "DW_TAG_class_type",
			0x03 => "DW_TAG_entry_point",
			0x04 => "DW_TAG_enumeration_type",
			0x05 => "DW_TAG_formal_parameter",
			0x08 => "DW_TAG_imported_declaration",
			0x0A => "DW_TAG_label",
			0x0B => "DW_TAG_lexical_block",
			0x0D => "DW_TAG_member",
			0x0F => "DW_TAG_pointer_type",
			0x10 => "DW_TAG_reference_type",
			0x11 => "DW_TAG_compile_unit",
			0x12 => "DW_TAG_string_type",
			0x13 => "DW_TAG_structure_type",
			0x15 => "DW_TAG_subroutine_type",
			0x16 => "DW_TAG_typedef",
			0x17 => "DW_TAG_union_type",
			0x18 => "DW_TAG_unspecified_parameters",
			0x19 => "DW_TAG_variant",
			0x1A => "DW_TAG_common_block",
			0x1B => "DW_TAG_common_inclusion",
			0x1C => "DW_TAG_inheritance",
			0x1D => "DW_TAG_inlined_subroutine",
			0x1E => "DW_TAG_module",
			0x1F => "DW_TAG_ptr_to_member_type",
			0x20 => "DW_TAG_set_type",
			0x21 => "DW_TAG_subrange_type",
			0x22 => "DW_TAG_with_stmt",
			0x24 => "DW_TAG_base_type",
			0x25 => "DW_TAG_catch_block",
			0x26 => "DW_TAG_const_type",
			0x27 => "DW_TAG_constant",
			0x28 => "DW_TAG_enumerator",
			0x29 => "DW_TAG_file_type",
			0x2A => "DW_TAG_friend",
			0x2B => "DW_TAG_namelist",
			0x2C => "DW_TAG_namelist_item",
			0x2E => "DW_TAG_subprogram",
			0x2F => "DW_TAG_template_type_parameter",
			0x30 => "DW_TAG_template_value_parameter",
			0x31 => "DW_TAG_thrown_type",
			0x32 => "DW_TAG_try_block",
			0x34 => "DW_TAG_variable",
			0x35 => "DW_TAG_volatile_type",
			0x39 => "DW_TAG_namespace",
			0x3A => "DW_TAG_imported_module",
			0x3B => "DW_TAG_unspecified_type",
			0x3C => "DW_TAG_partial_unit",
			0x41 => "DW_TAG_type_unit",
			0x42 => "DW_TAG_rvalue_reference_type",
			0x43 => "DW_TAG_template_alias",
			0x44 => "DW_TAG_coarray_type",
			0x45 => "DW_TAG_generic_subrange",
			0x46 => "DW_TAG_dynamic_type",
			0x47 => "DW_TAG_atomic_type",
			0x48 => "DW_TAG_call_site",
			0x49 => "DW_TAG_call_site_parameter",
			0x4A => "DW_TAG_skeleton_unit",
			0x4B => "DW_TAG_immutable_type",
			_ => FormatUnknownDwarfCode("DW_TAG", tag, DwTagLoUser, DwTagHiUser)
		};
	}

	private static string GetDwarfAttributeName(ulong attribute)
	{
		return attribute switch
		{
			0x01 => "DW_AT_sibling",
			0x02 => "DW_AT_location",
			0x03 => "DW_AT_name",
			0x09 => "DW_AT_ordering",
			0x0B => "DW_AT_byte_size",
			0x0C => "DW_AT_bit_offset",
			0x0D => "DW_AT_bit_size",
			0x10 => "DW_AT_stmt_list",
			0x11 => "DW_AT_low_pc",
			0x12 => "DW_AT_high_pc",
			0x13 => "DW_AT_language",
			0x15 => "DW_AT_discr",
			0x16 => "DW_AT_discr_value",
			0x17 => "DW_AT_visibility",
			0x18 => "DW_AT_import",
			0x19 => "DW_AT_string_length",
			0x1A => "DW_AT_common_reference",
			0x1B => "DW_AT_comp_dir",
			0x1C => "DW_AT_const_value",
			0x1D => "DW_AT_containing_type",
			0x1E => "DW_AT_default_value",
			0x20 => "DW_AT_inline",
			0x21 => "DW_AT_is_optional",
			0x22 => "DW_AT_lower_bound",
			0x25 => "DW_AT_producer",
			0x27 => "DW_AT_prototyped",
			0x2A => "DW_AT_return_addr",
			0x2C => "DW_AT_start_scope",
			0x2E => "DW_AT_bit_stride",
			0x2F => "DW_AT_upper_bound",
			0x31 => "DW_AT_abstract_origin",
			0x32 => "DW_AT_accessibility",
			0x33 => "DW_AT_address_class",
			0x34 => "DW_AT_artificial",
			0x35 => "DW_AT_base_types",
			0x36 => "DW_AT_calling_convention",
			0x37 => "DW_AT_count",
			0x38 => "DW_AT_data_member_location",
			0x39 => "DW_AT_decl_column",
			0x3A => "DW_AT_decl_file",
			0x3B => "DW_AT_decl_line",
			0x3C => "DW_AT_declaration",
			0x3D => "DW_AT_discr_list",
			0x3E => "DW_AT_encoding",
			0x3F => "DW_AT_external",
			0x40 => "DW_AT_frame_base",
			0x41 => "DW_AT_friend",
			0x42 => "DW_AT_identifier_case",
			0x43 => "DW_AT_macro_info",
			0x44 => "DW_AT_namelist_item",
			0x45 => "DW_AT_priority",
			0x46 => "DW_AT_segment",
			0x47 => "DW_AT_specification",
			0x48 => "DW_AT_static_link",
			0x49 => "DW_AT_type",
			0x4A => "DW_AT_use_location",
			0x4B => "DW_AT_variable_parameter",
			0x4C => "DW_AT_virtuality",
			0x4D => "DW_AT_vtable_elem_location",
			0x4E => "DW_AT_allocated",
			0x4F => "DW_AT_associated",
			0x50 => "DW_AT_data_location",
			0x51 => "DW_AT_byte_stride",
			0x52 => "DW_AT_entry_pc",
			0x53 => "DW_AT_use_UTF8",
			0x54 => "DW_AT_extension",
			0x55 => "DW_AT_ranges",
			0x56 => "DW_AT_trampoline",
			0x57 => "DW_AT_call_column",
			0x58 => "DW_AT_call_file",
			0x59 => "DW_AT_call_line",
			0x5A => "DW_AT_description",
			0x5B => "DW_AT_binary_scale",
			0x5C => "DW_AT_decimal_scale",
			0x5D => "DW_AT_small",
			0x5E => "DW_AT_decimal_sign",
			0x5F => "DW_AT_digit_count",
			0x60 => "DW_AT_picture_string",
			0x61 => "DW_AT_mutable",
			0x62 => "DW_AT_threads_scaled",
			0x63 => "DW_AT_explicit",
			0x64 => "DW_AT_object_pointer",
			0x65 => "DW_AT_endianity",
			0x66 => "DW_AT_elemental",
			0x67 => "DW_AT_pure",
			0x68 => "DW_AT_recursive",
			0x69 => "DW_AT_signature",
			0x6A => "DW_AT_main_subprogram",
			0x6B => "DW_AT_data_bit_offset",
			0x6C => "DW_AT_const_expr",
			0x6D => "DW_AT_enum_class",
			0x6E => "DW_AT_linkage_name",
			0x6F => "DW_AT_string_length_bit_size",
			0x70 => "DW_AT_string_length_byte_size",
			0x71 => "DW_AT_rank",
			0x72 => "DW_AT_str_offsets_base",
			0x73 => "DW_AT_addr_base",
			0x74 => "DW_AT_rnglists_base",
			0x75 => "DW_AT_dwo_name",
			0x76 => "DW_AT_reference",
			0x77 => "DW_AT_rvalue_reference",
			0x78 => "DW_AT_macros",
			0x79 => "DW_AT_call_all_calls",
			0x7A => "DW_AT_call_all_source_calls",
			0x7B => "DW_AT_call_all_tail_calls",
			0x7C => "DW_AT_call_return_pc",
			0x7D => "DW_AT_call_value",
			0x7E => "DW_AT_call_origin",
			0x7F => "DW_AT_call_parameter",
			0x80 => "DW_AT_call_pc",
			0x81 => "DW_AT_call_tail_call",
			0x82 => "DW_AT_call_target",
			0x83 => "DW_AT_call_target_clobbered",
			0x84 => "DW_AT_call_data_location",
			0x85 => "DW_AT_call_data_value",
			0x86 => "DW_AT_noreturn",
			0x87 => "DW_AT_alignment",
			0x88 => "DW_AT_export_symbols",
			0x89 => "DW_AT_deleted",
			0x8A => "DW_AT_defaulted",
			0x8B => "DW_AT_loclists_base",
			0x2007 => "DW_AT_MIPS_linkage_name",
			_ => FormatUnknownDwarfCode("DW_AT", attribute, DwAtLoUser, DwAtHiUser)
		};
	}

	private static string GetDwarfFormName(ulong form)
	{
		return form switch
		{
			DwFormAddr => "DW_FORM_addr",
			DwFormBlock2 => "DW_FORM_block2",
			DwFormBlock4 => "DW_FORM_block4",
			DwFormData2 => "DW_FORM_data2",
			DwFormData4 => "DW_FORM_data4",
			DwFormData8 => "DW_FORM_data8",
			DwFormString => "DW_FORM_string",
			DwFormBlock => "DW_FORM_block",
			DwFormBlock1 => "DW_FORM_block1",
			DwFormData1 => "DW_FORM_data1",
			DwFormFlag => "DW_FORM_flag",
			DwFormSData => "DW_FORM_sdata",
			DwFormStrp => "DW_FORM_strp",
			DwFormUData => "DW_FORM_udata",
			DwFormRefAddr => "DW_FORM_ref_addr",
			DwFormRef1 => "DW_FORM_ref1",
			DwFormRef2 => "DW_FORM_ref2",
			DwFormRef4 => "DW_FORM_ref4",
			DwFormRef8 => "DW_FORM_ref8",
			DwFormRefUData => "DW_FORM_ref_udata",
			DwFormIndirect => "DW_FORM_indirect",
			DwFormSecOffset => "DW_FORM_sec_offset",
			DwFormExprLoc => "DW_FORM_exprloc",
			DwFormFlagPresent => "DW_FORM_flag_present",
			DwFormStrx => "DW_FORM_strx",
			DwFormAddrx => "DW_FORM_addrx",
			DwFormRefSup4 => "DW_FORM_ref_sup4",
			DwFormStrpSup => "DW_FORM_strp_sup",
			DwFormData16 => "DW_FORM_data16",
			DwFormLineStrp => "DW_FORM_line_strp",
			DwFormRefSig8 => "DW_FORM_ref_sig8",
			DwFormImplicitConst => "DW_FORM_implicit_const",
			DwFormLoclistx => "DW_FORM_loclistx",
			DwFormRnglistx => "DW_FORM_rnglistx",
			DwFormRefSup8 => "DW_FORM_ref_sup8",
			DwFormStrx1 => "DW_FORM_strx1",
			DwFormStrx2 => "DW_FORM_strx2",
			DwFormStrx3 => "DW_FORM_strx3",
			DwFormStrx4 => "DW_FORM_strx4",
			DwFormAddrx1 => "DW_FORM_addrx1",
				DwFormAddrx2 => "DW_FORM_addrx2",
				DwFormAddrx3 => "DW_FORM_addrx3",
				DwFormAddrx4 => "DW_FORM_addrx4",
				DwFormGnuRefAlt => "DW_FORM_GNU_ref_alt",
				DwFormGnuStrpAlt => "DW_FORM_GNU_strp_alt",
				_ => FormatUnknownDwarfCode("DW_FORM", form, DwFormLoUser, DwFormHiUser)
			};
		}

	private static string FormatUnknownDwarfCode(string prefix, ulong value, ulong loUser, ulong hiUser)
	{
		if (value >= loUser && value <= hiUser)
			return $"{prefix}_lo_user+0x{value - loUser:X}";

		return $"{prefix}_0x{value:X}";
	}
}
