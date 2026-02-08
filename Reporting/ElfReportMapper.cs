namespace ELFInspector.Reporting;

public static class ElfReportMapper
{
	private const uint PtInterp = 3;
	private const uint PtGnuEhFrame = 0x6474E550;
	private const uint PtGnuStack = 0x6474E551;
	private const uint PtGnuRelro = 0x6474E552;
	private const uint PtGnuProperty = 0x6474E553;
	private const uint PtGnuSFrame = 0x6474E554;
	private const uint PtSunwBss = 0x6FFFFFFA;
	private const uint PtSunwStack = 0x6FFFFFFB;
	private const long DtBindNow = 24;
	private const long DtFlags = 30;
	private const long DtFlags1 = 0x6FFFFFFB;

	private const ulong DfBindNow = 0x8;
	private const ulong Df1Now = 0x1;
	private const ulong Df1Pie = 0x8000000;

	private const ulong ShfWrite = 0x1;
	private const ulong ShfAlloc = 0x2;
	private const ulong ShfExecInstr = 0x4;
	private const ulong ShfMerge = 0x10;
	private const ulong ShfStrings = 0x20;
	private const ulong ShfInfoLink = 0x40;
	private const ulong ShfLinkOrder = 0x80;
	private const ulong ShfOsNonConforming = 0x100;
	private const ulong ShfGroup = 0x200;
	private const ulong ShfTls = 0x400;
	private const ulong ShfCompressed = 0x800;
	private const ulong ShfMaskOs = 0x0FF00000;
	private const ulong ShfMaskProc = 0xF0000000;
	private const ulong ShfOrdered = 0x4000000;
	private const ulong ShfExclude = 0x8000000;

	private const uint PfX = 0x1;
	private const uint PfW = 0x2;
	private const uint PfR = 0x4;

	public static ElfReport Create(ELFInspector.Parser.ElfFile elf)
	{
		var symbols = elf.Symbols.Select(MapSymbol).ToList();
		var imports = elf.ImportedSymbols.Select(MapSymbol).ToList();
		var exports = elf.ExportedSymbols.Select(MapSymbol).ToList();

		var importLibrariesDetailed = imports
			.GroupBy(s => string.IsNullOrEmpty(s.Library) ? "(unknown)" : s.Library, StringComparer.Ordinal)
			.Select(group => new ImportLibraryReport
			{
				Name = group.Key,
				Symbols = group
					.Select(symbol => string.IsNullOrEmpty(symbol.QualifiedName) ? symbol.Name : symbol.QualifiedName)
					.Where(name => !string.IsNullOrEmpty(name))
					.Distinct(StringComparer.Ordinal)
					.OrderBy(name => name, StringComparer.Ordinal)
					.ToList()
			})
			.OrderBy(library => library.Name, StringComparer.Ordinal)
			.ToList();

		return new ElfReport
		{
			Header = new HeaderReport
			{
				Class = elf.Header.Class.ToString(),
				Endianness = elf.Header.DataEncoding.ToString(),
				Type = elf.Header.Type,
				TypeName = TranslateFileType(elf.Header.Type),
				MachineCode = elf.Header.Machine,
				Machine = TranslateMachine(elf.Header.Machine),
				OsAbiCode = elf.Header.OsAbi,
				OsAbi = TranslateOsAbi(elf.Header.OsAbi),
				AbiVersion = elf.Header.AbiVersion,
				Flags = elf.Header.Flags,
				EntryPoint = elf.Header.EntryPoint,
				Interpreter = elf.InterpreterPath,
				Soname = elf.Soname,
				RPath = elf.RPath,
				RunPath = elf.RunPath
			},
			HashTables = CreateHashTablesReport(elf),
			SectionSpecialCases = CreateSectionSpecialCasesReport(elf),
			Unwind = CreateUnwindReport(elf),
			Dwarf = CreateDwarfReport(elf),
			CoreDump = CreateCoreDumpReport(elf),
			Security = CreateSecurityFeatures(elf),
			Sections = elf.Sections.Select(s => new SectionReport
			{
				Name = s.Name,
				Type = s.Type,
				TypeName = TranslateSectionType(s.Type),
				Flags = s.Flags,
				FlagsText = FormatSectionFlags(s.Flags),
				Address = s.Address,
				Offset = s.Offset,
				Size = s.Size
			}).ToList(),
			Segments = elf.ProgramHeaders.Select(p => new SegmentReport
			{
				Type = p.Type,
				TypeName = TranslateSegmentType(p.Type),
				Flags = p.Flags,
				FlagsText = FormatSegmentFlags(p.Flags),
				Offset = p.Offset,
				VirtualAddress = p.VirtualAddress,
				PhysicalAddress = p.PhysicalAddress,
				FileSize = p.FileSize,
				MemorySize = p.MemorySize,
				Align = p.Align
			}).ToList(),
			Symbols = symbols,
			ImportedSymbols = imports,
			ExportedSymbols = exports,
			Relocations = elf.Relocations.Select(r => new RelocationReport
			{
				Offset = r.Offset,
				Info = r.Info,
				Encoding = r.Encoding,
				Addend = r.Addend,
				HasAddend = r.HasAddend,
				SymbolIndex = r.SymbolIndex,
				Type = r.Type,
				TypeName = r.TypeName,
				SymbolName = r.SymbolName,
				SymbolVersion = r.SymbolVersion,
				SymbolLibrary = r.SymbolLibrary,
				SourceSection = r.SourceSection,
				AppliesToSection = r.AppliesToSection,
				LoaderPath = r.LoaderPath,
				IsPltPath = r.IsPltPath,
				IsGotPath = r.IsGotPath,
				IsTlsPath = r.IsTlsPath
			}).ToList(),
			Dynamics = elf.DynamicEntries.Select(d => new DynamicReport
			{
				Tag = d.Tag,
				TagName = d.TagName,
				Value = d.Value,
				StringValue = d.StringValue,
				DecodedValue = d.DecodedValue
			}).ToList(),
			Notes = elf.Notes.Select(n => new NoteReport
			{
				Name = n.Name,
				Type = n.Type,
				TypeName = n.TypeName,
				DescriptionHex = BitConverter.ToString(n.Descriptor),
				DecodedDescription = n.DecodedDescription
			}).ToList(),
			Imports = elf.ImportLibraries,
			ImportLibrariesDetailed = importLibrariesDetailed
		};
	}

	private static SectionSpecialCasesReport CreateSectionSpecialCasesReport(ELFInspector.Parser.ElfFile elf)
	{
		return new SectionSpecialCasesReport
		{
			CompressedSections = elf.CompressedSections.Select(section => new CompressedSectionReport
			{
				Name = section.Name,
				CompressionType = section.CompressionType,
				CompressionTypeName = section.CompressionTypeName,
				CompressedSize = section.CompressedSize,
				UncompressedSize = section.UncompressedSize,
				Alignment = section.Alignment,
				IsGnuStyleZdebug = section.IsGnuStyleZdebug,
				DecompressionSucceeded = section.DecompressionSucceeded,
				Error = section.Error
			}).ToList(),
			SectionGroups = elf.SectionGroups.Select(group => new SectionGroupReport
			{
				Name = group.Name,
				Flags = group.Flags,
				IsComdat = group.IsComdat,
				SignatureSymbolIndex = group.SignatureSymbolIndex,
				SignatureSymbolName = group.SignatureSymbolName,
				MemberSectionIndexes = group.MemberSectionIndexes.ToList(),
				MemberSectionNames = group.MemberSectionNames.ToList()
			}).ToList()
		};
	}

	private static UnwindReport CreateUnwindReport(ELFInspector.Parser.ElfFile elf)
	{
		var unwind = elf.Unwind ?? new ELFInspector.Parser.ElfUnwindInfo();
		return new UnwindReport
		{
			EhFrame = new EhFrameReport
			{
				Present = unwind.EhFrame?.Present ?? false,
				Address = unwind.EhFrame?.Address ?? 0,
				Size = unwind.EhFrame?.Size ?? 0,
				CieCount = unwind.EhFrame?.CieCount ?? 0,
				FdeCount = unwind.EhFrame?.FdeCount ?? 0,
				TerminatorSeen = unwind.EhFrame?.TerminatorSeen ?? false,
				CieEntries = unwind.EhFrame?.CieEntries.Select(cie => new EhFrameCieReport
				{
					Index = cie.Index,
					Offset = cie.Offset,
					ContentLength = cie.ContentLength,
					IsDwarf64 = cie.IsDwarf64,
					CieId = cie.CieId,
					Version = cie.Version,
					Augmentation = cie.Augmentation,
					CodeAlignmentFactor = cie.CodeAlignmentFactor,
					DataAlignmentFactor = cie.DataAlignmentFactor,
					ReturnAddressRegister = cie.ReturnAddressRegister,
					FdePointerEncoding = cie.FdePointerEncoding,
					Instructions = cie.Instructions.ToList()
				}).ToList() ?? new List<EhFrameCieReport>(),
				FdeEntries = unwind.EhFrame?.FdeEntries.Select(fde => new EhFrameFdeReport
				{
					Index = fde.Index,
					Offset = fde.Offset,
					ContentLength = fde.ContentLength,
					IsDwarf64 = fde.IsDwarf64,
					CiePointer = fde.CiePointer,
					CieIndex = fde.CieIndex,
					InitialLocation = fde.InitialLocation,
					AddressRange = fde.AddressRange,
					EndLocation = fde.EndLocation,
					CfaRuleAvailable = fde.CfaRuleAvailable,
					CfaRegister = fde.CfaRegister,
					CfaOffset = fde.CfaOffset,
					ReturnAddressOffsetAvailable = fde.ReturnAddressOffsetAvailable,
					ReturnAddressOffset = fde.ReturnAddressOffset,
					Instructions = fde.Instructions.ToList()
				}).ToList() ?? new List<EhFrameFdeReport>()
			},
			EhFrameHeader = new EhFrameHeaderReport
			{
				Present = unwind.EhFrameHeader?.Present ?? false,
				Version = unwind.EhFrameHeader?.Version ?? 0,
				EhFramePointerEncoding = unwind.EhFrameHeader?.EhFramePointerEncoding ?? 0,
				FdeCountEncoding = unwind.EhFrameHeader?.FdeCountEncoding ?? 0,
				TableEncoding = unwind.EhFrameHeader?.TableEncoding ?? 0,
				EhFramePointerDecoded = unwind.EhFrameHeader?.EhFramePointerDecoded ?? false,
				EhFramePointer = unwind.EhFrameHeader?.EhFramePointer ?? 0,
				FdeCountDecoded = unwind.EhFrameHeader?.FdeCountDecoded ?? false,
				FdeCount = unwind.EhFrameHeader?.FdeCount ?? 0,
				ParsedTableEntries = unwind.EhFrameHeader?.ParsedTableEntries ?? 0
			},
			DebugSections = unwind.DebugSections.Select(section => new DebugSectionReport
			{
				Name = section.Name,
				Size = section.Size,
				IsCompressed = section.IsCompressed,
				UncompressedSize = section.UncompressedSize
			}).ToList()
		};
	}

	private static CoreDumpReport CreateCoreDumpReport(ELFInspector.Parser.ElfFile elf)
	{
		var coreDump = elf.CoreDump ?? new ELFInspector.Parser.ElfCoreDumpInfo();
		return new CoreDumpReport
		{
			IsCoreDump = coreDump.IsCoreDump,
			ProcessName = coreDump.ProcessName,
			ProcessId = coreDump.ProcessId,
			Signal = coreDump.Signal,
			AuxVectorEntryCount = coreDump.AuxVectorEntryCount,
			FileMappingCount = coreDump.FileMappingCount,
			Signals = coreDump.Signals.ToList(),
			Threads = coreDump.Threads.Select(thread => new CoreThreadReport
			{
				Index = thread.Index,
				ThreadId = thread.ThreadId,
				ParentProcessId = thread.ParentProcessId,
				ProcessGroupId = thread.ProcessGroupId,
				SessionId = thread.SessionId,
				Signal = thread.Signal,
				CurrentSignal = thread.CurrentSignal,
				RegisterPreview = thread.RegisterPreview.ToList()
			}).ToList(),
			UnwindThreads = coreDump.UnwindThreads.Select(thread => new CoreThreadUnwindReport
			{
				ThreadIndex = thread.ThreadIndex,
				ThreadId = thread.ThreadId,
				Strategy = thread.Strategy,
				Complete = thread.Complete,
				Frames = thread.Frames.Select(frame => new CoreUnwindFrameReport
				{
					Index = frame.Index,
					InstructionPointer = frame.InstructionPointer,
					StackPointer = frame.StackPointer,
					FramePointer = frame.FramePointer,
					SymbolName = frame.SymbolName,
					Strategy = frame.Strategy
				}).ToList()
			}).ToList()
		};
	}

	private static DwarfReport CreateDwarfReport(ELFInspector.Parser.ElfFile elf)
	{
		var dwarf = elf.Dwarf ?? new ELFInspector.Parser.ElfDwarfIndexInfo();
		return new DwarfReport
		{
			HasDebugInfo = dwarf.HasDebugInfo,
			HasDebugAbbrev = dwarf.HasDebugAbbrev,
			HasDebugLine = dwarf.HasDebugLine,
			HasDebugStr = dwarf.HasDebugStr,
			HasDebugRanges = dwarf.HasDebugRanges,
			HasDebugAddr = dwarf.HasDebugAddr,
			HasDebugStrOffsets = dwarf.HasDebugStrOffsets,
			HasDebugRngLists = dwarf.HasDebugRngLists,
			HasDebugLocLists = dwarf.HasDebugLocLists,
			CompileUnits = dwarf.CompileUnits.Select(unit => new DwarfCompileUnitReport
			{
				Offset = unit.Offset,
				UnitLength = unit.UnitLength,
				IsDwarf64 = unit.IsDwarf64,
				Version = unit.Version,
				UnitType = unit.UnitType,
				AbbrevOffset = unit.AbbrevOffset,
				AddressSize = unit.AddressSize
			}).ToList(),
			LineTables = dwarf.LineTables.Select(table => new DwarfLineTableReport
			{
				Offset = table.Offset,
				UnitLength = table.UnitLength,
				IsDwarf64 = table.IsDwarf64,
				Version = table.Version,
				AddressSize = table.AddressSize,
				SegmentSelectorSize = table.SegmentSelectorSize,
				HeaderLength = table.HeaderLength,
				MinimumInstructionLength = table.MinimumInstructionLength,
				MaximumOperationsPerInstruction = table.MaximumOperationsPerInstruction,
				DefaultIsStmt = table.DefaultIsStmt,
				LineBase = table.LineBase,
				LineRange = table.LineRange,
				OpcodeBase = table.OpcodeBase,
				IncludeDirectoryCount = table.IncludeDirectoryCount,
				FileNameEntryCount = table.FileNameEntryCount
			}).ToList(),
				SemanticUnits = dwarf.SemanticUnits.Select(unit => new DwarfSemanticUnitReport
				{
					Offset = unit.Offset,
					UnitLength = unit.UnitLength,
					IsDwarf64 = unit.IsDwarf64,
					Version = unit.Version,
					UnitType = unit.UnitType,
					AbbrevOffset = unit.AbbrevOffset,
					AddressSize = unit.AddressSize,
					RootDies = unit.RootDies.Select(MapDwarfDie).ToList(),
					PreservedRegions = unit.PreservedRegions.Select(region => new DwarfPreservedRegionReport
					{
						UnitRelativeOffset = region.UnitRelativeOffset,
						UnitRelativeLength = region.UnitRelativeLength,
						Reason = region.Reason,
						PreviewHex = region.PreviewHex
					}).ToList()
				}).ToList(),
			SymbolMappings = dwarf.SymbolMappings.Select(mapping => new DwarfSymbolMappingReport
			{
				SymbolName = mapping.SymbolName,
				SymbolAddress = mapping.SymbolAddress,
				DieOffset = mapping.DieOffset,
				DieTagText = mapping.DieTagText,
				MatchType = mapping.MatchType
			}).ToList(),
			Query = new DwarfQueryReport
			{
				Types = dwarf.Query.Types.Select(type => new DwarfTypeQueryReport
				{
					DieOffset = type.DieOffset,
					Name = type.Name,
					TagText = type.TagText,
					TypeDieOffset = type.TypeDieOffset,
					ByteSize = type.ByteSize,
					Encoding = type.Encoding,
					EncodingText = type.EncodingText,
					IsDeclaration = type.IsDeclaration
				}).ToList(),
				Functions = dwarf.Query.Functions.Select(function => new DwarfFunctionQueryReport
				{
					DieOffset = function.DieOffset,
					Name = function.Name,
					LinkageName = function.LinkageName,
					ReturnTypeDieOffset = function.ReturnTypeDieOffset,
					IsDeclaration = function.IsDeclaration,
					AddressRanges = function.AddressRanges.Select(range => new DwarfAddressRangeReport
					{
						Start = range.Start,
						End = range.End
					}).ToList(),
					Parameters = function.Parameters.Select(parameter => new DwarfFunctionParameterQueryReport
					{
						Name = parameter.Name,
						TypeDieOffset = parameter.TypeDieOffset
					}).ToList()
				}).ToList(),
				Variables = dwarf.Query.Variables.Select(variable => new DwarfVariableQueryReport
				{
					DieOffset = variable.DieOffset,
					Name = variable.Name,
					TypeDieOffset = variable.TypeDieOffset,
					IsExternal = variable.IsExternal,
					IsDeclaration = variable.IsDeclaration,
					AddressRanges = variable.AddressRanges.Select(range => new DwarfAddressRangeReport
					{
						Start = range.Start,
						End = range.End
					}).ToList()
				}).ToList()
			}
		};
	}

	private static DwarfDieReport MapDwarfDie(ELFInspector.Parser.ElfDwarfDie die)
	{
		return new DwarfDieReport
		{
			Offset = die.Offset,
			AbbrevCode = die.AbbrevCode,
			Tag = die.Tag,
			TagText = die.TagText,
			HasChildren = die.HasChildren,
				Attributes = die.Attributes.Select(attribute => new DwarfAttributeReport
				{
					Name = attribute.Name,
					NameText = attribute.NameText,
					Form = attribute.Form,
					FormText = attribute.FormText,
					Kind = attribute.Kind.ToString(),
					UnsignedValue = attribute.UnsignedValue,
					SignedValue = attribute.SignedValue,
					BoolValue = attribute.BoolValue,
					StringValue = attribute.StringValue,
					BytesHex = attribute.BytesValue == null || attribute.BytesValue.Length == 0
						? string.Empty
						: Convert.ToHexString(attribute.BytesValue),
					UnitRelativeValueOffset = attribute.UnitRelativeValueOffset,
					ConsumedByteCount = attribute.ConsumedByteCount,
					DecodeStatus = attribute.DecodeStatus.ToString(),
					DecodeNote = attribute.DecodeNote
				}).ToList(),
				Children = die.Children.Select(MapDwarfDie).ToList()
			};
		}

	private static HashTablesReport CreateHashTablesReport(ELFInspector.Parser.ElfFile elf)
	{
		var sysv = elf.SysvHashTable;
		var gnu = elf.GnuHashTable;

		return new HashTablesReport
		{
			Sysv = new SysvHashReport
			{
				Present = sysv != null,
				BucketCount = sysv?.BucketCount ?? 0,
				ChainCount = sysv?.ChainCount ?? 0,
				Buckets = sysv?.Buckets.ToList() ?? new List<uint>(),
				Chains = sysv?.Chains.ToList() ?? new List<uint>()
			},
			Gnu = new GnuHashReport
			{
				Present = gnu != null,
				BucketCount = gnu?.BucketCount ?? 0,
				SymbolOffset = gnu?.SymbolOffset ?? 0,
				BloomWordCount = gnu?.BloomWordCount ?? 0,
				BloomShift = gnu?.BloomShift ?? 0,
				BloomWordBits = gnu?.BloomWordBits ?? 0,
				BloomWords = gnu?.BloomWords.ToList() ?? new List<ulong>(),
				Buckets = gnu?.Buckets.ToList() ?? new List<uint>(),
				Chains = gnu?.Chains.ToList() ?? new List<uint>()
			},
			LookupPaths = elf.HashLookupPaths.Select(path => new HashLookupPathReport
			{
				Algorithm = path.Algorithm,
				SymbolName = path.SymbolName,
				Hash = path.Hash,
				BucketIndex = path.BucketIndex,
				BucketValue = path.BucketValue,
				BloomMayMatch = path.BloomMayMatch,
				ChainStartSymbolIndex = path.ChainStartSymbolIndex,
				ChainVisitedCount = path.ChainVisitedCount,
				MatchFound = path.MatchFound,
				MatchedSymbolIndex = path.MatchedSymbolIndex
			}).ToList()
		};
	}

	private static SecurityFeaturesReport CreateSecurityFeatures(ELFInspector.Parser.ElfFile elf)
	{
		var bindNow = HasBindNow(elf);
		var hasRelroSegment = elf.ProgramHeaders.Any(ph => ph.Type == PtGnuRelro);
		var relro = hasRelroSegment
			? (bindNow ? "Full" : "Partial")
			: "None";

		var pie = "No";
		if (elf.Header.Type == 3)
		{
			var hasInterpreter = elf.ProgramHeaders.Any(ph => ph.Type == PtInterp);
			var hasPieFlag = HasDynamicFlag(elf, DtFlags1, Df1Pie);
			pie = hasInterpreter || hasPieFlag ? "Yes" : "No";
		}

		var nx = "Unknown";
		var gnuStack = elf.ProgramHeaders.FirstOrDefault(ph => ph.Type == PtGnuStack);
		if (gnuStack != null)
			nx = (gnuStack.Flags & PfX) == 0 ? "Enabled" : "Disabled";

		var importedSymbolNames = elf.Symbols
			.Where(symbol => symbol.IsImport && !string.IsNullOrEmpty(symbol.Name))
			.Select(symbol => symbol.Name)
			.Distinct(StringComparer.Ordinal)
			.ToList();

		var canaryIndicators = importedSymbolNames
			.Where(IsCanaryIndicator)
			.OrderBy(name => name, StringComparer.Ordinal)
			.ToList();

		var fortifyIndicators = importedSymbolNames
			.Where(IsFortifyIndicator)
			.OrderBy(name => name, StringComparer.Ordinal)
			.ToList();

		return new SecurityFeaturesReport
		{
			Pie = pie,
			Relro = relro,
			Nx = nx,
			BindNow = bindNow,
			CanaryHints = canaryIndicators.Count > 0,
			CanaryIndicators = canaryIndicators,
			FortifyHints = fortifyIndicators.Count > 0,
			FortifyIndicators = fortifyIndicators
		};
	}

	private static bool HasBindNow(ELFInspector.Parser.ElfFile elf)
	{
		return HasDynamicTag(elf, DtBindNow)
			|| HasDynamicFlag(elf, DtFlags, DfBindNow)
			|| HasDynamicFlag(elf, DtFlags1, Df1Now);
	}

	private static bool HasDynamicTag(ELFInspector.Parser.ElfFile elf, long tag)
	{
		return elf.DynamicEntries.Any(entry => entry.Tag == tag);
	}

	private static bool HasDynamicFlag(ELFInspector.Parser.ElfFile elf, long tag, ulong bit)
	{
		return elf.DynamicEntries.Any(entry => entry.Tag == tag && (entry.Value & bit) != 0);
	}

	private static bool IsCanaryIndicator(string symbolName)
	{
		return symbolName switch
		{
			"__stack_chk_fail" => true,
			"__stack_chk_fail_local" => true,
			"__stack_chk_guard" => true,
			"__security_cookie" => true,
			"__intel_security_cookie" => true,
			_ => false
		};
	}

	private static bool IsFortifyIndicator(string symbolName)
	{
		if (string.IsNullOrEmpty(symbolName))
			return false;
		if (string.Equals(symbolName, "__fortify_fail", StringComparison.Ordinal))
			return true;
		if (symbolName.StartsWith("__stack_chk", StringComparison.Ordinal))
			return false;

		return symbolName.Contains("_chk", StringComparison.Ordinal);
	}

	private static SymbolReport MapSymbol(ELFInspector.Parser.ElfSymbol symbol)
	{
		return new SymbolReport
		{
			Name = symbol.Name,
			QualifiedName = symbol.QualifiedName,
			Address = symbol.Value,
			Size = symbol.Size,
			Binding = TranslateSymbolBinding(symbol.Binding),
			Type = TranslateSymbolType(symbol.Type),
			SectionIndexRaw = symbol.SectionIndexRaw,
			SectionIndex = symbol.SectionIndex,
			Visibility = symbol.Visibility,
			IsDynamic = symbol.IsDynamic,
			IsImport = symbol.IsImport,
			IsExport = symbol.IsExport,
			Library = symbol.LibraryName,
			Version = symbol.VersionName
		};
	}

	private static string TranslateFileType(ushort type)
	{
		return type switch
		{
			0 => "ET_NONE",
			1 => "ET_REL",
			2 => "ET_EXEC",
			3 => "ET_DYN",
			4 => "ET_CORE",
			>= 0xFE00 and <= 0xFEFF => $"ET_LOOS+0x{type - 0xFE00:X}",
			>= 0xFF00 and <= 0xFFFF => $"ET_LOPROC+0x{type - 0xFF00:X}",
			_ => $"ET_{type}"
		};
	}

	private static string TranslateSymbolBinding(ELFInspector.Parser.ElfSymbolBinding binding)
	{
		return binding switch
		{
			ELFInspector.Parser.ElfSymbolBinding.Local => "LOCAL",
			ELFInspector.Parser.ElfSymbolBinding.Global => "GLOBAL",
			ELFInspector.Parser.ElfSymbolBinding.Weak => "WEAK",
			ELFInspector.Parser.ElfSymbolBinding.GnuUnique => "GNU_UNIQUE",
			_ => $"STB_{(int)binding}"
		};
	}

	private static string TranslateSymbolType(ELFInspector.Parser.ElfSymbolType type)
	{
		return type switch
		{
			ELFInspector.Parser.ElfSymbolType.Notype => "NOTYPE",
			ELFInspector.Parser.ElfSymbolType.Object => "OBJECT",
			ELFInspector.Parser.ElfSymbolType.Function => "FUNCTION",
			ELFInspector.Parser.ElfSymbolType.Section => "SECTION",
			ELFInspector.Parser.ElfSymbolType.File => "FILE",
			ELFInspector.Parser.ElfSymbolType.Common => "COMMON",
			ELFInspector.Parser.ElfSymbolType.Tls => "TLS",
			ELFInspector.Parser.ElfSymbolType.GnuIfunc => "GNU_IFUNC",
			_ => $"STT_{(int)type}"
		};
	}

	private static string TranslateSectionType(uint type)
	{
		return type switch
		{
			0 => "SHT_NULL",
			1 => "SHT_PROGBITS",
			2 => "SHT_SYMTAB",
			3 => "SHT_STRTAB",
			4 => "SHT_RELA",
			5 => "SHT_HASH",
			6 => "SHT_DYNAMIC",
			7 => "SHT_NOTE",
			8 => "SHT_NOBITS",
			9 => "SHT_REL",
			10 => "SHT_SHLIB",
			11 => "SHT_DYNSYM",
			14 => "SHT_INIT_ARRAY",
			15 => "SHT_FINI_ARRAY",
			16 => "SHT_PREINIT_ARRAY",
			17 => "SHT_GROUP",
			18 => "SHT_SYMTAB_SHNDX",
			19 => "SHT_RELR",
			0x6FFFFFF5 => "SHT_GNU_ATTRIBUTES",
			0x6FFFFFF6 => "SHT_GNU_HASH",
			0x6FFFFFF7 => "SHT_GNU_LIBLIST",
			0x6FFFFFF8 => "SHT_CHECKSUM",
			0x6FFFFFFA => "SHT_SUNW_MOVE",
			0x6FFFFFFB => "SHT_SUNW_COMDAT",
			0x6FFFFFFC => "SHT_SUNW_SYMINFO",
			0x6FFFFFFD => "SHT_GNU_verdef",
			0x6FFFFFFE => "SHT_GNU_verneed",
			0x6FFFFFFF => "SHT_GNU_versym",
			0x6FFF4C00 => "SHT_LLVM_DEPENDENT_LIBRARIES",
			0x6FFF4C01 => "SHT_LLVM_SYMPART",
			0x6FFF4C02 => "SHT_LLVM_PART_EHDR",
			0x6FFF4C03 => "SHT_LLVM_ADDRSIG",
			0x6FFF4C04 => "SHT_LLVM_OFFLOADING",
			0x70000001 => "SHT_ARM_EXIDX",
			0x70000003 => "SHT_ARM_ATTRIBUTES",
			0x70000006 => "SHT_MIPS_REGINFO",
			0x7000000D => "SHT_MIPS_OPTIONS",
			0x7000002A => "SHT_MIPS_ABIFLAGS",
			0x7000002B => "SHT_MIPS_XHASH",
			>= 0x60000000 and <= 0x6FFFFFFF => $"SHT_LOOS+0x{type - 0x60000000:X}",
			>= 0x70000000 and <= 0x7FFFFFFF => $"SHT_LOPROC+0x{type - 0x70000000:X}",
			>= 0x80000000 => $"SHT_LOUSER+0x{type - 0x80000000:X}",
			_ => $"SHT_{type}"
		};
	}

	private static string TranslateSegmentType(uint type)
	{
		return type switch
		{
			0 => "PT_NULL",
			1 => "PT_LOAD",
			2 => "PT_DYNAMIC",
			3 => "PT_INTERP",
			4 => "PT_NOTE",
			5 => "PT_SHLIB",
			6 => "PT_PHDR",
			7 => "PT_TLS",
			PtGnuEhFrame => "PT_GNU_EH_FRAME",
			PtGnuStack => "PT_GNU_STACK",
			PtGnuRelro => "PT_GNU_RELRO",
			PtGnuProperty => "PT_GNU_PROPERTY",
			PtGnuSFrame => "PT_GNU_SFRAME",
			PtSunwBss => "PT_SUNWBSS",
			PtSunwStack => "PT_SUNWSTACK",
			0x65A3DBE6 => "PT_OPENBSD_RANDOMIZE",
			0x65A3DBE7 => "PT_OPENBSD_WXNEEDED",
			0x65A41BE6 => "PT_OPENBSD_BOOTDATA",
			0x70000000 => "PT_MIPS_REGINFO",
			0x70000001 => "PT_ARM_EXIDX",
			0x70000003 => "PT_MIPS_ABIFLAGS",
			>= 0x60000000 and <= 0x6FFFFFFF => $"PT_LOOS+0x{type - 0x60000000:X}",
			>= 0x70000000 and <= 0x7FFFFFFF => $"PT_LOPROC+0x{type - 0x70000000:X}",
			_ => $"PT_{type}"
		};
	}

	private static string FormatSectionFlags(ulong flags)
	{
		if (flags == 0)
			return "0";

		var names = new List<string>();
		var remaining = flags;

		ConsumeFlag(ref remaining, ShfWrite, "WRITE", names);
		ConsumeFlag(ref remaining, ShfAlloc, "ALLOC", names);
		ConsumeFlag(ref remaining, ShfExecInstr, "EXECINSTR", names);
		ConsumeFlag(ref remaining, ShfMerge, "MERGE", names);
		ConsumeFlag(ref remaining, ShfStrings, "STRINGS", names);
		ConsumeFlag(ref remaining, ShfInfoLink, "INFO_LINK", names);
		ConsumeFlag(ref remaining, ShfLinkOrder, "LINK_ORDER", names);
		ConsumeFlag(ref remaining, ShfOsNonConforming, "OS_NONCONFORMING", names);
		ConsumeFlag(ref remaining, ShfGroup, "GROUP", names);
		ConsumeFlag(ref remaining, ShfTls, "TLS", names);
		ConsumeFlag(ref remaining, ShfCompressed, "COMPRESSED", names);
		ConsumeFlag(ref remaining, ShfOrdered, "ORDERED", names);
		ConsumeFlag(ref remaining, ShfExclude, "EXCLUDE", names);

		if ((remaining & ShfMaskOs) != 0)
		{
			names.Add($"MASKOS=0x{remaining & ShfMaskOs:X}");
			remaining &= ~ShfMaskOs;
		}

		if ((remaining & ShfMaskProc) != 0)
		{
			names.Add($"MASKPROC=0x{remaining & ShfMaskProc:X}");
			remaining &= ~ShfMaskProc;
		}

		if (remaining != 0)
			names.Add($"0x{remaining:X}");

		return string.Join("|", names);
	}

	private static string FormatSegmentFlags(uint flags)
	{
		if (flags == 0)
			return "0";

		var permissions = new StringBuilder();
		permissions.Append((flags & PfR) != 0 ? 'R' : '-');
		permissions.Append((flags & PfW) != 0 ? 'W' : '-');
		permissions.Append((flags & PfX) != 0 ? 'X' : '-');

		var remaining = flags & ~(PfR | PfW | PfX);
		return remaining == 0 ? permissions.ToString() : $"{permissions}|0x{remaining:X}";
	}

	private static void ConsumeFlag(ref ulong remaining, ulong flag, string name, List<string> names)
	{
		if ((remaining & flag) == 0)
			return;

		names.Add(name);
		remaining &= ~flag;
	}

	private static string TranslateMachine(ushort machine)
	{
		return machine switch
		{
			0 => "No specific machine",
			1 => "AT&T WE 32100",
			2 => "SPARC",
			3 => "Intel 80386",
			4 => "Motorola 68000",
			5 => "Motorola 88000",
			7 => "Intel 80860",
			8 => "MIPS",
			9 => "IBM System/370",
			10 => "MIPS RS3000 Little-endian",
			14 => "HP PA-RISC",
			17 => "Fujitsu VPP500",
			18 => "SPARC32+",
			19 => "Intel 80960",
			20 => "PowerPC",
			21 => "PowerPC64",
			22 => "IBM S/390",
			23 => "IBM SPU/SPC",
			40 => "ARM",
			42 => "SuperH",
			43 => "SPARC V9",
			50 => "IA-64",
			62 => "AMD x86-64",
			75 => "Digital VAX",
			76 => "Axis CRIS",
			87 => "Atmel AVR",
			88 => "Mitsubishi FR30",
			89 => "Mitsubishi D10V",
			90 => "Mitsubishi D30V",
			92 => "OpenRISC",
			93 => "ARC",
			94 => "Xtensa",
			106 => "Blackfin",
			113 => "Altera Nios II",
			135 => "TI PRU",
			164 => "QUALCOMM Hexagon",
			167 => "Andes Technology NDS32",
			174 => "Imagination Technologies META",
			175 => "MCST Elbrus",
			183 => "AArch64",
			187 => "Tilera TILE64",
			188 => "Tilera TILEPro",
			189 => "Xilinx MicroBlaze",
			190 => "NVIDIA CUDA",
			191 => "Tilera TILE-Gx",
			224 => "AMDGPU",
			243 => "RISC-V",
			247 => "Linux BPF",
			252 => "C-SKY",
			258 => "LoongArch",
			_ => $"EM_{machine}"
		};
	}

	private static string TranslateOsAbi(byte osAbi)
	{
		return osAbi switch
		{
			0 => "UNIX - System V",
			1 => "HP-UX",
			2 => "NetBSD",
			3 => "Linux",
			4 => "GNU Hurd",
			5 => "UNIX - GNU",
			6 => "Solaris",
			7 => "AIX",
			8 => "IRIX",
			9 => "FreeBSD",
			10 => "Tru64",
			11 => "Novell Modesto",
			12 => "OpenBSD",
			13 => "OpenVMS",
			14 => "NonStop Kernel",
			15 => "AROS",
			16 => "FenixOS",
			17 => "Nuxi CloudABI",
			18 => "OpenVOS",
			53 => "Sortix",
			64 => "ARM EABI",
			97 => "ARM",
			255 => "Standalone Application",
			_ => $"ELFOSABI_{osAbi}"
		};
	}
}
