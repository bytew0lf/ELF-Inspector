namespace ELFInspector.Library;

public static class ExampleUsage
{
	private const int MaxDetailedItems = 500;
	private const int MaxHashPreviewEntries = 32;

	public static int RunWithArgs(string[] args)
	{
		if (!TryParseArguments(args, out var filePath, out var outputFileName, out var outputDirectory, out var deterministic, out var compatHeaderValidation, out var error))
		{
			Console.Error.WriteLine(error);
			Console.Error.WriteLine("Usage: --file <ELF-File> --output <report.txt> --output-path <path> [--deterministic] [--compat-header-validation]");
			return 1;
		}

		if (!File.Exists(filePath))
		{
			Console.Error.WriteLine($"ELF file does not exist: {filePath}");
			return 1;
		}

		var outputPath = Path.GetFullPath(outputDirectory);
		Directory.CreateDirectory(outputPath);
		var reportFilePath = Path.Combine(outputPath, outputFileName);

		try
		{
			var parseOptions = new ELFInspector.Parser.ElfParseOptions
			{
				HeaderValidationMode = compatHeaderValidation
					? ELFInspector.Parser.ElfHeaderValidationMode.Compat
					: ELFInspector.Parser.ElfHeaderValidationMode.Strict
			};
			var elf = ELFInspector.Parser.ElfReader.Parse(filePath, parseOptions);
			var report = ELFInspector.Reporting.ElfReportMapper.Create(elf);
			var reportText = BuildTextReport(filePath, report, deterministic);

			File.WriteAllText(reportFilePath, reportText, Encoding.UTF8);
			Console.WriteLine($"Report written to: {reportFilePath}");
			return 0;
		}
		catch (Exception ex)
		{
			Console.Error.WriteLine($"Failed to parse ELF file: {ex.Message}");
			return 1;
		}
	}

	public static void Run(string path)
	{
		var exitCode = RunWithArgs(new[]
		{
			"--file", path,
			"--output", "report.txt",
			"--output-path", Directory.GetCurrentDirectory()
		});

		if (exitCode != 0)
			throw new InvalidOperationException("Failed to generate ELF report.");
	}

	private static bool TryParseArguments(
		string[] args,
		out string filePath,
		out string outputFileName,
		out string outputDirectory,
		out bool deterministic,
		out bool compatHeaderValidation,
		out string error)
	{
		filePath = string.Empty;
		outputFileName = string.Empty;
		outputDirectory = string.Empty;
		deterministic = false;
		compatHeaderValidation = false;
		error = string.Empty;

		for (var i = 0; i < args.Length; i++)
		{
			var option = args[i];
				if (option == "--deterministic")
				{
					deterministic = true;
					continue;
				}
				if (option == "--compat-header-validation")
				{
					compatHeaderValidation = true;
					continue;
				}

			if (!option.StartsWith("--", StringComparison.Ordinal))
			{
				error = $"Unexpected token: {option}";
				return false;
			}

			if (i + 1 >= args.Length)
			{
				error = $"Missing value for option: {option}";
				return false;
			}

			var value = args[++i];
			switch (option)
			{
				case "--file":
					filePath = value;
					break;
				case "--output":
					outputFileName = value;
					break;
				case "--output-path":
					outputDirectory = value;
					break;
				default:
					error = $"Unknown option: {option}";
					return false;
			}
		}

		if (string.IsNullOrWhiteSpace(filePath))
		{
			error = "Missing required option: --file";
			return false;
		}

		if (string.IsNullOrWhiteSpace(outputFileName))
		{
			error = "Missing required option: --output";
			return false;
		}

		if (string.IsNullOrWhiteSpace(outputDirectory))
		{
			error = "Missing required option: --output-path";
			return false;
		}

		return true;
	}

	private static string BuildTextReport(string filePath, ELFInspector.Reporting.ElfReport report, bool deterministic)
	{
		var sb = new StringBuilder();
		sb.AppendLine("ELF Report");
		sb.AppendLine("==========");
		sb.AppendLine($"File: {Path.GetFullPath(filePath)}");
		if (deterministic)
			sb.AppendLine("Generated: (deterministic)");
		else
			sb.AppendLine($"Generated: {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
		sb.AppendLine();

		sb.AppendLine("Header");
		sb.AppendLine("------");
		sb.AppendLine($"Class: {report.Header.Class}");
		sb.AppendLine($"Endianness: {report.Header.Endianness}");
		sb.AppendLine($"Type: {report.Header.TypeName} ({report.Header.Type})");
		sb.AppendLine($"Machine: {report.Header.Machine} (code {report.Header.MachineCode})");
		sb.AppendLine($"OSABI: {report.Header.OsAbi} (code {report.Header.OsAbiCode})");
		sb.AppendLine($"ABI Version: {report.Header.AbiVersion}");
		sb.AppendLine($"Flags: 0x{report.Header.Flags:X}");
		sb.AppendLine($"EntryPoint: 0x{report.Header.EntryPoint:X}");
		sb.AppendLine($"Interpreter: {OrNone(report.Header.Interpreter)}");
		sb.AppendLine($"SONAME: {OrNone(report.Header.Soname)}");
		sb.AppendLine($"RPATH: {OrNone(report.Header.RPath)}");
		sb.AppendLine($"RUNPATH: {OrNone(report.Header.RunPath)}");
		sb.AppendLine();

		sb.AppendLine("Security Features");
		sb.AppendLine("-----------------");
		sb.AppendLine($"PIE: {report.Security.Pie}");
		sb.AppendLine($"RELRO: {report.Security.Relro}");
		sb.AppendLine($"NX: {report.Security.Nx}");
		sb.AppendLine($"BIND_NOW: {YesNo(report.Security.BindNow)}");
		sb.AppendLine($"Canary Hints: {YesNo(report.Security.CanaryHints)}");
		sb.AppendLine($"Canary Indicators: {JoinIndicators(report.Security.CanaryIndicators)}");
		sb.AppendLine($"FORTIFY Hints: {YesNo(report.Security.FortifyHints)}");
		sb.AppendLine($"FORTIFY Indicators: {JoinIndicators(report.Security.FortifyIndicators)}");
		sb.AppendLine();

		sb.AppendLine("Hash Tables");
		sb.AppendLine("-----------");

		var sysvHash = report.HashTables?.Sysv;
		if (sysvHash == null || !sysvHash.Present)
		{
			sb.AppendLine("SYSV Hash: (none)");
		}
		else
		{
			sb.AppendLine("SYSV Hash: present");
			sb.AppendLine($"- Buckets: declared={sysvHash.BucketCount}, parsed={sysvHash.Buckets.Count}");
			sb.AppendLine($"- Chains: declared={sysvHash.ChainCount}, parsed={sysvHash.Chains.Count}");
			sb.AppendLine($"- Buckets Preview: {FormatUIntPreview(sysvHash.Buckets, MaxHashPreviewEntries)}");
			sb.AppendLine($"- Chains Preview: {FormatUIntPreview(sysvHash.Chains, MaxHashPreviewEntries)}");
		}

		var gnuHash = report.HashTables?.Gnu;
		if (gnuHash == null || !gnuHash.Present)
		{
			sb.AppendLine("GNU Hash: (none)");
		}
		else
		{
			sb.AppendLine("GNU Hash: present");
			sb.AppendLine($"- Buckets: declared={gnuHash.BucketCount}, parsed={gnuHash.Buckets.Count}");
			sb.AppendLine($"- Symbol Offset: {gnuHash.SymbolOffset}");
			sb.AppendLine($"- Bloom Words: declared={gnuHash.BloomWordCount}, parsed={gnuHash.BloomWords.Count}, bits={gnuHash.BloomWordBits}, shift={gnuHash.BloomShift}");
			sb.AppendLine($"- Bloom Preview: {FormatUlongPreview(gnuHash.BloomWords, MaxHashPreviewEntries)}");
			sb.AppendLine($"- Buckets Preview: {FormatUIntPreview(gnuHash.Buckets, MaxHashPreviewEntries)}");
			sb.AppendLine($"- Chains Preview: {FormatUIntPreview(gnuHash.Chains, MaxHashPreviewEntries)}");
		}

		sb.AppendLine("Lookup Paths");
		var lookupPaths = report.HashTables?.LookupPaths ?? new List<ELFInspector.Reporting.HashLookupPathReport>();
		if (lookupPaths.Count == 0)
		{
			sb.AppendLine("(none)");
		}
		else
		{
			foreach (var lookupPath in lookupPaths.Take(MaxDetailedItems))
			{
				var bloomText = string.Equals(lookupPath.Algorithm, "GNU", StringComparison.Ordinal)
					? (lookupPath.BloomMayMatch ? "bloom=hit" : "bloom=miss")
					: "bloom=n/a";
				var matchText = lookupPath.MatchFound
					? $"match=yes (sym#{lookupPath.MatchedSymbolIndex})"
					: "match=no";

				sb.AppendLine($"- [{lookupPath.Algorithm}] {lookupPath.SymbolName}: hash=0x{lookupPath.Hash:X8}, {bloomText}, bucket[{lookupPath.BucketIndex}]={lookupPath.BucketValue}, chainStart={lookupPath.ChainStartSymbolIndex}, visited={lookupPath.ChainVisitedCount}, {matchText}");
			}
			if (lookupPaths.Count > MaxDetailedItems)
				sb.AppendLine($"... {lookupPaths.Count - MaxDetailedItems} more");
		}
		sb.AppendLine();

		sb.AppendLine("Unwind / Debug");
		sb.AppendLine("--------------");
		var unwind = report.Unwind;
		if (unwind == null)
		{
			sb.AppendLine("(none)");
		}
		else
		{
			var ehFrame = unwind.EhFrame;
			if (ehFrame == null || !ehFrame.Present)
			{
				sb.AppendLine(".eh_frame: (none)");
			}
			else
			{
				sb.AppendLine($".eh_frame: addr=0x{ehFrame.Address:X}, size=0x{ehFrame.Size:X}, CIE={ehFrame.CieCount}, FDE={ehFrame.FdeCount}, terminator={YesNo(ehFrame.TerminatorSeen)}");
				sb.AppendLine($".eh_frame CIE entries: {ehFrame.CieEntries?.Count ?? 0}");
				foreach (var cie in (ehFrame.CieEntries ?? new List<ELFInspector.Reporting.EhFrameCieReport>()).Take(16))
				{
					sb.AppendLine($"- CIE#{cie.Index}: off=0x{cie.Offset:X}, len=0x{cie.ContentLength:X}, v={cie.Version}, aug={OrNone(cie.Augmentation)}, code_align={cie.CodeAlignmentFactor}, data_align={cie.DataAlignmentFactor}, ra_reg={cie.ReturnAddressRegister}, fde_enc=0x{cie.FdePointerEncoding:X2}, instr={cie.Instructions.Count}");
				}
				if ((ehFrame.CieEntries?.Count ?? 0) > 16)
					sb.AppendLine($"... {ehFrame.CieEntries!.Count - 16} more CIE entries");

				sb.AppendLine($".eh_frame FDE entries: {ehFrame.FdeEntries?.Count ?? 0}");
				foreach (var fde in (ehFrame.FdeEntries ?? new List<ELFInspector.Reporting.EhFrameFdeReport>()).Take(32))
				{
					var cfa = fde.CfaRuleAvailable ? $"r{fde.CfaRegister}{(fde.CfaOffset >= 0 ? "+" : string.Empty)}{fde.CfaOffset}" : "(n/a)";
					var ra = fde.ReturnAddressOffsetAvailable ? fde.ReturnAddressOffset.ToString() : "(n/a)";
					sb.AppendLine($"- FDE#{fde.Index}: off=0x{fde.Offset:X}, cie={fde.CieIndex?.ToString() ?? "?"}, pc=[0x{fde.InitialLocation:X},0x{fde.EndLocation:X}), cfa={cfa}, ra_off={ra}, instr={fde.Instructions.Count}");
				}
				if ((ehFrame.FdeEntries?.Count ?? 0) > 32)
					sb.AppendLine($"... {ehFrame.FdeEntries!.Count - 32} more FDE entries");
			}

			var ehFrameHeader = unwind.EhFrameHeader;
			if (ehFrameHeader == null || !ehFrameHeader.Present)
			{
				sb.AppendLine(".eh_frame_hdr: (none)");
			}
			else
			{
				var pointerText = ehFrameHeader.EhFramePointerDecoded ? $"0x{ehFrameHeader.EhFramePointer:X}" : "(n/a)";
				var fdeCountText = ehFrameHeader.FdeCountDecoded ? ehFrameHeader.FdeCount.ToString() : "(n/a)";
				sb.AppendLine($".eh_frame_hdr: v{ehFrameHeader.Version}, eh_ptr_enc=0x{ehFrameHeader.EhFramePointerEncoding:X2}, fde_enc=0x{ehFrameHeader.FdeCountEncoding:X2}, table_enc=0x{ehFrameHeader.TableEncoding:X2}, eh_frame_ptr={pointerText}, fde_count={fdeCountText}, parsed_table_entries={ehFrameHeader.ParsedTableEntries}");
			}

			var debugSections = unwind.DebugSections ?? new List<ELFInspector.Reporting.DebugSectionReport>();
			if (debugSections.Count == 0)
			{
				sb.AppendLine("Debug Sections: (none)");
			}
			else
			{
				sb.AppendLine($"Debug Sections: {debugSections.Count}");
				foreach (var debugSection in debugSections.Take(MaxDetailedItems))
				{
					var compressedText = debugSection.IsCompressed
						? $"compressed, uncompressed_size=0x{debugSection.UncompressedSize:X}"
						: "uncompressed";
					sb.AppendLine($"- {debugSection.Name}: size=0x{debugSection.Size:X}, {compressedText}");
				}
				if (debugSections.Count > MaxDetailedItems)
					sb.AppendLine($"... {debugSections.Count - MaxDetailedItems} more");
			}
		}
		sb.AppendLine();

		sb.AppendLine("DWARF Index");
		sb.AppendLine("-----------");
		var dwarf = report.Dwarf;
		if (dwarf == null)
		{
			sb.AppendLine("(none)");
		}
		else
		{
			sb.AppendLine($"Sections: info={YesNo(dwarf.HasDebugInfo)}, abbrev={YesNo(dwarf.HasDebugAbbrev)}, line={YesNo(dwarf.HasDebugLine)}, str={YesNo(dwarf.HasDebugStr)}, ranges={YesNo(dwarf.HasDebugRanges)}, addr={YesNo(dwarf.HasDebugAddr)}, str_offsets={YesNo(dwarf.HasDebugStrOffsets)}, rnglists={YesNo(dwarf.HasDebugRngLists)}, loclists={YesNo(dwarf.HasDebugLocLists)}");
			sb.AppendLine($"Compile Units: {dwarf.CompileUnits.Count}");
			foreach (var compileUnit in dwarf.CompileUnits.Take(MaxDetailedItems))
			{
				var unitTypeText = compileUnit.UnitType.HasValue ? $"0x{compileUnit.UnitType.Value:X2}" : "(n/a)";
				sb.AppendLine($"- off=0x{compileUnit.Offset:X}, len=0x{compileUnit.UnitLength:X}, dwarf64={YesNo(compileUnit.IsDwarf64)}, v{compileUnit.Version}, unit_type={unitTypeText}, abbrev_off=0x{compileUnit.AbbrevOffset:X}, addr_size={compileUnit.AddressSize}");
			}
			if (dwarf.CompileUnits.Count > MaxDetailedItems)
				sb.AppendLine($"... {dwarf.CompileUnits.Count - MaxDetailedItems} more");

			sb.AppendLine($"Line Tables: {dwarf.LineTables.Count}");
			foreach (var lineTable in dwarf.LineTables.Take(MaxDetailedItems))
			{
				sb.AppendLine($"- off=0x{lineTable.Offset:X}, len=0x{lineTable.UnitLength:X}, dwarf64={YesNo(lineTable.IsDwarf64)}, v{lineTable.Version}, addr_size={lineTable.AddressSize}, seg_size={lineTable.SegmentSelectorSize}, header_len=0x{lineTable.HeaderLength:X}, min_inst={lineTable.MinimumInstructionLength}, max_ops={lineTable.MaximumOperationsPerInstruction}, default_stmt={YesNo(lineTable.DefaultIsStmt)}, line_base={lineTable.LineBase}, line_range={lineTable.LineRange}, opcode_base={lineTable.OpcodeBase}, dirs={lineTable.IncludeDirectoryCount}, files={lineTable.FileNameEntryCount}");
			}
			if (dwarf.LineTables.Count > MaxDetailedItems)
				sb.AppendLine($"... {dwarf.LineTables.Count - MaxDetailedItems} more");

			var semanticUnits = dwarf.SemanticUnits ?? new List<ELFInspector.Reporting.DwarfSemanticUnitReport>();
			sb.AppendLine($"Semantic Units: {semanticUnits.Count}");
			foreach (var semanticUnit in semanticUnits.Take(MaxDetailedItems))
			{
				sb.AppendLine($"- CU off=0x{semanticUnit.Offset:X}, len=0x{semanticUnit.UnitLength:X}, dwarf64={YesNo(semanticUnit.IsDwarf64)}, v{semanticUnit.Version}, unit_type={(semanticUnit.UnitType.HasValue ? $"0x{semanticUnit.UnitType.Value:X2}" : "(n/a)")}, abbrev_off=0x{semanticUnit.AbbrevOffset:X}, addr_size={semanticUnit.AddressSize}, root_dies={semanticUnit.RootDies.Count}");
				var rootCount = Math.Min(semanticUnit.RootDies.Count, 8);
				for (var i = 0; i < rootCount; i++)
					AppendDwarfDieLine(sb, semanticUnit.RootDies[i], maxDepth: 2, depth: 0);
				if (semanticUnit.RootDies.Count > rootCount)
					sb.AppendLine($"  ... {semanticUnit.RootDies.Count - rootCount} more root DIEs");
			}
			if (semanticUnits.Count > MaxDetailedItems)
				sb.AppendLine($"... {semanticUnits.Count - MaxDetailedItems} more");

			var symbolMappings = dwarf.SymbolMappings ?? new List<ELFInspector.Reporting.DwarfSymbolMappingReport>();
			sb.AppendLine($"Symbol↔DIE Mappings: {symbolMappings.Count}");
			foreach (var mapping in symbolMappings.Take(MaxDetailedItems))
				sb.AppendLine($"- {mapping.SymbolName} @ 0x{mapping.SymbolAddress:X} -> DIE@0x{mapping.DieOffset:X} ({mapping.DieTagText}), match={mapping.MatchType}");
			if (symbolMappings.Count > MaxDetailedItems)
				sb.AppendLine($"... {symbolMappings.Count - MaxDetailedItems} more");

			var query = dwarf.Query ?? new ELFInspector.Reporting.DwarfQueryReport();
			var queryTypes = query.Types ?? new List<ELFInspector.Reporting.DwarfTypeQueryReport>();
			var queryFunctions = query.Functions ?? new List<ELFInspector.Reporting.DwarfFunctionQueryReport>();
			var queryVariables = query.Variables ?? new List<ELFInspector.Reporting.DwarfVariableQueryReport>();
			sb.AppendLine($"Query Model: types={queryTypes.Count}, functions={queryFunctions.Count}, variables={queryVariables.Count}");
			foreach (var function in queryFunctions.Take(Math.Min(MaxDetailedItems, 24)))
			{
				var displayName = !string.IsNullOrEmpty(function.LinkageName) ? function.LinkageName : function.Name;
				var ranges = function.AddressRanges == null || function.AddressRanges.Count == 0
					? "(none)"
					: string.Join(", ", function.AddressRanges.Take(4).Select(range => $"0x{range.Start:X}-0x{range.End:X}"));
				sb.AppendLine($"- fn DIE@0x{function.DieOffset:X}: {OrNone(displayName)}, return_type={(function.ReturnTypeDieOffset.HasValue ? $"0x{function.ReturnTypeDieOffset.Value:X}" : "(n/a)")}, params={(function.Parameters?.Count ?? 0)}, ranges={ranges}");
			}
			if (queryFunctions.Count > 24)
				sb.AppendLine($"... {queryFunctions.Count - 24} more query functions");
		}
		sb.AppendLine();

		sb.AppendLine("Section Special Cases");
		sb.AppendLine("---------------------");
		var sectionSpecialCases = report.SectionSpecialCases;
		if (sectionSpecialCases == null)
		{
			sb.AppendLine("(none)");
		}
		else
		{
			var compressedSections = sectionSpecialCases.CompressedSections ?? new List<ELFInspector.Reporting.CompressedSectionReport>();
			if (compressedSections.Count == 0)
			{
				sb.AppendLine("Compressed Sections: (none)");
			}
			else
			{
				sb.AppendLine($"Compressed Sections: {compressedSections.Count}");
				foreach (var compressedSection in compressedSections.Take(MaxDetailedItems))
				{
					var source = compressedSection.IsGnuStyleZdebug ? "gnu-zdebug" : "elf-chdr";
					var status = compressedSection.DecompressionSucceeded ? "ok" : $"error={OrNone(compressedSection.Error)}";
					sb.AppendLine($"- {compressedSection.Name}: {compressedSection.CompressionTypeName} ({compressedSection.CompressionType}), source={source}, compressed=0x{compressedSection.CompressedSize:X}, uncompressed=0x{compressedSection.UncompressedSize:X}, align={compressedSection.Alignment}, {status}");
				}
				if (compressedSections.Count > MaxDetailedItems)
					sb.AppendLine($"... {compressedSections.Count - MaxDetailedItems} more");
			}

			var sectionGroups = sectionSpecialCases.SectionGroups ?? new List<ELFInspector.Reporting.SectionGroupReport>();
			if (sectionGroups.Count == 0)
			{
				sb.AppendLine("Section Groups: (none)");
			}
			else
			{
				sb.AppendLine($"Section Groups: {sectionGroups.Count}");
				foreach (var group in sectionGroups.Take(MaxDetailedItems))
				{
					var signature = string.IsNullOrEmpty(group.SignatureSymbolName)
						? $"sym#{group.SignatureSymbolIndex}"
						: $"{group.SignatureSymbolName} (sym#{group.SignatureSymbolIndex})";
					sb.AppendLine($"- {group.Name}: flags=0x{group.Flags:X}, comdat={YesNo(group.IsComdat)}, signature={signature}, members={group.MemberSectionIndexes.Count}");
				}
				if (sectionGroups.Count > MaxDetailedItems)
					sb.AppendLine($"... {sectionGroups.Count - MaxDetailedItems} more");
			}
		}
		sb.AppendLine();

		sb.AppendLine("Core Dump");
		sb.AppendLine("---------");
		var coreDump = report.CoreDump;
		if (coreDump == null || !coreDump.IsCoreDump)
		{
			sb.AppendLine("Type: not ET_CORE");
		}
		else
		{
			sb.AppendLine("Type: ET_CORE");
			sb.AppendLine($"Process: {OrNone(coreDump.ProcessName)}");
			sb.AppendLine($"Process ID: {(coreDump.ProcessId.HasValue ? coreDump.ProcessId.Value.ToString() : "(unknown)")}");
			sb.AppendLine($"Primary Signal: {(coreDump.Signal.HasValue ? coreDump.Signal.Value.ToString() : "(unknown)")}");
			sb.AppendLine($"Signals Seen: {(coreDump.Signals == null || coreDump.Signals.Count == 0 ? "(none)" : string.Join(", ", coreDump.Signals))}");
			sb.AppendLine($"AUXV Entries: {coreDump.AuxVectorEntryCount}");
			sb.AppendLine($"File Mappings: {coreDump.FileMappingCount}");

			var threads = coreDump.Threads ?? new List<ELFInspector.Reporting.CoreThreadReport>();
			if (threads.Count == 0)
			{
				sb.AppendLine("Threads: (none)");
			}
			else
			{
				sb.AppendLine($"Threads: {threads.Count}");
				foreach (var thread in threads.Take(MaxDetailedItems))
				{
					var tid = thread.ThreadId.HasValue ? thread.ThreadId.Value.ToString() : "(unknown)";
					var ppid = thread.ParentProcessId.HasValue ? thread.ParentProcessId.Value.ToString() : "(unknown)";
					var pgrp = thread.ProcessGroupId.HasValue ? thread.ProcessGroupId.Value.ToString() : "(unknown)";
					var sid = thread.SessionId.HasValue ? thread.SessionId.Value.ToString() : "(unknown)";
					var signal = thread.Signal.HasValue ? thread.Signal.Value.ToString() : "(unknown)";
					var currentSignal = thread.CurrentSignal.HasValue ? thread.CurrentSignal.Value.ToString() : "(unknown)";
					sb.AppendLine($"- Thread#{thread.Index}: tid={tid}, ppid={ppid}, pgrp={pgrp}, sid={sid}, signal={signal}, current_signal={currentSignal}, register_preview={FormatRegisterPreview(thread.RegisterPreview)}");
				}
				if (threads.Count > MaxDetailedItems)
					sb.AppendLine($"... {threads.Count - MaxDetailedItems} more");
			}

			var unwindThreads = coreDump.UnwindThreads ?? new List<ELFInspector.Reporting.CoreThreadUnwindReport>();
			if (unwindThreads.Count == 0)
			{
				sb.AppendLine("Stack Walk: (none)");
			}
			else
			{
				sb.AppendLine($"Stack Walk Threads: {unwindThreads.Count}");
				foreach (var unwindThread in unwindThreads.Take(MaxDetailedItems))
				{
					sb.AppendLine($"- Thread#{unwindThread.ThreadIndex} (tid={(unwindThread.ThreadId.HasValue ? unwindThread.ThreadId.Value.ToString() : "(unknown)")}), strategy={OrNone(unwindThread.Strategy)}, complete={YesNo(unwindThread.Complete)}, frames={unwindThread.Frames.Count}");
					foreach (var frame in unwindThread.Frames.Take(32))
					{
						var fp = frame.FramePointer.HasValue ? $"0x{frame.FramePointer.Value:X}" : "(n/a)";
						var symbol = string.IsNullOrEmpty(frame.SymbolName) ? "(unknown)" : frame.SymbolName;
						sb.AppendLine($"  - #{frame.Index}: ip=0x{frame.InstructionPointer:X}, sp=0x{frame.StackPointer:X}, fp={fp}, symbol={symbol}, via={OrNone(frame.Strategy)}");
					}
					if (unwindThread.Frames.Count > 32)
						sb.AppendLine($"  ... {unwindThread.Frames.Count - 32} more");
				}
				if (unwindThreads.Count > MaxDetailedItems)
					sb.AppendLine($"... {unwindThreads.Count - MaxDetailedItems} more");
			}
		}
		sb.AppendLine();

		sb.AppendLine("Counts");
		sb.AppendLine("------");
		sb.AppendLine($"Sections: {report.Sections.Count}");
		sb.AppendLine($"Segments: {report.Segments.Count}");
		sb.AppendLine($"Symbols: {report.Symbols.Count}");
		sb.AppendLine($"Imported Symbols: {report.ImportedSymbols.Count}");
		sb.AppendLine($"Exported Symbols: {report.ExportedSymbols.Count}");
		sb.AppendLine($"Relocations: {report.Relocations.Count}");
		sb.AppendLine($"Dynamic Entries: {report.Dynamics.Count}");
		sb.AppendLine($"Notes: {report.Notes.Count}");
		sb.AppendLine();

		sb.AppendLine("Sections");
		sb.AppendLine("--------");
		for (var i = 0; i < report.Sections.Count && i < MaxDetailedItems; i++)
		{
			var section = report.Sections[i];
			var name = string.IsNullOrEmpty(section.Name) ? "(unnamed)" : section.Name;
			sb.AppendLine($"- [{i}] {name}: {section.TypeName} ({section.Type}), flags={section.FlagsText}, addr=0x{section.Address:X}, off=0x{section.Offset:X}, size=0x{section.Size:X}");
		}
		if (report.Sections.Count > MaxDetailedItems)
			sb.AppendLine($"... {report.Sections.Count - MaxDetailedItems} more");
		sb.AppendLine();

		sb.AppendLine("Segments");
		sb.AppendLine("--------");
		for (var i = 0; i < report.Segments.Count && i < MaxDetailedItems; i++)
		{
			var segment = report.Segments[i];
			sb.AppendLine($"- [{i}] {segment.TypeName} ({segment.Type}), flags={segment.FlagsText}, off=0x{segment.Offset:X}, vaddr=0x{segment.VirtualAddress:X}, filesz=0x{segment.FileSize:X}, memsz=0x{segment.MemorySize:X}");
		}
		if (report.Segments.Count > MaxDetailedItems)
			sb.AppendLine($"... {report.Segments.Count - MaxDetailedItems} more");
		sb.AppendLine();

		sb.AppendLine("Import Libraries");
		sb.AppendLine("----------------");
		if (report.Imports.Count == 0)
		{
			sb.AppendLine("(none)");
		}
		else
		{
			foreach (var library in report.Imports.OrderBy(name => name, StringComparer.Ordinal))
				sb.AppendLine($"- {library}");
		}
		sb.AppendLine();

		sb.AppendLine("Imported Symbols");
		sb.AppendLine("----------------");
		if (report.ImportedSymbols.Count == 0)
		{
			sb.AppendLine("(none)");
		}
		else
		{
			foreach (var symbol in report.ImportedSymbols.OrderBy(s => s.QualifiedName, StringComparer.Ordinal))
			{
				var library = string.IsNullOrEmpty(symbol.Library) ? "(unknown)" : symbol.Library;
				var name = string.IsNullOrEmpty(symbol.QualifiedName) ? symbol.Name : symbol.QualifiedName;
				sb.AppendLine($"- {name} <= {library}");
			}
		}
		sb.AppendLine();

		sb.AppendLine("Exported Symbols");
		sb.AppendLine("----------------");
		if (report.ExportedSymbols.Count == 0)
		{
			sb.AppendLine("(none)");
		}
		else
		{
			foreach (var symbol in report.ExportedSymbols.OrderBy(s => s.QualifiedName, StringComparer.Ordinal))
			{
				var name = string.IsNullOrEmpty(symbol.QualifiedName) ? symbol.Name : symbol.QualifiedName;
				sb.AppendLine($"- {name} @ 0x{symbol.Address:X}");
			}
		}
		sb.AppendLine();

		sb.AppendLine("Dynamic Entries");
		sb.AppendLine("---------------");
		foreach (var entry in report.Dynamics.Take(MaxDetailedItems))
		{
			var details = new List<string>();
			if (!string.IsNullOrEmpty(entry.StringValue))
				details.Add(entry.StringValue);
			if (!string.IsNullOrEmpty(entry.DecodedValue))
				details.Add(entry.DecodedValue);

			var suffix = details.Count == 0 ? string.Empty : $" -> {string.Join("; ", details)}";
			sb.AppendLine($"- {entry.TagName} ({entry.Tag}) = 0x{entry.Value:X}{suffix}");
		}
		if (report.Dynamics.Count > MaxDetailedItems)
			sb.AppendLine($"... {report.Dynamics.Count - MaxDetailedItems} more");
		sb.AppendLine();

		sb.AppendLine("Relocations (resolved)");
		sb.AppendLine("----------------------");
		foreach (var relocation in report.Relocations.Take(MaxDetailedItems))
		{
			var symbol = "relative";
			if (!string.Equals(relocation.Encoding, "RELR", StringComparison.Ordinal))
			{
				var symbolVersion = string.IsNullOrEmpty(relocation.SymbolVersion) ? string.Empty : $"@{relocation.SymbolVersion}";
				var symbolLibrary = string.IsNullOrEmpty(relocation.SymbolLibrary) ? string.Empty : $" <= {relocation.SymbolLibrary}";
				symbol = string.IsNullOrEmpty(relocation.SymbolName) ? $"sym#{relocation.SymbolIndex}" : $"{relocation.SymbolName}{symbolVersion}{symbolLibrary}";
			}

			var section = string.IsNullOrEmpty(relocation.AppliesToSection) ? "(unknown)" : relocation.AppliesToSection;
			var source = string.IsNullOrEmpty(relocation.SourceSection) ? "(unknown)" : relocation.SourceSection;
			var addend = relocation.HasAddend ? $", addend={relocation.Addend}" : string.Empty;
			var encoding = string.IsNullOrEmpty(relocation.Encoding) ? "REL?" : relocation.Encoding;
			var loaderPath = string.IsNullOrEmpty(relocation.LoaderPath) ? "(unknown)" : relocation.LoaderPath;
			sb.AppendLine($"- 0x{relocation.Offset:X}: {relocation.TypeName} ({relocation.Type}) [{encoding}] -> {symbol}, source={source}, section={section}, loader={loaderPath}{addend}");
		}
		if (report.Relocations.Count > MaxDetailedItems)
			sb.AppendLine($"... {report.Relocations.Count - MaxDetailedItems} more");
		sb.AppendLine();

		sb.AppendLine("Notes");
		sb.AppendLine("-----");
		if (report.Notes.Count == 0)
		{
			sb.AppendLine("(none)");
		}
		else
		{
			foreach (var note in report.Notes)
			{
				var decoded = string.IsNullOrEmpty(note.DecodedDescription) ? string.Empty : $" -> {note.DecodedDescription}";
				sb.AppendLine($"- {note.Name} {note.TypeName} ({note.Type}){decoded}");
			}
		}

		return sb.ToString();
	}

	private static string OrNone(string value)
	{
		return string.IsNullOrEmpty(value) ? "(none)" : value;
	}

	private static string YesNo(bool value)
	{
		return value ? "Yes" : "No";
	}

	private static string JoinIndicators(IReadOnlyCollection<string> indicators)
	{
		return indicators == null || indicators.Count == 0
			? "(none)"
			: string.Join(", ", indicators);
	}

	private static string FormatUIntPreview(IReadOnlyList<uint> values, int maxEntries)
	{
		if (values == null || values.Count == 0)
			return "(none)";

		var count = Math.Min(values.Count, maxEntries);
		var parts = new List<string>(count + 1);
		for (var i = 0; i < count; i++)
			parts.Add($"[{i}]={values[i]}");
		if (values.Count > count)
			parts.Add($"... +{values.Count - count}");

		return string.Join(", ", parts);
	}

	private static string FormatUlongPreview(IReadOnlyList<ulong> values, int maxEntries)
	{
		if (values == null || values.Count == 0)
			return "(none)";

		var count = Math.Min(values.Count, maxEntries);
		var parts = new List<string>(count + 1);
		for (var i = 0; i < count; i++)
			parts.Add($"[{i}]=0x{values[i]:X}");
		if (values.Count > count)
			parts.Add($"... +{values.Count - count}");

		return string.Join(", ", parts);
	}

	private static string FormatRegisterPreview(IReadOnlyList<ulong> values)
	{
		if (values == null || values.Count == 0)
			return "(none)";

		var count = Math.Min(values.Count, 16);
		var parts = new List<string>(count + 1);
		for (var i = 0; i < count; i++)
			parts.Add($"0x{values[i]:X}");
		if (values.Count > count)
			parts.Add($"... +{values.Count - count}");

		return string.Join(", ", parts);
	}

	private static void AppendDwarfDieLine(StringBuilder sb, ELFInspector.Reporting.DwarfDieReport die, int maxDepth, int depth)
	{
		var indent = new string(' ', depth * 2 + 2);
		var nameAttr = die.Attributes?.FirstOrDefault(attribute =>
			string.Equals(attribute.NameText, "DW_AT_linkage_name", StringComparison.Ordinal)
			|| string.Equals(attribute.NameText, "DW_AT_MIPS_linkage_name", StringComparison.Ordinal)
			|| string.Equals(attribute.NameText, "DW_AT_name", StringComparison.Ordinal));
		var displayName = nameAttr == null || string.IsNullOrEmpty(nameAttr.StringValue)
			? string.Empty
			: $" name={nameAttr.StringValue}";

		sb.AppendLine($"{indent}- DIE@0x{die.Offset:X}: {die.TagText} (tag=0x{die.Tag:X}, attrs={die.Attributes?.Count ?? 0}, children={die.Children?.Count ?? 0}){displayName}");
		if (depth >= maxDepth || die.Children == null || die.Children.Count == 0)
			return;

		var childCount = Math.Min(6, die.Children.Count);
		for (var i = 0; i < childCount; i++)
			AppendDwarfDieLine(sb, die.Children[i], maxDepth, depth + 1);
		if (die.Children.Count > childCount)
			sb.AppendLine($"{indent}  ... {die.Children.Count - childCount} more children");
	}
}
