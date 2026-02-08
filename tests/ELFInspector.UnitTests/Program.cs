using System.Buffers.Binary;
using System.Reflection;
using System.Text;
using ELFInspector.Endianness;
using ELFInspector.Library;
using ELFInspector.Parser;
using ELFInspector.Reporting;
using Xunit;

namespace ELFInspector.UnitTests;

public sealed class ElfReaderTests
{
	[Fact]
	public void EndianBinaryReader_ReadBeyondBounds_ThrowsInvalidDataException()
	{
		Assert.Throws<InvalidDataException>(ReadPastEndWithEndianBinaryReader);
	}

	[Fact]
	public void EndianBinaryReader_InvalidPosition_ThrowsInvalidDataException()
	{
		Assert.Throws<InvalidDataException>(SetInvalidEndianReaderPosition);
	}

	[Fact]
	public void Parse_AllDetectedElfSamples_Succeeds()
	{
		var sampleFiles = GetSampleElfFiles();
		Assert.NotEmpty(sampleFiles);

		foreach (var file in sampleFiles)
		{
			var data = File.ReadAllBytes(file);
			var elf = ElfReader.Parse(data);

			Assert.True(elf.Header.Class is ElfClass.Elf32 or ElfClass.Elf64, $"Unsupported class for {Path.GetFileName(file)}.");
			Assert.True(elf.ProgramHeaders.Count > 0 || elf.Sections.Count > 0, $"No structures parsed for {Path.GetFileName(file)}.");
		}
	}

	[Fact]
	public void Parse_InternalDataSource_LengthOverIntMax_SucceedsForMinimalElf64()
	{
		var header = BuildMinimalElf64Header();
		var source = new SparseEndianDataSource((ulong)int.MaxValue + 4096UL, header);
		var elf = InvokeInternalParse(source, ElfParseOptions.StrictDefault);

		Assert.Equal(ElfClass.Elf64, elf.Header.Class);
		Assert.Equal((ushort)2, elf.Header.Type);
		Assert.Equal((ushort)62, elf.Header.Machine);
		Assert.Empty(elf.ProgramHeaders);
		Assert.Empty(elf.Sections);
	}

	[Fact]
	public void Parse_FilePath_StreamMode_SparseFileOverIntMax_Succeeds()
	{
		var tempFile = Path.Combine(Path.GetTempPath(), $"elf-large-{Guid.NewGuid():N}.bin");
		try
		{
			var header = BuildMinimalElf64Header();
			using (var stream = new FileStream(tempFile, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read))
			{
				stream.Write(header);
				stream.SetLength((long)int.MaxValue + 4096L);
			}

			var elf = ElfReader.Parse(tempFile, new ElfParseOptions
			{
				DataSourceMode = ElfDataSourceMode.Stream
			});

			Assert.Equal(ElfClass.Elf64, elf.Header.Class);
			Assert.Equal((ushort)62, elf.Header.Machine);
			Assert.Empty(elf.Sections);
		}
		finally
		{
			if (File.Exists(tempFile))
				File.Delete(tempFile);
		}
	}

	[Fact]
	public void Parse_FilePath_AutoMode_UsesDataSourceRefactorPath()
	{
		var helloFile = GetRequiredSample("hello_x86_64");
		var elf = ElfReader.Parse(helloFile);

		Assert.Equal(ElfClass.Elf64, elf.Header.Class);
		Assert.NotEmpty(elf.ProgramHeaders);
	}

	[Fact]
	public void Parse_Stream_Mode_SucceedsWithoutMonolithicFileRead()
	{
		var helloFile = GetRequiredSample("hello_x86_64");
		using var stream = new FileStream(helloFile, FileMode.Open, FileAccess.Read, FileShare.Read);
		var elf = ElfReader.Parse(stream, new ElfParseOptions
		{
			DataSourceMode = ElfDataSourceMode.Stream
		});

		Assert.Equal(ElfClass.Elf64, elf.Header.Class);
		Assert.NotEmpty(elf.Sections);
	}

	[Fact]
	public void Parse_FilePath_StreamMode_SparseInterpSegmentOverIntMax_Succeeds()
	{
		var tempFile = Path.Combine(Path.GetTempPath(), $"elf-large-interp-{Guid.NewGuid():N}.bin");
		try
		{
			const string expectedInterpreter = "/lib/ld-musl-x86_64.so.1";
			const ulong interpreterOffset = 0x200;
			var interpreterBytes = Encoding.ASCII.GetBytes(expectedInterpreter + "\0");
			var interpreterSegmentSize = (ulong)int.MaxValue + 8192UL;

			var header = BuildMinimalElf64Header();
			WriteUInt64(header.AsSpan(32, 8), 64, littleEndian: true); // e_phoff
			WriteUInt16(header.AsSpan(54, 2), 56, littleEndian: true); // e_phentsize
			WriteUInt16(header.AsSpan(56, 2), 1, littleEndian: true);  // e_phnum

			var programHeader = new byte[56];
			WriteUInt32(programHeader.AsSpan(0, 4), 3U, littleEndian: true); // PT_INTERP
			WriteUInt32(programHeader.AsSpan(4, 4), 0U, littleEndian: true); // p_flags
			WriteUInt64(programHeader.AsSpan(8, 8), interpreterOffset, littleEndian: true); // p_offset
			WriteUInt64(programHeader.AsSpan(32, 8), interpreterSegmentSize, littleEndian: true); // p_filesz
			WriteUInt64(programHeader.AsSpan(40, 8), interpreterSegmentSize, littleEndian: true); // p_memsz
			WriteUInt64(programHeader.AsSpan(48, 8), 1UL, littleEndian: true); // p_align

			using (var stream = new FileStream(tempFile, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read))
			{
				stream.Write(header);
				stream.Position = 64;
				stream.Write(programHeader);
				stream.Position = (long)interpreterOffset;
				stream.Write(interpreterBytes);
				stream.SetLength((long)(interpreterOffset + interpreterSegmentSize));
			}

			var elf = ElfReader.Parse(tempFile, new ElfParseOptions
			{
				DataSourceMode = ElfDataSourceMode.Stream
			});

			Assert.Equal(expectedInterpreter, elf.InterpreterPath);
		}
		finally
		{
			if (File.Exists(tempFile))
				File.Delete(tempFile);
		}
	}

	[Fact]
	public void Parse_Busybox_ContainsRelrRelocations()
	{
		var busyboxFile = GetRequiredSample("busybox");
		var elf = ElfReader.Parse(File.ReadAllBytes(busyboxFile));

		var relrRelocations = elf.Relocations.Where(r => string.Equals(r.Encoding, "RELR", StringComparison.Ordinal)).ToList();
		Assert.NotEmpty(relrRelocations);
		Assert.Contains(relrRelocations, relocation => !string.IsNullOrEmpty(relocation.AppliesToSection));
	}

	[Fact]
	public void Parse_MultiArchSamples_UseArchitectureSpecificRelocationNames()
	{
		AssertRelocationTypeName("hello_mips", "R_MIPS_REL32");
		AssertRelocationTypeName("hello_mips64", "R_MIPS_REL32/R_MIPS_64/R_MIPS_NONE");
		AssertRelocationTypeName("hello_mips64el", "R_MIPS_REL32/R_MIPS_64/R_MIPS_NONE");
		AssertRelocationTypeName("hello_ppc", "R_PPC_RELATIVE");
		AssertRelocationTypeName("hello_ppc64le", "R_PPC64_ADDR64");
		AssertRelocationTypeName("hello_s390x", "R_390_GLOB_DAT");
		AssertRelocationTypeName("hello_sparc64", "R_SPARC_JMP_SLOT");
	}

	[Fact]
	public void Parse_RelocationTypeNameCoverage_AdditionalArchMappings_AreResolved()
	{
		Assert.Equal("R_RISCV_TLS_DTPMOD32", InvokeRelocationTypeName(243, 6));
		Assert.Equal("R_RISCV_IRELATIVE", InvokeRelocationTypeName(243, 58));
		Assert.Equal("R_386_IRELATIVE", InvokeRelocationTypeName(3, 42));
		Assert.Equal("R_SPARC_HI22", InvokeRelocationTypeName(43, 10));
		Assert.Equal("R_MIPS_REL16", InvokeRelocationTypeName(8, 33));
		Assert.Equal("R_ARM_TLS_DTPMOD32", InvokeRelocationTypeName(40, 17));
		Assert.Equal("R_ARM_GOT_BREL", InvokeRelocationTypeName(40, 26));
		Assert.Equal("R_ARM_UNKNOWN_4095", InvokeRelocationTypeName(40, 4095));
		Assert.Equal("R_RISCV_UNKNOWN_4095", InvokeRelocationTypeName(243, 4095));
		Assert.Equal("R_MACHINE_9999_7", InvokeRelocationTypeName(9999, 7));
	}

	[Fact]
	public void Parse_Nano_DecodesDynamicFlags()
	{
		var nanoFile = GetRequiredSample("nano");
		var elf = ElfReader.Parse(File.ReadAllBytes(nanoFile));

		var dtFlags = elf.DynamicEntries.FirstOrDefault(d => d.TagName == "DT_FLAGS");
		Assert.NotNull(dtFlags);
		Assert.Contains("DF_BIND_NOW", dtFlags!.DecodedValue ?? string.Empty);

		var dtFlags1 = elf.DynamicEntries.FirstOrDefault(d => d.TagName == "DT_FLAGS_1");
		Assert.NotNull(dtFlags1);
		Assert.Contains("DF_1_", dtFlags1!.DecodedValue ?? string.Empty);
	}

	[Fact]
	public void Parse_DynamicTags_UseNamedTagsForVersionAndProcessorSpecificRanges()
	{
		var helloX64 = ElfReader.Parse(File.ReadAllBytes(GetRequiredSample("hello_x86_64")));
		Assert.Contains(helloX64.DynamicEntries, entry => entry.Tag == 0x6FFFFFF9 && entry.TagName == "DT_RELACOUNT");

		var helloArmhf = ElfReader.Parse(File.ReadAllBytes(GetRequiredSample("hello_armhf")));
		Assert.Contains(helloArmhf.DynamicEntries, entry => entry.Tag == 0x6FFFFFFA && entry.TagName == "DT_RELCOUNT");

		var helloMips = ElfReader.Parse(File.ReadAllBytes(GetRequiredSample("hello_mips")));
		Assert.Contains(helloMips.DynamicEntries, entry => entry.Tag == 0x70000011 && entry.TagName == "DT_MIPS_SYMTABNO");
		Assert.Contains(helloMips.DynamicEntries, entry => entry.Tag == 0x70000012 && entry.TagName == "DT_MIPS_UNREFEXTNO");

		var helloPpc64 = ElfReader.Parse(File.ReadAllBytes(GetRequiredSample("hello_ppc64le")));
		Assert.Contains(helloPpc64.DynamicEntries, entry => entry.Tag == 0x70000000 && entry.TagName == "DT_PPC64_GLINK");
	}

	[Fact]
	public void Parse_DynamicTags_AArch64AndSparc_ProcessorSpecificTags_AreNamedAndStructured()
	{
		var nano = ElfReader.Parse(File.ReadAllBytes(GetRequiredSample("nano")));
		var aarch64Tag = nano.DynamicEntries.FirstOrDefault(entry => entry.Tag == 0x70000001);
		Assert.NotNull(aarch64Tag);
		Assert.Equal("DT_AARCH64_BTI_PLT", aarch64Tag!.TagName);
		Assert.DoesNotContain("addr=", aarch64Tag.DecodedValue ?? string.Empty, StringComparison.Ordinal);
		Assert.Contains("disabled", aarch64Tag.DecodedValue ?? string.Empty, StringComparison.OrdinalIgnoreCase);

		var sparc = ElfReader.Parse(File.ReadAllBytes(GetRequiredSample("hello_sparc64")));
		var sparcTags = sparc.DynamicEntries.Where(entry => entry.Tag == 0x70000001).ToList();
		Assert.NotEmpty(sparcTags);
		Assert.All(sparcTags, entry =>
		{
			Assert.Equal("DT_SPARC_REGISTER", entry.TagName);
			Assert.Contains("register=", entry.DecodedValue ?? string.Empty, StringComparison.Ordinal);
			Assert.DoesNotContain("file_off", entry.DecodedValue ?? string.Empty, StringComparison.Ordinal);
		});
	}

	[Fact]
	public void Parse_HelloX64_HeaderReport_ContainsAbiMetadata()
	{
		var helloFile = GetRequiredSample("hello_x86_64");
		var elf = ElfReader.Parse(File.ReadAllBytes(helloFile));
		var report = ElfReportMapper.Create(elf);

		Assert.Equal(elf.Header.OsAbi, report.Header.OsAbiCode);
		Assert.Equal(elf.Header.AbiVersion, report.Header.AbiVersion);
		Assert.Equal(elf.Header.Flags, report.Header.Flags);
		Assert.False(string.IsNullOrWhiteSpace(report.Header.OsAbi));
	}

	[Fact]
	public void Parse_DynamicTags_ExposeStructuredDecodedSemantics()
	{
		var helloX64 = ElfReader.Parse(File.ReadAllBytes(GetRequiredSample("hello_x86_64")));
		var strTab = helloX64.DynamicEntries.First(entry => entry.TagName == "DT_STRTAB");
		var strSz = helloX64.DynamicEntries.First(entry => entry.TagName == "DT_STRSZ");
		var symEnt = helloX64.DynamicEntries.First(entry => entry.TagName == "DT_SYMENT");

		Assert.Contains("addr=0x", strTab.DecodedValue ?? string.Empty, StringComparison.Ordinal);
		Assert.Contains("size=", strSz.DecodedValue ?? string.Empty, StringComparison.Ordinal);
		Assert.Contains("entry_size=", symEnt.DecodedValue ?? string.Empty, StringComparison.Ordinal);

		var helloMips = ElfReader.Parse(File.ReadAllBytes(GetRequiredSample("hello_mips")));
		var mipsSymTabNo = helloMips.DynamicEntries.First(entry => entry.TagName == "DT_MIPS_SYMTABNO");
		Assert.Contains("count=", mipsSymTabNo.DecodedValue ?? string.Empty, StringComparison.Ordinal);

		var helloPpc64 = ElfReader.Parse(File.ReadAllBytes(GetRequiredSample("hello_ppc64le")));
		var ppc64Glink = helloPpc64.DynamicEntries.First(entry => entry.TagName == "DT_PPC64_GLINK");
		Assert.Contains("addr=0x", ppc64Glink.DecodedValue ?? string.Empty, StringComparison.Ordinal);
	}

	[Fact]
	public void Parse_DynamicTags_ProcessorSpecificSemantics_AvoidGenericProcValueFallback()
	{
		var helloMips = ElfReader.Parse(File.ReadAllBytes(GetRequiredSample("hello_mips")));
		var mipsFlags = helloMips.DynamicEntries.First(entry => entry.TagName == "DT_MIPS_FLAGS");
		Assert.Contains("RHF_", mipsFlags.DecodedValue ?? string.Empty, StringComparison.Ordinal);
		Assert.Contains("mask=0x", mipsFlags.DecodedValue ?? string.Empty, StringComparison.Ordinal);
		Assert.DoesNotContain("proc_tag=", mipsFlags.DecodedValue ?? string.Empty, StringComparison.Ordinal);
		Assert.DoesNotContain("processor_specific(", mipsFlags.DecodedValue ?? string.Empty, StringComparison.Ordinal);

		var mipsLocalGotNo = helloMips.DynamicEntries.First(entry => entry.TagName == "DT_MIPS_LOCAL_GOTNO");
		Assert.Contains("local_got_entries=", mipsLocalGotNo.DecodedValue ?? string.Empty, StringComparison.Ordinal);
		Assert.DoesNotContain("proc_value", mipsLocalGotNo.DecodedValue ?? string.Empty, StringComparison.Ordinal);
		Assert.DoesNotContain("proc_tag=", mipsLocalGotNo.DecodedValue ?? string.Empty, StringComparison.Ordinal);

		var helloPpc64 = ElfReader.Parse(File.ReadAllBytes(GetRequiredSample("hello_ppc64le")));
		var ppc64Opt = helloPpc64.DynamicEntries.First(entry => entry.TagName == "DT_PPC64_OPT");
		Assert.DoesNotContain("proc_value", ppc64Opt.DecodedValue ?? string.Empty, StringComparison.Ordinal);
		Assert.DoesNotContain("proc_tag=", ppc64Opt.DecodedValue ?? string.Empty, StringComparison.Ordinal);
		Assert.Equal("0", ppc64Opt.DecodedValue);
	}

	[Fact]
	public void Report_Nano_ContainsExpectedSecurityFeatures()
	{
		var nanoFile = GetRequiredSample("nano");
		var elf = ElfReader.Parse(File.ReadAllBytes(nanoFile));
		var report = ElfReportMapper.Create(elf);

		Assert.Equal("Yes", report.Security.Pie);
		Assert.Equal("Full", report.Security.Relro);
		Assert.Equal("Enabled", report.Security.Nx);
		Assert.True(report.Security.BindNow);
		Assert.True(report.Security.CanaryHints);
		Assert.True(report.Security.FortifyHints);
		Assert.Contains("__stack_chk_fail", report.Security.CanaryIndicators);
		Assert.Contains("__printf_chk", report.Security.FortifyIndicators);
	}

	[Fact]
	public void Report_HelloX64_ContainsExpectedSecurityFeatures()
	{
		var helloFile = GetRequiredSample("hello_x86_64");
		var elf = ElfReader.Parse(File.ReadAllBytes(helloFile));
		var report = ElfReportMapper.Create(elf);

		Assert.Equal("Yes", report.Security.Pie);
		Assert.Equal("Partial", report.Security.Relro);
		Assert.Equal("Enabled", report.Security.Nx);
		Assert.False(report.Security.BindNow);
	}

	[Fact]
	public void Parse_HelloX64_ParsesUnwindSections()
	{
		var helloFile = GetRequiredSample("hello_x86_64");
		var elf = ElfReader.Parse(File.ReadAllBytes(helloFile));
		var report = ElfReportMapper.Create(elf);

		Assert.NotNull(elf.Unwind);
		Assert.True(elf.Unwind.EhFrame.Present);
		Assert.True(elf.Unwind.EhFrame.CieCount > 0 || elf.Unwind.EhFrame.FdeCount > 0);
		Assert.True(elf.Unwind.EhFrameHeader.Present);

		Assert.NotNull(report.Unwind);
		Assert.True(report.Unwind.EhFrame.Present);
		Assert.True(report.Unwind.EhFrameHeader.Present);
		Assert.True(report.Unwind.EhFrameHeader.FdeCountDecoded);
		Assert.True(report.Unwind.EhFrameHeader.ParsedTableEntries > 0);
		Assert.Equal((uint)Math.Min(report.Unwind.EhFrameHeader.FdeCount, 4096UL), report.Unwind.EhFrameHeader.ParsedTableEntries);
	}

	[Fact]
	public void Parse_HelloX64_Relocations_ExposeLoaderPathClassification()
	{
		var helloFile = GetRequiredSample("hello_x86_64");
		var elf = ElfReader.Parse(File.ReadAllBytes(helloFile));
		var report = ElfReportMapper.Create(elf);

		Assert.Contains(elf.Relocations, relocation => relocation.IsPltPath);
		Assert.Contains(elf.Relocations, relocation => relocation.IsGotPath);
		Assert.All(elf.Relocations, relocation => Assert.False(string.IsNullOrEmpty(relocation.LoaderPath)));

		Assert.Contains(report.Relocations, relocation => relocation.IsPltPath);
		Assert.Contains(report.Relocations, relocation => relocation.IsGotPath);
		Assert.All(report.Relocations, relocation => Assert.False(string.IsNullOrEmpty(relocation.LoaderPath)));
	}

	[Fact]
	public void Parse_MultiArchSamples_Relocations_AvoidRawFallbackTypeNames()
	{
		var sampleFiles = new[]
		{
			"hello_armhf",
			"hello_ppc",
			"hello_ppc64le",
			"hello_s390x",
			"hello_sparc64"
		};

		foreach (var sampleFile in sampleFiles)
		{
			var elf = ElfReader.Parse(File.ReadAllBytes(GetRequiredSample(sampleFile)));
			Assert.DoesNotContain(
				elf.Relocations,
				relocation => IsRawFallbackRelocationTypeName(elf.Header.Machine, relocation));
		}
	}

	[Fact]
	public void ParseDwarfIndex_SyntheticSections_ParsesCompileUnitAndLineHeader()
	{
		var data = new byte[0x100];
		var infoSectionOffset = 0x20;
		var lineSectionOffset = 0x60;

		var debugInfo = new byte[]
		{
			0x07, 0x00, 0x00, 0x00,
			0x04, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x08
		};
		Array.Copy(debugInfo, 0, data, infoSectionOffset, debugInfo.Length);

		var debugLine = new byte[]
		{
			0x0E, 0x00, 0x00, 0x00,
			0x04, 0x00,
			0x08, 0x00, 0x00, 0x00,
			0x01,
			0x01,
			0x01,
			0xFB,
			0x0E,
			0x01,
			0x00,
			0x00
		};
		Array.Copy(debugLine, 0, data, lineSectionOffset, debugLine.Length);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian
			}
		};
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_info", Offset = (ulong)infoSectionOffset, Size = (ulong)debugInfo.Length });
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_abbrev", Offset = 0, Size = 0 });
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_line", Offset = (ulong)lineSectionOffset, Size = (ulong)debugLine.Length });
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_str", Offset = 0, Size = 0 });
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_ranges", Offset = 0, Size = 0 });

		ElfReader.ParseDwarfIndex(data, elf);
		var report = ElfReportMapper.Create(elf);

		Assert.True(elf.Dwarf.HasDebugInfo);
		Assert.True(elf.Dwarf.HasDebugAbbrev);
		Assert.True(elf.Dwarf.HasDebugLine);
		Assert.True(elf.Dwarf.HasDebugStr);
		Assert.True(elf.Dwarf.HasDebugRanges);
		Assert.Single(elf.Dwarf.CompileUnits);
		Assert.Single(elf.Dwarf.LineTables);
		Assert.Equal((ushort)4, elf.Dwarf.CompileUnits[0].Version);
		Assert.Equal((byte)8, elf.Dwarf.CompileUnits[0].AddressSize);
		Assert.Equal((ushort)4, elf.Dwarf.LineTables[0].Version);
		Assert.Equal((byte)1, elf.Dwarf.LineTables[0].MinimumInstructionLength);
		Assert.Equal((ulong)8, elf.Dwarf.LineTables[0].HeaderLength);
		Assert.Single(report.Dwarf.CompileUnits);
		Assert.Single(report.Dwarf.LineTables);
	}

	[Fact]
	public void ParseDwarfIndex_SemanticModel_ParsesDieTreeAndSymbolMappings()
	{
		var data = new byte[0x400];
		var infoOffset = 0x80;
		var abbrevOffset = 0x140;

		var debugAbbrev = new byte[]
		{
			0x01, 0x11, 0x01, 0x03, 0x08, 0x11, 0x01, 0x12, 0x06, 0x00, 0x00,
			0x02, 0x2E, 0x00, 0x03, 0x08, 0x11, 0x01, 0x12, 0x06, 0x6E, 0x08, 0x00, 0x00,
			0x00
		};
		Array.Copy(debugAbbrev, 0, data, abbrevOffset, debugAbbrev.Length);

		var body = new List<byte>();
		body.AddRange(new byte[] { 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08 }); // v4, abbrev=0, addr_size=8
		body.Add(0x01); // compile unit DIE
		body.AddRange(Encoding.ASCII.GetBytes("synthetic-cu\0"));
		body.AddRange(BitConverter.GetBytes(0x1000UL));
		body.AddRange(BitConverter.GetBytes(0x100U));
		body.Add(0x02); // subprogram DIE
		body.AddRange(Encoding.ASCII.GetBytes("main\0"));
		body.AddRange(BitConverter.GetBytes(0x1010UL));
		body.AddRange(BitConverter.GetBytes(0x30U));
		body.AddRange(Encoding.ASCII.GetBytes("_Z4mainv\0"));
		body.Add(0x00); // end of children for CU

		var unitLength = (uint)body.Count;
		var debugInfo = new List<byte>();
		debugInfo.AddRange(BitConverter.GetBytes(unitLength));
		debugInfo.AddRange(body);
		Array.Copy(debugInfo.ToArray(), 0, data, infoOffset, debugInfo.Count);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian,
				Machine = 62
			}
		};
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_info", Offset = (ulong)infoOffset, Size = (ulong)debugInfo.Count });
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_abbrev", Offset = (ulong)abbrevOffset, Size = (ulong)debugAbbrev.Length });
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_line", Offset = 0, Size = 0 });
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_str", Offset = 0, Size = 0 });
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_ranges", Offset = 0, Size = 0 });

		elf.Symbols.Add(new ElfSymbol
		{
			Name = "_Z4mainv",
			Value = 0x1020,
			Size = 0x10
		});

		ElfReader.ParseDwarfIndex(data, elf);
		var report = ElfReportMapper.Create(elf);

		Assert.True(
			elf.Dwarf.SemanticUnits.Count == 1,
			$"semantic_units={elf.Dwarf.SemanticUnits.Count}, index_compile_units={elf.Dwarf.CompileUnits.Count}, has_debug_info={elf.Dwarf.HasDebugInfo}, has_debug_abbrev={elf.Dwarf.HasDebugAbbrev}");
		var semanticUnit = elf.Dwarf.SemanticUnits[0];
		Assert.Single(semanticUnit.RootDies);
		Assert.Equal("DW_TAG_compile_unit", semanticUnit.RootDies[0].TagText);
		Assert.Single(semanticUnit.RootDies[0].Children);
		Assert.Equal("DW_TAG_subprogram", semanticUnit.RootDies[0].Children[0].TagText);
		Assert.Contains(elf.Dwarf.SymbolMappings, mapping => mapping.SymbolName == "_Z4mainv" && mapping.DieTagText == "DW_TAG_subprogram");

		Assert.Single(report.Dwarf.SemanticUnits);
		Assert.Contains(report.Dwarf.SymbolMappings, mapping => mapping.SymbolName == "_Z4mainv");
	}

	[Fact]
	public void ParseDwarfIndex_DwarfV5Tables_EnableRnglistsAndLoclistsSymbolMappings()
	{
		var data = new byte[0x800];
		var infoOffset = 0x120;
		var abbrevOffset = 0x200;
		var strOffset = 0x280;
		var strOffsetsOffset = 0x300;
		var addrOffset = 0x340;
		var rnglistsOffset = 0x3C0;
		var loclistsOffset = 0x420;

		var debugAbbrev = new byte[]
		{
			0x01, 0x11, 0x01, 0x72, 0x17, 0x73, 0x17, 0x74, 0x17, 0x8B, 0x01, 0x17, 0x00, 0x00,
			0x02, 0x2E, 0x00, 0x03, 0x25, 0x55, 0x23, 0x00, 0x00,
			0x03, 0x34, 0x00, 0x03, 0x25, 0x02, 0x22, 0x00, 0x00,
			0x00
		};
		Array.Copy(debugAbbrev, 0, data, abbrevOffset, debugAbbrev.Length);

		var debugStr = Encoding.ASCII.GetBytes("func\0var\0");
		Array.Copy(debugStr, 0, data, strOffset, debugStr.Length);

		var debugStrOffsets = new byte[8];
		WriteUInt32(debugStrOffsets.AsSpan(0, 4), 0, littleEndian: true);
		WriteUInt32(debugStrOffsets.AsSpan(4, 4), 5, littleEndian: true);
		Array.Copy(debugStrOffsets, 0, data, strOffsetsOffset, debugStrOffsets.Length);

		var debugAddr = new byte[6 * 8];
		WriteUInt64(debugAddr.AsSpan(0, 8), 0x1000, littleEndian: true);
		WriteUInt64(debugAddr.AsSpan(8, 8), 0x1010, littleEndian: true);
		WriteUInt64(debugAddr.AsSpan(16, 8), 0x2000, littleEndian: true);
		WriteUInt64(debugAddr.AsSpan(24, 8), 0x2010, littleEndian: true);
		WriteUInt64(debugAddr.AsSpan(32, 8), 0x3000, littleEndian: true);
		WriteUInt64(debugAddr.AsSpan(40, 8), 0x3010, littleEndian: true);
		Array.Copy(debugAddr, 0, data, addrOffset, debugAddr.Length);

		var debugRnglists = new byte[]
		{
			0x08, 0x00, 0x00, 0x00,
			0x0C, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x01, 0x00,
			0x02, 0x02, 0x03, 0x00
		};
		Array.Copy(debugRnglists, 0, data, rnglistsOffset, debugRnglists.Length);

		var debugLoclists = new byte[]
		{
			0x04, 0x00, 0x00, 0x00,
			0x02, 0x04, 0x05, 0x01, 0x50, 0x00
		};
		Array.Copy(debugLoclists, 0, data, loclistsOffset, debugLoclists.Length);

		var debugInfoBody = new List<byte>
		{
			0x05, 0x00, // version
			0x01, // unit_type = compile unit
			0x08 // address_size
		};
		debugInfoBody.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 }); // abbrev offset
		debugInfoBody.Add(0x01); // CU abbrev
		debugInfoBody.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 }); // str_offsets_base
		debugInfoBody.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 }); // addr_base
		debugInfoBody.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 }); // rnglists_base
		debugInfoBody.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 }); // loclists_base
		debugInfoBody.AddRange(new byte[] { 0x02, 0x00, 0x00 }); // subprogram #1 (func, rng idx 0)
		debugInfoBody.AddRange(new byte[] { 0x02, 0x00, 0x01 }); // subprogram #2 (func, rng idx 1)
		debugInfoBody.AddRange(new byte[] { 0x03, 0x01, 0x00 }); // variable (var, loc idx 0)
		debugInfoBody.Add(0x00); // end children

		var debugInfo = new List<byte>();
		WriteUInt32(data.AsSpan(infoOffset, 4), (uint)debugInfoBody.Count, littleEndian: true);
		debugInfo.AddRange(data.AsSpan(infoOffset, 4).ToArray());
		debugInfo.AddRange(debugInfoBody);
		Array.Copy(debugInfo.ToArray(), 0, data, infoOffset, debugInfo.Count);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian,
				Machine = 62
			}
		};

		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_info", Offset = (ulong)infoOffset, Size = (ulong)debugInfo.Count });
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_abbrev", Offset = (ulong)abbrevOffset, Size = (ulong)debugAbbrev.Length });
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_str", Offset = (ulong)strOffset, Size = (ulong)debugStr.Length });
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_str_offsets", Offset = (ulong)strOffsetsOffset, Size = (ulong)debugStrOffsets.Length });
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_addr", Offset = (ulong)addrOffset, Size = (ulong)debugAddr.Length });
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_rnglists", Offset = (ulong)rnglistsOffset, Size = (ulong)debugRnglists.Length });
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_loclists", Offset = (ulong)loclistsOffset, Size = (ulong)debugLoclists.Length });

		elf.Symbols.Add(new ElfSymbol { Name = "func", Value = 0x2008, Size = 4 });
		elf.Symbols.Add(new ElfSymbol { Name = "var", Value = 0x3004, Size = 4 });

		ElfReader.ParseDwarfIndex(data, elf);
		var report = ElfReportMapper.Create(elf);

		Assert.True(report.Dwarf.HasDebugAddr);
		Assert.True(report.Dwarf.HasDebugStrOffsets);
		Assert.True(report.Dwarf.HasDebugRngLists);
		Assert.True(report.Dwarf.HasDebugLocLists);

		var funcMapping = report.Dwarf.SymbolMappings.FirstOrDefault(mapping => mapping.SymbolName == "func");
		Assert.NotNull(funcMapping);
		Assert.Equal((ulong)32, funcMapping!.DieOffset);
		Assert.Contains("address", funcMapping.MatchType, StringComparison.Ordinal);

		var varMapping = report.Dwarf.SymbolMappings.FirstOrDefault(mapping => mapping.SymbolName == "var");
		Assert.NotNull(varMapping);
		Assert.Equal((ulong)35, varMapping!.DieOffset);
		Assert.Contains("address", varMapping.MatchType, StringComparison.Ordinal);
	}

	[Fact]
	public void ParseDwarfIndex_SemanticModel_UnknownAttributeForm_IsPreservedWithFallbackValue()
	{
		var data = new byte[0x200];
		var infoOffset = 0x80;
		var abbrevOffset = 0x120;

		var debugAbbrev = new byte[]
		{
			0x01, 0x11, 0x00, // abbrev #1, DW_TAG_compile_unit, no children
			0x03, 0x44,       // DW_AT_name, unknown form 0x44
			0x00, 0x00,
			0x00
		};
		Array.Copy(debugAbbrev, 0, data, abbrevOffset, debugAbbrev.Length);

		var debugInfoBody = new List<byte>
		{
			0x04, 0x00,             // DWARF v4
			0x00, 0x00, 0x00, 0x00, // abbrev offset
			0x08,                   // address size
			0x01,                   // abbrev code
			0x2A                    // unknown-form fallback payload
		};

		WriteUInt32(data.AsSpan(infoOffset, 4), (uint)debugInfoBody.Count, littleEndian: true);
		Array.Copy(debugInfoBody.ToArray(), 0, data, infoOffset + 4, debugInfoBody.Count);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian
			}
		};

		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_info", Offset = (ulong)infoOffset, Size = (ulong)(4 + debugInfoBody.Count) });
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_abbrev", Offset = (ulong)abbrevOffset, Size = (ulong)debugAbbrev.Length });

		ElfReader.ParseDwarfIndex(data, elf);

		var unit = Assert.Single(elf.Dwarf.SemanticUnits);
		var rootDie = Assert.Single(unit.RootDies);
		var attribute = Assert.Single(rootDie.Attributes);

		Assert.Equal(0x44UL, attribute.Form);
		Assert.Equal("DW_FORM_0x44", attribute.FormText);
		Assert.Equal(ElfDwarfAttributeValueKind.Unsigned, attribute.Kind);
		Assert.Equal(0x2AUL, attribute.UnsignedValue);
		Assert.Equal((ulong)12, attribute.UnitRelativeValueOffset);
		Assert.Equal((ulong)1, attribute.ConsumedByteCount);
		Assert.Equal(ElfDwarfDecodeStatus.PreservedUnknown, attribute.DecodeStatus);
		Assert.Contains("unknown form preserved", attribute.DecodeNote, StringComparison.Ordinal);
		Assert.Contains("unknown-form-fallback", attribute.StringValue, StringComparison.Ordinal);
		Assert.Contains("form=DW_FORM_0x44", attribute.StringValue, StringComparison.Ordinal);
	}

	[Fact]
	public void ParseDwarfIndex_SemanticModel_AttributeEnumValue_IsSemanticallyDecoded()
	{
		var data = new byte[0x200];
		var infoOffset = 0x80;
		var abbrevOffset = 0x120;

		var debugAbbrev = new byte[]
		{
			0x01, 0x11, 0x00, // abbrev #1, DW_TAG_compile_unit, no children
			0x13, 0x05,       // DW_AT_language, DW_FORM_data2
			0x00, 0x00,
			0x00
		};
		Array.Copy(debugAbbrev, 0, data, abbrevOffset, debugAbbrev.Length);

		var debugInfoBody = new List<byte>
		{
			0x04, 0x00,             // DWARF v4
			0x00, 0x00, 0x00, 0x00, // abbrev offset
			0x08,                   // address size
			0x01,                   // abbrev code
			0x1C, 0x00              // DW_LANG_Rust
		};

		WriteUInt32(data.AsSpan(infoOffset, 4), (uint)debugInfoBody.Count, littleEndian: true);
		Array.Copy(debugInfoBody.ToArray(), 0, data, infoOffset + 4, debugInfoBody.Count);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian
			}
		};

		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_info", Offset = (ulong)infoOffset, Size = (ulong)(4 + debugInfoBody.Count) });
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_abbrev", Offset = (ulong)abbrevOffset, Size = (ulong)debugAbbrev.Length });

		ElfReader.ParseDwarfIndex(data, elf);
		var report = ElfReportMapper.Create(elf);

		var unit = Assert.Single(elf.Dwarf.SemanticUnits);
		var rootDie = Assert.Single(unit.RootDies);
		var attribute = Assert.Single(rootDie.Attributes);

		Assert.Equal(0x13UL, attribute.Name);
		Assert.Equal(0x1CUL, attribute.UnsignedValue);
		Assert.Equal(ElfDwarfDecodeStatus.Exact, attribute.DecodeStatus);
		Assert.Equal("DW_LANG_Rust (0x1C)", attribute.StringValue);

		var reportAttribute = Assert.Single(Assert.Single(Assert.Single(report.Dwarf.SemanticUnits).RootDies).Attributes);
		Assert.Equal("Exact", reportAttribute.DecodeStatus);
		Assert.Equal("DW_LANG_Rust (0x1C)", reportAttribute.StringValue);
	}

	[Fact]
	public void ParseDwarfIndex_SemanticModel_UnknownUserRangeIdentifiers_ArePreservedWithLoUserNames()
	{
		Assert.Equal("DW_TAG_lo_user+0x1", InvokeReaderString("GetDwarfTagName", 0x4081UL));
		Assert.Equal("DW_AT_lo_user+0x1", InvokeReaderString("GetDwarfAttributeName", 0x2001UL));
		Assert.Equal("DW_FORM_lo_user+0x1", InvokeReaderString("GetDwarfFormName", 0x1F01UL));
	}

	[Fact]
	public void ParseDwarfIndex_LineTableV5_UnknownForm_DoesNotAbortParsing()
	{
		var data = new byte[0x200];
		var lineOffset = 0x80;

		var lineBody = new byte[]
		{
			0x05, 0x00,             // version
			0x08,                   // address_size
			0x00,                   // segment_selector_size
			0x0A, 0x00, 0x00, 0x00, // header_length
			0x01,                   // minimum_instruction_length
			0x01,                   // maximum_operations_per_instruction
			0x01,                   // default_is_stmt
			0xFB,                   // line_base
			0x0E,                   // line_range
			0x01,                   // opcode_base
			0x01,                   // directory format count
			0x01,                   // directory content type (DW_LNCT_path)
			0x44,                   // unknown form
			0x01,                   // include directory count
			0x2A,                   // payload for unknown form fallback
			0x00,                   // file format count
			0x00                    // file entry count
		};

		WriteUInt32(data.AsSpan(lineOffset, 4), (uint)lineBody.Length, littleEndian: true);
		Array.Copy(lineBody, 0, data, lineOffset + 4, lineBody.Length);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian
			}
		};
		elf.Sections.Add(new ElfSectionHeader { Name = ".debug_line", Offset = (ulong)lineOffset, Size = (ulong)(4 + lineBody.Length) });

		ElfReader.ParseDwarfIndex(data, elf);

		var lineTable = Assert.Single(elf.Dwarf.LineTables);
		Assert.Equal((ushort)5, lineTable.Version);
		Assert.Equal(1UL, lineTable.IncludeDirectoryCount);
	}

	[Fact]
	public void ParseUnwindData_SyntheticEhFrame_ParsesCieFdeRules()
	{
		var ehFrame = new List<byte>();
		ehFrame.AddRange(BitConverter.GetBytes((uint)14));
		ehFrame.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x78, 0x10, 0x0C, 0x07, 0x08, 0x90, 0x01 });
		ehFrame.AddRange(BitConverter.GetBytes((uint)20));
		ehFrame.AddRange(BitConverter.GetBytes((uint)0x16));
		ehFrame.AddRange(BitConverter.GetBytes(0x401000UL));
		ehFrame.AddRange(BitConverter.GetBytes(0x20UL));
		ehFrame.AddRange(BitConverter.GetBytes((uint)0));

		var data = new byte[0x200];
		var offset = 0x80;
		Array.Copy(ehFrame.ToArray(), 0, data, offset, ehFrame.Count);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian
			}
		};
		elf.Sections.Add(new ElfSectionHeader
		{
			Name = ".eh_frame",
			Offset = (ulong)offset,
			Size = (ulong)ehFrame.Count,
			Address = 0x700000
		});

		ElfReader.ParseUnwindData(data, elf);

		Assert.True(elf.Unwind.EhFrame.Present);
		Assert.Equal((uint)1, elf.Unwind.EhFrame.CieCount);
		Assert.Equal((uint)1, elf.Unwind.EhFrame.FdeCount);
		Assert.True(elf.Unwind.EhFrame.TerminatorSeen);
		Assert.Single(elf.Unwind.EhFrame.CieEntries);
		Assert.Single(elf.Unwind.EhFrame.FdeEntries);

		var cie = elf.Unwind.EhFrame.CieEntries[0];
		Assert.Equal((byte)1, cie.Version);
		Assert.Equal((ulong)16, cie.ReturnAddressRegister);
		Assert.Equal((long)(-8), cie.DataAlignmentFactor);
		Assert.Contains(cie.Instructions, instruction => instruction.Contains("DW_CFA_def_cfa", StringComparison.Ordinal));

		var fde = elf.Unwind.EhFrame.FdeEntries[0];
		Assert.Equal(0x401000UL, fde.InitialLocation);
		Assert.Equal(0x20UL, fde.AddressRange);
		Assert.True(fde.CfaRuleAvailable);
		Assert.Equal(7UL, fde.CfaRegister);
		Assert.Equal(8L, fde.CfaOffset);
		Assert.True(fde.ReturnAddressOffsetAvailable);
		Assert.Equal(-8L, fde.ReturnAddressOffset);
	}

	[Fact]
	public void ParseNotes_SyntheticGnuExtendedTypes_AreNamedAndDecoded()
	{
		var noteSectionData = BuildNoteSection(
			CreateNote("GNU", 4, Encoding.ASCII.GetBytes("GNU gold 2.41\0")),
			CreateNote("GNU", 2, new byte[] { 0x01, 0x00, 0x00, 0x00, 0xA5, 0x5A, 0x00, 0x00 }));

		var elfData = new byte[0x200];
		var offset = 0x80;
		Array.Copy(noteSectionData, 0, elfData, offset, noteSectionData.Length);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian
			}
		};
		elf.Sections.Add(new ElfSectionHeader
		{
			Name = ".note.gnu.build-id",
			Type = 7,
			Offset = (ulong)offset,
			Size = (ulong)noteSectionData.Length,
			AddressAlign = 4
		});

		ElfReader.ParseNotes(elfData, elf);

		Assert.Contains(elf.Notes, note => note.Type == 4 && note.TypeName == "NT_GNU_GOLD_VERSION" && note.DecodedDescription.Contains("GNU gold", StringComparison.Ordinal));
		Assert.Contains(elf.Notes, note => note.Type == 2 && note.TypeName == "NT_GNU_HWCAP" && note.DecodedDescription.Contains("hwcap_words", StringComparison.Ordinal));
	}

	[Fact]
	public void ParseNotes_SyntheticCoreSigInfo_DecodesSignalCodeAndErrno()
	{
		var descriptor = new byte[12];
		WriteUInt32(descriptor.AsSpan(0, 4), 11, littleEndian: true);
		WriteUInt32(descriptor.AsSpan(4, 4), 1, littleEndian: true);
		WriteUInt32(descriptor.AsSpan(8, 4), 0, littleEndian: true);

		var noteSectionData = BuildNoteSection(CreateNote("CORE", 0x53494749, descriptor));
		var elfData = new byte[0x200];
		var offset = 0x80;
		Array.Copy(noteSectionData, 0, elfData, offset, noteSectionData.Length);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian,
				Type = 4
			}
		};
		elf.Sections.Add(new ElfSectionHeader
		{
			Name = ".note.core.siginfo",
			Type = 7,
			Offset = (ulong)offset,
			Size = (ulong)noteSectionData.Length,
			AddressAlign = 4
		});

		ElfReader.ParseNotes(elfData, elf);

		var sigInfo = elf.Notes.Single(note => note.Type == 0x53494749);
		Assert.Equal("NT_SIGINFO", sigInfo.TypeName);
		Assert.Contains("signal=11", sigInfo.DecodedDescription, StringComparison.Ordinal);
		Assert.Contains("code=1", sigInfo.DecodedDescription, StringComparison.Ordinal);
		Assert.Contains("errno=0", sigInfo.DecodedDescription, StringComparison.Ordinal);
	}

	[Fact]
	public void ParseNotes_SyntheticCoreExtendedTypes_AreNamedAndDecoded()
	{
		var noteSectionData = BuildNoteSection(
			CreateNote("CORE", 0x203, new byte[24]),
			CreateNote("CORE", 0x10D, new byte[16]));

		var elfData = new byte[0x200];
		var offset = 0x80;
		Array.Copy(noteSectionData, 0, elfData, offset, noteSectionData.Length);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian
			}
		};
		elf.Sections.Add(new ElfSectionHeader
		{
			Name = ".note.core.ext",
			Type = 7,
			Offset = (ulong)offset,
			Size = (ulong)noteSectionData.Length,
			AddressAlign = 4
		});

		ElfReader.ParseNotes(elfData, elf);

		Assert.Contains(elf.Notes, note =>
			note.TypeName == "NT_X86_CET"
			&& note.DecodedDescription.Contains("x86_cet_bytes=24", StringComparison.Ordinal));
		Assert.Contains(elf.Notes, note =>
			note.TypeName == "NT_PPC_TM_CTAR"
			&& note.DecodedDescription.Contains("ppc_tm_ctar_bytes=16", StringComparison.Ordinal));
	}

	[Fact]
	public void ParseNotes_SyntheticVendorTypes_AreNamedAndDecoded()
	{
		var freeBsdAbi = new byte[4];
		WriteUInt32(freeBsdAbi.AsSpan(0, 4), 14, littleEndian: true);
		var androidMemtagSync = new byte[4];
		WriteUInt32(androidMemtagSync.AsSpan(0, 4), 2, littleEndian: true);
		var linuxNote = new byte[4];
		WriteUInt32(linuxNote.AsSpan(0, 4), 0xABCD, littleEndian: true);

		var noteSectionData = BuildNoteSection(
			CreateNote("FDO", 0xCAFE1A7E, Encoding.ASCII.GetBytes("pkg=elf-inspector\0")),
			CreateNote("Go", 4, Encoding.ASCII.GetBytes("go1.22.0\0")),
			CreateNote("FreeBSD", 1, freeBsdAbi),
			CreateNote("Android", 0x101, androidMemtagSync),
			CreateNote("LINUX", 0x1234, linuxNote));

		var elfData = new byte[0x200];
		var offset = 0x80;
		Array.Copy(noteSectionData, 0, elfData, offset, noteSectionData.Length);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian
			}
		};
		elf.Sections.Add(new ElfSectionHeader
		{
			Name = ".note.vendor",
			Type = 7,
			Offset = (ulong)offset,
			Size = (ulong)noteSectionData.Length,
			AddressAlign = 4
		});

		ElfReader.ParseNotes(elfData, elf);

		Assert.Contains(elf.Notes, note =>
			note.Name == "FDO"
			&& note.TypeName == "NT_FDO_PACKAGING_METADATA"
			&& note.DecodedDescription.Contains("pkg=elf-inspector", StringComparison.Ordinal));
		Assert.Contains(elf.Notes, note =>
			note.Name == "Go"
			&& note.TypeName == "NT_GO_BUILD_ID"
			&& note.DecodedDescription.Contains("go1.22.0", StringComparison.Ordinal));
		Assert.Contains(elf.Notes, note =>
			note.Name == "FreeBSD"
			&& note.TypeName == "NT_FREEBSD_ABI_TAG"
			&& note.DecodedDescription.Contains("FreeBSD_abi=14", StringComparison.Ordinal));
		Assert.Contains(elf.Notes, note =>
			note.Name == "Android"
			&& note.TypeName == "NT_ANDROID_MEMTAG_LEVEL_SYNC"
			&& note.DecodedDescription.Contains("android_memtag_sync=2", StringComparison.Ordinal));
		Assert.Contains(elf.Notes, note =>
			note.Name == "LINUX"
			&& note.TypeName == "NT_LINUX_0x1234"
			&& note.DecodedDescription.Contains("linux_note_0x1234=0xABCD", StringComparison.Ordinal));
	}

	[Fact]
	public void ParseNotes_GnuBuildAttributes_AreNamedAndDecoded_WithCaseInsensitiveNamespace()
	{
		var noteSectionData = BuildNoteSection(CreateNote("gnu", 0x100, Encoding.ASCII.GetBytes("build:open\0")));
		var elfData = new byte[0x200];
		var offset = 0x80;
		Array.Copy(noteSectionData, 0, elfData, offset, noteSectionData.Length);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian
			}
		};
		elf.Sections.Add(new ElfSectionHeader
		{
			Name = ".note.gnu.build-attr",
			Type = 7,
			Offset = (ulong)offset,
			Size = (ulong)noteSectionData.Length,
			AddressAlign = 4
		});

		ElfReader.ParseNotes(elfData, elf);

		var note = Assert.Single(elf.Notes);
		Assert.Equal("GNU", note.Name);
		Assert.Equal("NT_GNU_BUILD_ATTRIBUTE_OPEN", note.TypeName);
		Assert.Contains("build:open", note.DecodedDescription, StringComparison.Ordinal);
	}

	[Fact]
	public void ParseNotes_UnknownNamespace_UsesNamespacedTypeName_AndDecodesPreview()
	{
		var descriptor = new byte[] { 0x01, 0x02, 0xA0, 0xFF, 0x10, 0x20 };
		var noteSectionData = BuildNoteSection(CreateNote("qemu", 7, descriptor));
		var elfData = new byte[0x200];
		var offset = 0x80;
		Array.Copy(noteSectionData, 0, elfData, offset, noteSectionData.Length);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian
			}
		};
		elf.Sections.Add(new ElfSectionHeader
		{
			Name = ".note.qemu.meta",
			Type = 7,
			Offset = (ulong)offset,
			Size = (ulong)noteSectionData.Length,
			AddressAlign = 4
		});

		ElfReader.ParseNotes(elfData, elf);

		var note = Assert.Single(elf.Notes);
		Assert.Equal("qemu", note.Name);
		Assert.Equal("NT_QEMU_0x7", note.TypeName);
		Assert.Contains("preview=0x", note.DecodedDescription, StringComparison.Ordinal);
	}

	[Fact]
	public void ParseNotes_LinuxCoreNamespace_UsesCoreTypeNameAndCoreDecode()
	{
		var descriptor = new byte[12];
		WriteUInt32(descriptor.AsSpan(0, 4), 11, littleEndian: true);
		WriteUInt32(descriptor.AsSpan(4, 4), 1, littleEndian: true);
		WriteUInt32(descriptor.AsSpan(8, 4), 0, littleEndian: true);
		var noteSectionData = BuildNoteSection(CreateNote("LINUX", 0x53494749, descriptor));
		var elfData = new byte[0x200];
		var offset = 0x80;
		Array.Copy(noteSectionData, 0, elfData, offset, noteSectionData.Length);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian
			}
		};
		elf.Sections.Add(new ElfSectionHeader
		{
			Name = ".note.linux.core",
			Type = 7,
			Offset = (ulong)offset,
			Size = (ulong)noteSectionData.Length,
			AddressAlign = 4
		});

		ElfReader.ParseNotes(elfData, elf);

		var note = Assert.Single(elf.Notes);
		Assert.Equal("NT_SIGINFO", note.TypeName);
		Assert.Contains("signal=11", note.DecodedDescription, StringComparison.Ordinal);
	}

	[Fact]
	public void ParseNotes_CoreNamespace_UnknownArchRange_UsesArchSpecificTypeName()
	{
		var descriptor = new byte[4];
		WriteUInt32(descriptor.AsSpan(0, 4), 0x12345678, littleEndian: true);
		var noteSectionData = BuildNoteSection(CreateNote("CORE", 0x3FE, descriptor));
		var elfData = new byte[0x200];
		var offset = 0x80;
		Array.Copy(noteSectionData, 0, elfData, offset, noteSectionData.Length);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian
			}
		};
		elf.Sections.Add(new ElfSectionHeader
		{
			Name = ".note.core.unknown",
			Type = 7,
			Offset = (ulong)offset,
			Size = (ulong)noteSectionData.Length,
			AddressAlign = 4
		});

		ElfReader.ParseNotes(elfData, elf);

		var note = Assert.Single(elf.Notes);
		Assert.Equal("NT_S390_0x3FE", note.TypeName);
		Assert.Equal("u32=305419896 (0x12345678)", note.DecodedDescription);
	}

	[Fact]
	public void ParseNotes_StapSdt_IsNamedAndDecoded()
	{
		var descriptor = new byte[64];
		WriteUInt64(descriptor.AsSpan(0, 8), 0x401000, littleEndian: true);
		WriteUInt64(descriptor.AsSpan(8, 8), 0x400000, littleEndian: true);
		WriteUInt64(descriptor.AsSpan(16, 8), 0, littleEndian: true);
		var cursor = 24;
		var providerBytes = Encoding.ASCII.GetBytes("provider\0");
		providerBytes.CopyTo(descriptor.AsSpan(cursor));
		cursor += providerBytes.Length;
		var nameBytes = Encoding.ASCII.GetBytes("probe\0");
		nameBytes.CopyTo(descriptor.AsSpan(cursor));
		cursor += nameBytes.Length;
		var argsBytes = Encoding.ASCII.GetBytes("%ip\0");
		argsBytes.CopyTo(descriptor.AsSpan(cursor));

		var noteSectionData = BuildNoteSection(CreateNote("stapsdt", 3, descriptor));
		var elfData = new byte[0x240];
		var offset = 0x100;
		Array.Copy(noteSectionData, 0, elfData, offset, noteSectionData.Length);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian
			}
		};
		elf.Sections.Add(new ElfSectionHeader
		{
			Name = ".note.stapsdt",
			Type = 7,
			Offset = (ulong)offset,
			Size = (ulong)noteSectionData.Length,
			AddressAlign = 4
		});

		ElfReader.ParseNotes(elfData, elf);

		var note = Assert.Single(elf.Notes);
		Assert.Equal("NT_STAPSDT", note.TypeName);
		Assert.Contains("provider=provider", note.DecodedDescription, StringComparison.Ordinal);
		Assert.Contains("name=probe", note.DecodedDescription, StringComparison.Ordinal);
	}

	[Fact]
	public void ParseNotes_OversizedDescriptor_IsTruncatedWithoutParserAbort()
	{
		const uint noteType = 0x1234;
		const ulong descSize = 80UL * 1024UL * 1024UL;

		var prefix = new byte[128];
		WriteUInt32(prefix.AsSpan(0, 4), 4U, littleEndian: true); // namesz
		WriteUInt32(prefix.AsSpan(4, 4), checked((uint)descSize), littleEndian: true); // descsz
		WriteUInt32(prefix.AsSpan(8, 4), noteType, littleEndian: true); // type
		Encoding.ASCII.GetBytes("GNU\0").CopyTo(prefix.AsSpan(12, 4));
		prefix[16] = 0xAA;
		prefix[17] = 0x55;

		var noteSectionSize = 16UL + descSize;
		var source = new SparseEndianDataSource(noteSectionSize, prefix);
		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian
			}
		};
		elf.Sections.Add(new ElfSectionHeader
		{
			Name = ".note.large",
			Type = 7,
			Offset = 0,
			Size = noteSectionSize,
			AddressAlign = 4
		});

		ElfReader.ParseNotes(source, elf);

		var note = Assert.Single(elf.Notes);
		Assert.Equal("GNU", note.Name);
		Assert.Equal(noteType, note.Type);
		Assert.Equal(64, note.Descriptor.Length);
		Assert.Contains("descriptor truncated", note.DecodedDescription, StringComparison.Ordinal);
		Assert.Contains("bytes=", note.DecodedDescription, StringComparison.Ordinal);
	}

	[Fact]
	public void Parse_HelloX64_Notes_AreDeduplicatedAndPropertyIsDecoded()
	{
		var helloFile = GetRequiredSample("hello_x86_64");
		var elf = ElfReader.Parse(File.ReadAllBytes(helloFile));

		var uniqueKeys = new HashSet<string>(
			elf.Notes.Select(note => string.Concat(note.Name, "\0", note.Type.ToString(), "\0", Convert.ToHexString(note.Descriptor))),
			StringComparer.Ordinal);
		Assert.Equal(elf.Notes.Count, uniqueKeys.Count);

		var gnuPropertyNote = elf.Notes.FirstOrDefault(note => note.Name == "GNU" && note.Type == 5);
		Assert.NotNull(gnuPropertyNote);
		Assert.False(string.IsNullOrEmpty(gnuPropertyNote!.DecodedDescription));
		Assert.DoesNotContain("GNU_PROPERTY_0x", gnuPropertyNote.DecodedDescription, StringComparison.Ordinal);
	}

	[Fact]
	public void Parse_WithoutSectionHeaderTable_StillParsesNotesFromProgramHeaders()
	{
		var data = (byte[])File.ReadAllBytes(GetRequiredSample("hello_x86_64")).Clone();
		StripSectionHeaderTable(data);

		var elf = ElfReader.Parse(data);

		Assert.NotEmpty(elf.Notes);
		Assert.Contains(elf.Notes, note => note.Name == "GNU" && note.Type == 3); // NT_GNU_BUILD_ID
	}

	[Fact]
	public void Parse_CompressedSectionMetadata_IsConsistentWhenPresent()
	{
		var sampleFiles = GetSampleElfFiles();
		Assert.NotEmpty(sampleFiles);

		foreach (var file in sampleFiles)
		{
			var elf = ElfReader.Parse(File.ReadAllBytes(file));
			Assert.NotNull(elf.CompressedSections);
			Assert.NotNull(elf.SectionGroups);

			Assert.All(elf.CompressedSections, section =>
			{
				Assert.False(string.IsNullOrEmpty(section.Name));
				Assert.True(section.DecompressionSucceeded, $"Compressed section failed to decompress in {Path.GetFileName(file)}: {section.Name} ({section.Error})");
				Assert.True(section.UncompressedSize > 0);
			});
		}
	}

	[Fact]
	public void ParseDwarfIndex_ShfCompressedZstdSection_IsDecoded()
	{
		var debugInfo = new byte[]
		{
			0x07, 0x00, 0x00, 0x00,
			0x04, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x08
		};
		var zstdFrame = BuildZstdRawSingleSegmentFrame(debugInfo);
		var compressedSectionData = BuildElfCompressedSectionPayload(
			uncompressedSize: (ulong)debugInfo.Length,
			compressionType: 2,
			compressedPayload: zstdFrame,
			littleEndian: true,
			isElf64: true);

		var data = new byte[0x200];
		var sectionOffset = 0x80;
		Array.Copy(compressedSectionData, 0, data, sectionOffset, compressedSectionData.Length);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian
			}
		};
		elf.Sections.Add(new ElfSectionHeader
		{
			Name = ".debug_info",
			Flags = 0x800,
			Offset = (ulong)sectionOffset,
			Size = (ulong)compressedSectionData.Length,
			AddressAlign = 1
		});

		ElfReader.ParseSectionSpecialCases(data, elf);
		Assert.Single(elf.CompressedSections);
		Assert.Equal("ELFCOMPRESS_ZSTD", elf.CompressedSections[0].CompressionTypeName);
		Assert.True(elf.CompressedSections[0].DecompressionSucceeded, elf.CompressedSections[0].Error);
		Assert.Equal((ulong)debugInfo.Length, elf.CompressedSections[0].UncompressedSize);

		ElfReader.ParseDwarfIndex(data, elf);
		Assert.Single(elf.Dwarf.CompileUnits);
		Assert.Equal((ushort)4, elf.Dwarf.CompileUnits[0].Version);
	}

	[Fact]
	public void ParseSectionSpecialCases_ShfCompressedHugePayload_IsRejectedGracefully()
	{
		var sectionSize = 24UL + (ulong)int.MaxValue + 1024UL;
		var prefix = new byte[64];
		WriteUInt32(prefix.AsSpan(0, 4), 1U, littleEndian: true); // ELFCOMPRESS_ZLIB
		WriteUInt32(prefix.AsSpan(4, 4), 0U, littleEndian: true); // ch_reserved
		WriteUInt64(prefix.AsSpan(8, 8), 128UL, littleEndian: true); // ch_size
		WriteUInt64(prefix.AsSpan(16, 8), 1UL, littleEndian: true); // ch_addralign

		var source = new SparseEndianDataSource(sectionSize, prefix);
		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian
			}
		};
		elf.Sections.Add(new ElfSectionHeader
		{
			Name = ".debug_info",
			Flags = 0x800, // SHF_COMPRESSED
			Offset = 0,
			Size = sectionSize,
			AddressAlign = 1
		});

		ElfReader.ParseSectionSpecialCases(source, elf);

		var compressed = Assert.Single(elf.CompressedSections);
		Assert.False(compressed.DecompressionSucceeded);
		Assert.Contains("contiguous managed buffer window", compressed.Error, StringComparison.Ordinal);
	}

	[Fact]
	public void ParseDwarfIndex_GnuZdebugZstdSection_IsDecoded()
	{
		var debugInfo = new byte[]
		{
			0x07, 0x00, 0x00, 0x00,
			0x04, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x08
		};
		var zstdFrame = BuildZstdRawSingleSegmentFrame(debugInfo);
		var gnuSectionData = BuildGnuZdebugSectionPayload(
			codecHeader: "ZSTD",
			uncompressedSize: (ulong)debugInfo.Length,
			compressedPayload: zstdFrame);

		var data = new byte[0x200];
		var sectionOffset = 0x80;
		Array.Copy(gnuSectionData, 0, data, sectionOffset, gnuSectionData.Length);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian
			}
		};
		elf.Sections.Add(new ElfSectionHeader
		{
			Name = ".zdebug_info",
			Offset = (ulong)sectionOffset,
			Size = (ulong)gnuSectionData.Length,
			AddressAlign = 1
		});

		ElfReader.ParseSectionSpecialCases(data, elf);
		Assert.Single(elf.CompressedSections);
		Assert.Equal("ELFCOMPRESS_ZSTD (GNU)", elf.CompressedSections[0].CompressionTypeName);
		Assert.True(elf.CompressedSections[0].DecompressionSucceeded, elf.CompressedSections[0].Error);
		Assert.Equal((ulong)debugInfo.Length, elf.CompressedSections[0].UncompressedSize);

		ElfReader.ParseDwarfIndex(data, elf);
		Assert.Single(elf.Dwarf.CompileUnits);
		Assert.Equal((ushort)4, elf.Dwarf.CompileUnits[0].Version);
	}

	[Fact]
	public void ParseDwarfIndex_ShfCompressedZstd_MultiFrameRawPayload_IsDecoded()
	{
		var debugInfo = new byte[]
		{
			0x07, 0x00, 0x00, 0x00,
			0x04, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x08
		};
		var zstdFrames = BuildZstdConcatenatedRawFrames(
			debugInfo.AsSpan(0, 5).ToArray(),
			debugInfo.AsSpan(5).ToArray());
		var compressedSectionData = BuildElfCompressedSectionPayload(
			uncompressedSize: (ulong)debugInfo.Length,
			compressionType: 2,
			compressedPayload: zstdFrames,
			littleEndian: true,
			isElf64: true);

		var data = new byte[0x200];
		var sectionOffset = 0x80;
		Array.Copy(compressedSectionData, 0, data, sectionOffset, compressedSectionData.Length);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian
			}
		};
		elf.Sections.Add(new ElfSectionHeader
		{
			Name = ".debug_info",
			Flags = 0x800,
			Offset = (ulong)sectionOffset,
			Size = (ulong)compressedSectionData.Length,
			AddressAlign = 1
		});

		ElfReader.ParseSectionSpecialCases(data, elf);
		Assert.Single(elf.CompressedSections);
		Assert.Equal("ELFCOMPRESS_ZSTD", elf.CompressedSections[0].CompressionTypeName);
		Assert.True(elf.CompressedSections[0].DecompressionSucceeded, elf.CompressedSections[0].Error);
		Assert.Equal((ulong)debugInfo.Length, elf.CompressedSections[0].UncompressedSize);

		ElfReader.ParseDwarfIndex(data, elf);
		Assert.Single(elf.Dwarf.CompileUnits);
		Assert.Equal((ushort)4, elf.Dwarf.CompileUnits[0].Version);
	}

	[Fact]
	public void Parse_CoreTypedSample_InitializesCoreReportBranch()
	{
		var data = (byte[])File.ReadAllBytes(GetRequiredSample("nano")).Clone();
		ForceElfType(data, 4);

		var elf = ElfReader.Parse(data);
		var report = ElfReportMapper.Create(elf);

		Assert.NotNull(elf.CoreDump);
		Assert.True(elf.CoreDump.IsCoreDump);
		Assert.NotNull(report.CoreDump);
		Assert.True(report.CoreDump.IsCoreDump);
	}

	[Fact]
	public void Parse_CoreNotes_X86_64_PrStatus_UsesStructuredLayout()
	{
		var prStatus = new byte[112 + (27 * 8)];
		WriteUInt32(prStatus.AsSpan(0, 4), 11, littleEndian: true); // si_signo
		WriteUInt16(prStatus.AsSpan(12, 2), 5, littleEndian: true); // pr_cursig
		WriteUInt32(prStatus.AsSpan(32, 4), 1234, littleEndian: true); // pr_pid
		for (var i = 0; i < 27; i++)
			WriteUInt64(prStatus.AsSpan(112 + (i * 8), 8), (ulong)(0x1000 + i), littleEndian: true);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Type = 4,
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian,
				Machine = 62
			}
		};
		elf.Notes.Add(new ElfNote
		{
			Name = "CORE",
			Type = 1,
			Descriptor = prStatus,
			TypeName = "NT_PRSTATUS",
			DecodedDescription = string.Empty
		});

		ElfReader.ParseCoreDumpInfo(elf);

		Assert.True(elf.CoreDump.IsCoreDump);
		Assert.Equal(1234, elf.CoreDump.ProcessId);
		Assert.Equal(11, elf.CoreDump.Signal);
		Assert.Single(elf.CoreDump.Threads);
		Assert.Equal(1234, elf.CoreDump.Threads[0].ThreadId);
		Assert.Equal(11, elf.CoreDump.Threads[0].Signal);
		Assert.Equal(5, elf.CoreDump.Threads[0].CurrentSignal);
		Assert.Equal(27, elf.CoreDump.Threads[0].RegisterPreview.Count);
		Assert.Equal(0x1000UL, elf.CoreDump.Threads[0].RegisterPreview[0]);
		Assert.Equal(0x101AUL, elf.CoreDump.Threads[0].RegisterPreview[^1]);
	}

	[Fact]
	public void Parse_CoreNotes_AArch64_PrPsInfoAuxvAndFile_AreParsedAndBounded()
	{
		var prPsInfo = new byte[136];
		WriteUInt32(prPsInfo.AsSpan(24, 4), 777, littleEndian: true); // pr_pid
		System.Text.Encoding.ASCII.GetBytes("coreproc").CopyTo(prPsInfo.AsSpan(40, 8)); // pr_fname[16]

		var auxv = new byte[3 * 16];
		WriteUInt64(auxv.AsSpan(0, 8), 6, littleEndian: true);
		WriteUInt64(auxv.AsSpan(8, 8), 4096, littleEndian: true);
		WriteUInt64(auxv.AsSpan(16, 8), 0, littleEndian: true);
		WriteUInt64(auxv.AsSpan(24, 8), 0, littleEndian: true);
		WriteUInt64(auxv.AsSpan(32, 8), 31, littleEndian: true); // should be ignored after AT_NULL
		WriteUInt64(auxv.AsSpan(40, 8), 1, littleEndian: true);

		var file = new byte[16 + (2 * 24)];
		WriteUInt64(file.AsSpan(0, 8), 10, littleEndian: true); // declared count > available entries
		WriteUInt64(file.AsSpan(8, 8), 4096, littleEndian: true);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Type = 4,
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian,
				Machine = 183
			}
		};
		elf.Notes.Add(new ElfNote { Name = "CORE", Type = 3, Descriptor = prPsInfo, TypeName = "NT_PRPSINFO", DecodedDescription = string.Empty });
		elf.Notes.Add(new ElfNote { Name = "CORE", Type = 6, Descriptor = auxv, TypeName = "NT_AUXV", DecodedDescription = string.Empty });
		elf.Notes.Add(new ElfNote { Name = "CORE", Type = 0x46494C45, Descriptor = file, TypeName = "NT_FILE", DecodedDescription = string.Empty });

		ElfReader.ParseCoreDumpInfo(elf);

		Assert.True(elf.CoreDump.IsCoreDump);
		Assert.Equal("coreproc", elf.CoreDump.ProcessName);
		Assert.Equal(777, elf.CoreDump.ProcessId);
		Assert.Equal(2, elf.CoreDump.AuxVectorEntryCount);
		Assert.Equal(2, elf.CoreDump.FileMappingCount);
	}

	[Fact]
	public void ParseCoreDumpInfo_X86_64_FramePointerWalk_ProducesDeterministicStackTrace()
	{
		var coreBytes = new byte[0x400];
		var execSegmentOffset = 0x100UL;
		var stackSegmentOffset = 0x200UL;
		var execVaddr = 0x401000UL;
		var stackVaddr = 0x500000UL;

		var fp0 = stackVaddr + 0x20;
		var fp1 = stackVaddr + 0x40;
		WriteUInt64(coreBytes.AsSpan((int)(stackSegmentOffset + 0x20), 8), fp1, littleEndian: true);
		WriteUInt64(coreBytes.AsSpan((int)(stackSegmentOffset + 0x28), 8), execVaddr + 0x20, littleEndian: true);
		WriteUInt64(coreBytes.AsSpan((int)(stackSegmentOffset + 0x40), 8), 0, littleEndian: true);
		WriteUInt64(coreBytes.AsSpan((int)(stackSegmentOffset + 0x48), 8), execVaddr + 0x40, littleEndian: true);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Type = 4,
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian,
				Machine = 62
			}
		};
		elf.ProgramHeaders.Add(new ElfProgramHeader
		{
			Type = 1,
			Offset = execSegmentOffset,
			VirtualAddress = execVaddr,
			FileSize = 0x100,
			MemorySize = 0x100,
			Flags = 0x5
		});
		elf.ProgramHeaders.Add(new ElfProgramHeader
		{
			Type = 1,
			Offset = stackSegmentOffset,
			VirtualAddress = stackVaddr,
			FileSize = 0x100,
			MemorySize = 0x100,
			Flags = 0x6
		});

		var prStatus = new byte[112 + (27 * 8)];
		WriteUInt32(prStatus.AsSpan(0, 4), 11, littleEndian: true); // si_signo
		WriteUInt16(prStatus.AsSpan(12, 2), 11, littleEndian: true); // pr_cursig
		WriteUInt32(prStatus.AsSpan(32, 4), 1337, littleEndian: true); // pr_pid
		WriteUInt64(prStatus.AsSpan(112 + (4 * 8), 8), fp0, littleEndian: true); // rbp
		WriteUInt64(prStatus.AsSpan(112 + (16 * 8), 8), execVaddr, littleEndian: true); // rip
		WriteUInt64(prStatus.AsSpan(112 + (19 * 8), 8), stackVaddr, littleEndian: true); // rsp
		elf.Notes.Add(new ElfNote { Name = "CORE", Type = 1, Descriptor = prStatus, TypeName = "NT_PRSTATUS", DecodedDescription = string.Empty });

		elf.Symbols.Add(new ElfSymbol { Name = "entry", Value = execVaddr, Size = 0x20 });
		elf.Symbols.Add(new ElfSymbol { Name = "frame1", Value = execVaddr + 0x20, Size = 0x20 });
		elf.Symbols.Add(new ElfSymbol { Name = "frame2", Value = execVaddr + 0x40, Size = 0x20 });

		ElfReader.ParseCoreDumpInfo(coreBytes, elf);
		var report = ElfReportMapper.Create(elf);

		Assert.Single(elf.CoreDump.UnwindThreads);
		var unwind = elf.CoreDump.UnwindThreads[0];
		Assert.True(unwind.Complete, $"complete={unwind.Complete}, frames={unwind.Frames.Count}, strategy={unwind.Strategy}");
		Assert.True(unwind.Frames.Count >= 3, $"frames={unwind.Frames.Count}");
		Assert.Equal(execVaddr, unwind.Frames[0].InstructionPointer);
		Assert.Equal(execVaddr + 0x20, unwind.Frames[1].InstructionPointer);
		Assert.Equal(execVaddr + 0x40, unwind.Frames[2].InstructionPointer);

		Assert.Single(report.CoreDump.UnwindThreads);
		Assert.True(report.CoreDump.UnwindThreads[0].Frames.Count >= 3);
	}

	[Fact]
	public void ParseCoreDumpInfo_X86_64_EhFrameCfiFallback_ProducesAdditionalFrame()
	{
		var coreBytes = new byte[0x400];
		var execSegmentOffset = 0x100UL;
		var stackSegmentOffset = 0x200UL;
		var execVaddr = 0x401000UL;
		var stackVaddr = 0x500000UL;

		WriteUInt64(coreBytes.AsSpan((int)stackSegmentOffset, 8), execVaddr + 0x20, littleEndian: true);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Type = 4,
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian,
				Machine = 62
			},
			Unwind = new ElfUnwindInfo
			{
				EhFrame = new ElfEhFrameInfo()
			}
		};
		elf.ProgramHeaders.Add(new ElfProgramHeader
		{
			Type = 1,
			Offset = execSegmentOffset,
			VirtualAddress = execVaddr,
			FileSize = 0x100,
			MemorySize = 0x100,
			Flags = 0x5
		});
		elf.ProgramHeaders.Add(new ElfProgramHeader
		{
			Type = 1,
			Offset = stackSegmentOffset,
			VirtualAddress = stackVaddr,
			FileSize = 0x100,
			MemorySize = 0x100,
			Flags = 0x6
		});
		elf.Unwind.EhFrame.FdeEntries.Add(new ElfEhFrameFdeInfo
		{
			InitialLocation = execVaddr,
			EndLocation = execVaddr + 0x100,
			CfaRuleAvailable = true,
			CfaRegister = 7,
			CfaOffset = 8,
			ReturnAddressOffsetAvailable = true,
			ReturnAddressOffset = -8
		});

		var prStatus = new byte[112 + (27 * 8)];
		WriteUInt32(prStatus.AsSpan(0, 4), 11, littleEndian: true);
		WriteUInt16(prStatus.AsSpan(12, 2), 11, littleEndian: true);
		WriteUInt32(prStatus.AsSpan(32, 4), 1337, littleEndian: true);
		WriteUInt64(prStatus.AsSpan(112 + (4 * 8), 8), 0, littleEndian: true); // rbp intentionally invalid
		WriteUInt64(prStatus.AsSpan(112 + (16 * 8), 8), execVaddr, littleEndian: true); // rip
		WriteUInt64(prStatus.AsSpan(112 + (19 * 8), 8), stackVaddr, littleEndian: true); // rsp
		elf.Notes.Add(new ElfNote { Name = "CORE", Type = 1, Descriptor = prStatus, TypeName = "NT_PRSTATUS", DecodedDescription = string.Empty });

		elf.Symbols.Add(new ElfSymbol { Name = "entry", Value = execVaddr, Size = 0x20 });
		elf.Symbols.Add(new ElfSymbol { Name = "callee", Value = execVaddr + 0x20, Size = 0x20 });

		ElfReader.ParseCoreDumpInfo(coreBytes, elf);

		Assert.Single(elf.CoreDump.UnwindThreads);
		var unwind = elf.CoreDump.UnwindThreads[0];
		Assert.True(unwind.Complete);
		Assert.True(unwind.Frames.Count >= 2);
		Assert.Contains(unwind.Frames, frame => frame.InstructionPointer == execVaddr + 0x20 && frame.Strategy == "eh-frame-cfi");
	}

	[Fact]
	public void Parse_CoreNotes_RiscV_PrStatus_UsesStructuredLayout()
	{
		var prStatus = new byte[112 + (33 * 8)];
		WriteUInt32(prStatus.AsSpan(0, 4), 7, littleEndian: true);
		WriteUInt16(prStatus.AsSpan(12, 2), 7, littleEndian: true);
		WriteUInt32(prStatus.AsSpan(32, 4), 4242, littleEndian: true);
		for (var i = 0; i < 33; i++)
			WriteUInt64(prStatus.AsSpan(112 + (i * 8), 8), (ulong)(0x2000 + i), littleEndian: true);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Type = 4,
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian,
				Machine = 243
			}
		};
		elf.Notes.Add(new ElfNote
		{
			Name = "CORE",
			Type = 1,
			Descriptor = prStatus,
			TypeName = "NT_PRSTATUS",
			DecodedDescription = string.Empty
		});

		ElfReader.ParseCoreDumpInfo(elf);

		Assert.True(elf.CoreDump.IsCoreDump);
		Assert.Single(elf.CoreDump.Threads);
		Assert.Equal(4242, elf.CoreDump.ProcessId);
		Assert.Equal(4242, elf.CoreDump.Threads[0].ThreadId);
		Assert.Equal(33, elf.CoreDump.Threads[0].RegisterPreview.Count);
	}

	[Fact]
	public void Parse_CoreNotes_Mips_PrStatus_UsesStructuredLayoutAndUnwindStrategy()
	{
		var prStatus = new byte[112 + (45 * 8)];
		WriteUInt32(prStatus.AsSpan(0, 4), 6, littleEndian: true);
		WriteUInt16(prStatus.AsSpan(12, 2), 6, littleEndian: true);
		WriteUInt32(prStatus.AsSpan(32, 4), 9001, littleEndian: true);
		for (var i = 0; i < 45; i++)
			WriteUInt64(prStatus.AsSpan(112 + (i * 8), 8), (ulong)(0x3000 + i), littleEndian: true);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Type = 4,
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian,
				Machine = 8
			}
		};
		elf.Notes.Add(new ElfNote
		{
			Name = "CORE",
			Type = 1,
			Descriptor = prStatus,
			TypeName = "NT_PRSTATUS",
			DecodedDescription = string.Empty
		});

		ElfReader.ParseCoreDumpInfo(elf);

		Assert.True(elf.CoreDump.IsCoreDump);
		Assert.Single(elf.CoreDump.Threads);
		Assert.Equal(9001, elf.CoreDump.Threads[0].ThreadId);
		Assert.Equal(45, elf.CoreDump.Threads[0].RegisterPreview.Count);
		Assert.Single(elf.CoreDump.UnwindThreads);
		Assert.Equal("mips-stack", elf.CoreDump.UnwindThreads[0].Strategy);
	}

	[Fact]
	public void Parse_CoreNotes_Sparc64_PrStatus_UsesStructuredLayoutAndUnwindStrategy()
	{
		var prStatus = new byte[112 + (36 * 8)];
		WriteUInt32(prStatus.AsSpan(0, 4), 5, littleEndian: true);
		WriteUInt16(prStatus.AsSpan(12, 2), 5, littleEndian: true);
		WriteUInt32(prStatus.AsSpan(32, 4), 77, littleEndian: true);
		for (var i = 0; i < 36; i++)
			WriteUInt64(prStatus.AsSpan(112 + (i * 8), 8), (ulong)(0x5000 + i), littleEndian: true);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Type = 4,
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian,
				Machine = 43
			}
		};
		elf.Notes.Add(new ElfNote
		{
			Name = "CORE",
			Type = 1,
			Descriptor = prStatus,
			TypeName = "NT_PRSTATUS",
			DecodedDescription = string.Empty
		});

		ElfReader.ParseCoreDumpInfo(elf);

		Assert.True(elf.CoreDump.IsCoreDump);
		Assert.Single(elf.CoreDump.Threads);
		Assert.Equal(77, elf.CoreDump.Threads[0].ThreadId);
		Assert.Equal(36, elf.CoreDump.Threads[0].RegisterPreview.Count);
		Assert.Single(elf.CoreDump.UnwindThreads);
		Assert.Equal("sparc-stack", elf.CoreDump.UnwindThreads[0].Strategy);
	}

	[Fact]
	public void ParseCoreDumpInfo_AArch64_LinkRegisterFallback_ProducesSecondaryFrame()
	{
		var coreBytes = new byte[0x300];
		var execSegmentOffset = 0x100UL;
		var stackSegmentOffset = 0x180UL;
		var execVaddr = 0x400000UL;
		var stackVaddr = 0x500000UL;

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Type = 4,
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian,
				Machine = 183
			}
		};
		elf.ProgramHeaders.Add(new ElfProgramHeader
		{
			Type = 1,
			Offset = execSegmentOffset,
			VirtualAddress = execVaddr,
			FileSize = 0x80,
			MemorySize = 0x80,
			Flags = 0x5
		});
		elf.ProgramHeaders.Add(new ElfProgramHeader
		{
			Type = 1,
			Offset = stackSegmentOffset,
			VirtualAddress = stackVaddr,
			FileSize = 0x80,
			MemorySize = 0x80,
			Flags = 0x6
		});

		var prStatus = new byte[112 + (34 * 8)];
		WriteUInt32(prStatus.AsSpan(0, 4), 11, littleEndian: true);
		WriteUInt16(prStatus.AsSpan(12, 2), 11, littleEndian: true);
		WriteUInt32(prStatus.AsSpan(32, 4), 7331, littleEndian: true);
		for (var i = 0; i < 34; i++)
			WriteUInt64(prStatus.AsSpan(112 + (i * 8), 8), 0, littleEndian: true);
		WriteUInt64(prStatus.AsSpan(112 + (29 * 8), 8), 0, littleEndian: true); // fp invalid
		WriteUInt64(prStatus.AsSpan(112 + (30 * 8), 8), execVaddr + 0x30, littleEndian: true); // lr
		WriteUInt64(prStatus.AsSpan(112 + (31 * 8), 8), stackVaddr + 0x20, littleEndian: true); // sp
		WriteUInt64(prStatus.AsSpan(112 + (32 * 8), 8), execVaddr + 0x10, littleEndian: true); // pc

		elf.Notes.Add(new ElfNote
		{
			Name = "CORE",
			Type = 1,
			Descriptor = prStatus,
			TypeName = "NT_PRSTATUS",
			DecodedDescription = string.Empty
		});

		ElfReader.ParseCoreDumpInfo(coreBytes, elf);

		Assert.Single(elf.CoreDump.UnwindThreads);
		var unwind = elf.CoreDump.UnwindThreads[0];
		Assert.True(unwind.Frames.Count >= 2);
		Assert.Contains(unwind.Frames, frame =>
			frame.InstructionPointer == execVaddr + 0x30
			&& frame.Strategy == "aarch64-frame-pointer-link-register");
	}

	[Fact]
	public void ParseCoreDumpInfo_S390_LinkRegisterFallback_ProducesSecondaryFrame()
	{
		var coreBytes = new byte[0x300];
		var execSegmentOffset = 0x100UL;
		var stackSegmentOffset = 0x180UL;
		var execVaddr = 0x600000UL;
		var stackVaddr = 0x700000UL;

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Type = 4,
				Class = ElfClass.Elf64,
				DataEncoding = ElfData.LittleEndian,
				Machine = 22
			}
		};
		elf.ProgramHeaders.Add(new ElfProgramHeader
		{
			Type = 1,
			Offset = execSegmentOffset,
			VirtualAddress = execVaddr,
			FileSize = 0x80,
			MemorySize = 0x80,
			Flags = 0x5
		});
		elf.ProgramHeaders.Add(new ElfProgramHeader
		{
			Type = 1,
			Offset = stackSegmentOffset,
			VirtualAddress = stackVaddr,
			FileSize = 0x80,
			MemorySize = 0x80,
			Flags = 0x6
		});

		var prStatus = new byte[112 + (18 * 8)];
		WriteUInt32(prStatus.AsSpan(0, 4), 11, littleEndian: true);
		WriteUInt16(prStatus.AsSpan(12, 2), 11, littleEndian: true);
		WriteUInt32(prStatus.AsSpan(32, 4), 8080, littleEndian: true);
		for (var i = 0; i < 18; i++)
			WriteUInt64(prStatus.AsSpan(112 + (i * 8), 8), 0, littleEndian: true);
		WriteUInt64(prStatus.AsSpan(112 + (1 * 8), 8), execVaddr + 0x10, littleEndian: true); // psw_addr => ip
		WriteUInt64(prStatus.AsSpan(112 + (16 * 8), 8), execVaddr + 0x30, littleEndian: true); // gpr14 => lr
		WriteUInt64(prStatus.AsSpan(112 + (17 * 8), 8), stackVaddr + 0x20, littleEndian: true); // gpr15 => sp

		elf.Notes.Add(new ElfNote
		{
			Name = "CORE",
			Type = 1,
			Descriptor = prStatus,
			TypeName = "NT_PRSTATUS",
			DecodedDescription = string.Empty
		});

		ElfReader.ParseCoreDumpInfo(coreBytes, elf);

		Assert.Single(elf.CoreDump.UnwindThreads);
		var unwind = elf.CoreDump.UnwindThreads[0];
		Assert.True(unwind.Frames.Count >= 2);
		Assert.Contains(unwind.Frames, frame =>
			frame.InstructionPointer == execVaddr + 0x30
			&& frame.Strategy == "s390-stack-link-register");
	}

	[Fact]
	public void ParseCoreDumpInfo_ArmSupplementalRegisterNote_ExtendsRegisterPreview()
	{
		var prStatus = new byte[72 + (18 * 4)];
		WriteUInt32(prStatus.AsSpan(0, 4), 6, littleEndian: true);
		WriteUInt16(prStatus.AsSpan(12, 2), 6, littleEndian: true);
		WriteUInt32(prStatus.AsSpan(24, 4), 404, littleEndian: true);
		for (var i = 0; i < 18; i++)
			WriteUInt32(prStatus.AsSpan(72 + (i * 4), 4), 0x1000 + i, littleEndian: true);

		var armVfp = new byte[32];
		for (var i = 0; i < 8; i++)
			WriteUInt32(armVfp.AsSpan(i * 4, 4), 0x2000 + i, littleEndian: true);

		var elf = new ElfFile
		{
			Header = new ElfHeader
			{
				Type = 4,
				Class = ElfClass.Elf32,
				DataEncoding = ElfData.LittleEndian,
				Machine = 40
			}
		};
		elf.Notes.Add(new ElfNote { Name = "CORE", Type = 1, Descriptor = prStatus, TypeName = "NT_PRSTATUS", DecodedDescription = string.Empty });
		elf.Notes.Add(new ElfNote { Name = "CORE", Type = 0x400, Descriptor = armVfp, TypeName = "NT_ARM_VFP", DecodedDescription = string.Empty });

		ElfReader.ParseCoreDumpInfo(elf);

		Assert.Single(elf.CoreDump.Threads);
		Assert.True(elf.CoreDump.Threads[0].RegisterPreview.Count >= 26);
	}

	[Fact]
	public void Report_Nano_ParsesGnuHashTablesAndLookupPaths()
	{
		var nanoFile = GetRequiredSample("nano");
		var elf = ElfReader.Parse(File.ReadAllBytes(nanoFile));
		var report = ElfReportMapper.Create(elf);

		Assert.NotNull(elf.GnuHashTable);
		Assert.NotEmpty(elf.GnuHashTable!.Buckets);
		Assert.Empty(elf.GnuHashTable.Chains);
		Assert.Empty(elf.SysvHashTable?.Buckets ?? Enumerable.Empty<uint>());

		Assert.NotNull(report.HashTables);
		Assert.True(report.HashTables.Gnu.Present);
		Assert.NotEmpty(report.HashTables.Gnu.Buckets);
		Assert.Empty(report.HashTables.Gnu.Chains);
		Assert.NotEmpty(report.HashTables.LookupPaths);
		Assert.All(report.HashTables.LookupPaths, path => Assert.Equal("GNU", path.Algorithm));
		Assert.All(report.HashTables.LookupPaths, path => Assert.False(path.MatchFound));
		Assert.All(report.HashTables.LookupPaths, path => Assert.Equal(0U, path.BucketValue));
	}

	[Fact]
	public void Report_HelloX64_GnuHashLookupPaths_CanResolveMatches()
	{
		var helloFile = GetRequiredSample("hello_x86_64");
		var elf = ElfReader.Parse(File.ReadAllBytes(helloFile));
		var report = ElfReportMapper.Create(elf);

		Assert.NotNull(elf.GnuHashTable);
		Assert.NotEmpty(elf.GnuHashTable!.Buckets);
		Assert.NotEmpty(elf.GnuHashTable.Chains);

		Assert.NotNull(report.HashTables);
		Assert.True(report.HashTables.Gnu.Present);
		Assert.NotEmpty(report.HashTables.LookupPaths);
		Assert.Contains(report.HashTables.LookupPaths, path => path.Algorithm == "GNU" && path.MatchFound);
	}

	[Fact]
	public void Parse_HashLookupPaths_SymbolLimit_IsConfigurable()
	{
		var nanoFile = GetRequiredSample("nano");
		var data = File.ReadAllBytes(nanoFile);

		var limited = ElfReader.Parse(data, new ElfParseOptions
		{
			HashLookupPathSymbolLimit = 1
		});
		var unlimited = ElfReader.Parse(data, new ElfParseOptions
		{
			HashLookupPathSymbolLimit = null
		});

		var hashAlgorithmCount = (limited.SysvHashTable != null ? 1 : 0) + (limited.GnuHashTable != null ? 1 : 0);
		Assert.True(hashAlgorithmCount > 0);
		Assert.Equal(hashAlgorithmCount, limited.HashLookupPaths.Count);
		Assert.True(unlimited.HashLookupPaths.Count > limited.HashLookupPaths.Count);
	}

	[Fact]
	public void ReportMapper_Mappings_AdditionalKnownValues_AreResolved()
	{
		Assert.Equal("LoongArch", InvokeReportMapperString("TranslateMachine", (ushort)258));
		Assert.Equal("MIPS RS3000 Little-endian", InvokeReportMapperString("TranslateMachine", (ushort)10));
		Assert.Equal("ARM EABI", InvokeReportMapperString("TranslateOsAbi", (byte)64));
		Assert.Equal("UNIX - GNU", InvokeReportMapperString("TranslateOsAbi", (byte)5));
		Assert.Equal("SHT_GNU_ATTRIBUTES", InvokeReportMapperString("TranslateSectionType", 0x6FFFFFF5U));
		Assert.Equal("SHT_MIPS_ABIFLAGS", InvokeReportMapperString("TranslateSectionType", 0x7000002AU));
		Assert.Equal("PT_SUNWSTACK", InvokeReportMapperString("TranslateSegmentType", 0x6FFFFFFBU));
		Assert.Equal("PT_MIPS_ABIFLAGS", InvokeReportMapperString("TranslateSegmentType", 0x70000003U));
	}

	[Fact]
	public void ReportMapper_Mappings_UnknownValues_UseStableSpecIdentifiers()
	{
		Assert.Equal("EM_4660", InvokeReportMapperString("TranslateMachine", (ushort)4660));
		Assert.Equal("ELFOSABI_222", InvokeReportMapperString("TranslateOsAbi", (byte)222));
	}

	[Fact]
	public void Parse_WithoutSectionHeaderTable_StillResolvesDynamicData()
	{
		var data = (byte[])File.ReadAllBytes(GetRequiredSample("busybox")).Clone();
		StripSectionHeaderTable(data);

		var elf = ElfReader.Parse(data);

		Assert.NotEmpty(elf.DynamicEntries);
		Assert.NotEmpty(elf.ImportLibraries);
		Assert.NotEmpty(elf.Symbols);
		Assert.NotEmpty(elf.Relocations);
	}

	[Fact]
	public void Parse_WithoutSectionHeaderTable_ResolvesVersionedImportsViaDynamicTables()
	{
		var data = (byte[])File.ReadAllBytes(GetRequiredSample("nano")).Clone();
		StripSectionHeaderTable(data);

		var elf = ElfReader.Parse(data);
		var importedSymbols = elf.ImportedSymbols;

		Assert.NotEmpty(importedSymbols);
		Assert.Contains(importedSymbols, symbol => !string.IsNullOrEmpty(symbol.VersionName));
		Assert.Contains(importedSymbols, symbol => !string.IsNullOrEmpty(symbol.LibraryName));
		Assert.Contains(elf.DynamicEntries, entry => entry.TagName == "DT_GNU_HASH");
	}

	[Fact]
	public void Parse_TruncatedSample_Throws()
	{
		var source = File.ReadAllBytes(GetRequiredSample("nano"));
		var truncatedLength = Math.Min(128, source.Length);
		var truncated = source[..truncatedLength];

		Assert.ThrowsAny<Exception>(() => ElfReader.Parse(truncated));
	}

	[Fact]
	public void Parse_CorruptedMagicFromSample_Throws()
	{
		var data = (byte[])File.ReadAllBytes(GetRequiredSample("busybox")).Clone();
		data[0] = 0x00;

		Assert.ThrowsAny<Exception>(() => ElfReader.Parse(data));
	}

	[Fact]
	public void Parse_CorruptedHeaderOffsetsFromSample_Throws()
	{
		var data = (byte[])File.ReadAllBytes(GetRequiredSample("busybox")).Clone();
		CorruptHeaderOffsets(data);

		Assert.ThrowsAny<Exception>(() => ElfReader.Parse(data));
	}

	[Fact]
	public void Parse_InvalidEiVersion_StrictRejects_CompatAllows()
	{
		var data = (byte[])File.ReadAllBytes(GetRequiredSample("hello_x86_64")).Clone();
		data[6] = 0;

		Assert.ThrowsAny<Exception>(() => ElfReader.Parse(data));

		var elf = ElfReader.Parse(data, new ElfParseOptions { HeaderValidationMode = ElfHeaderValidationMode.Compat });
		Assert.Equal(ElfClass.Elf64, elf.Header.Class);
	}

	[Fact]
	public void Parse_InvalidEiPadding_StrictRejects_CompatAllows()
	{
		var data = (byte[])File.ReadAllBytes(GetRequiredSample("hello_x86_64")).Clone();
		data[9] = 0x01;

		Assert.ThrowsAny<Exception>(() => ElfReader.Parse(data));

		var elf = ElfReader.Parse(data, new ElfParseOptions { HeaderValidationMode = ElfHeaderValidationMode.Compat });
		Assert.Equal(ElfClass.Elf64, elf.Header.Class);
	}

	[Fact]
	public void Parse_InvalidHeaderVersion_StrictRejects_CompatAllows()
	{
		var data = (byte[])File.ReadAllBytes(GetRequiredSample("hello_x86_64")).Clone();
		WriteUInt32(data.AsSpan(20, 4), 0, littleEndian: data[5] == 1); // e_version

		Assert.ThrowsAny<Exception>(() => ElfReader.Parse(data));

		var elf = ElfReader.Parse(data, new ElfParseOptions { HeaderValidationMode = ElfHeaderValidationMode.Compat });
		Assert.Equal(ElfClass.Elf64, elf.Header.Class);
	}

	[Fact]
	public void Parse_InvalidHeaderSize_StrictRejects_CompatAllows()
	{
		var data = (byte[])File.ReadAllBytes(GetRequiredSample("hello_x86_64")).Clone();
		WriteUInt16(data.AsSpan(52, 2), 63, littleEndian: data[5] == 1); // e_ehsize (ELF64 expected 64)

		Assert.ThrowsAny<Exception>(() => ElfReader.Parse(data));

		var elf = ElfReader.Parse(data, new ElfParseOptions { HeaderValidationMode = ElfHeaderValidationMode.Compat });
		Assert.Equal(ElfClass.Elf64, elf.Header.Class);
	}

	[Fact]
	public void Parse_InconsistentProgramHeaderMetadata_StrictRejects_CompatAllows()
	{
		var data = (byte[])File.ReadAllBytes(GetRequiredSample("hello_x86_64")).Clone();
		var littleEndian = data[5] == 1;
		WriteUInt64(data.AsSpan(32, 8), 64, littleEndian); // e_phoff
		WriteUInt16(data.AsSpan(54, 2), 0, littleEndian); // e_phentsize
		WriteUInt16(data.AsSpan(56, 2), 1, littleEndian); // e_phnum

		Assert.ThrowsAny<Exception>(() => ElfReader.Parse(data));

		var elf = ElfReader.Parse(data, new ElfParseOptions { HeaderValidationMode = ElfHeaderValidationMode.Compat });
		Assert.Equal(ElfClass.Elf64, elf.Header.Class);
	}

	[Fact]
	public void Parse_InconsistentSectionHeaderMetadata_StrictRejects_CompatAllows()
	{
		var data = (byte[])File.ReadAllBytes(GetRequiredSample("hello_x86_64")).Clone();
		var littleEndian = data[5] == 1;
		WriteUInt64(data.AsSpan(40, 8), 64, littleEndian); // e_shoff
		WriteUInt16(data.AsSpan(58, 2), 0, littleEndian); // e_shentsize
		WriteUInt16(data.AsSpan(60, 2), 1, littleEndian); // e_shnum

		Assert.ThrowsAny<Exception>(() => ElfReader.Parse(data));

		var elf = ElfReader.Parse(data, new ElfParseOptions { HeaderValidationMode = ElfHeaderValidationMode.Compat });
		Assert.Equal(ElfClass.Elf64, elf.Header.Class);
	}

	[Fact]
	public void Parse_InvalidSectionStringIndex_StrictRejects_CompatAllows()
	{
		var data = (byte[])File.ReadAllBytes(GetRequiredSample("hello_x86_64")).Clone();
		var littleEndian = data[5] == 1;
		WriteUInt16(data.AsSpan(60, 2), 2, littleEndian); // e_shnum
		WriteUInt16(data.AsSpan(62, 2), 2, littleEndian); // e_shstrndx (out of range for shnum=2)

		Assert.ThrowsAny<Exception>(() => ElfReader.Parse(data));

		var elf = ElfReader.Parse(data, new ElfParseOptions { HeaderValidationMode = ElfHeaderValidationMode.Compat });
		Assert.Equal(ElfClass.Elf64, elf.Header.Class);
	}

	[Fact]
	public void Parse_HeaderMutationCorpus_ProducesOnlyControlledFailures()
	{
		var source = File.ReadAllBytes(GetRequiredSample("busybox"));
		var rng = new Random(1337);
		var controlled = new[]
		{
			typeof(InvalidDataException),
			typeof(NotSupportedException),
			typeof(OverflowException),
			typeof(ArgumentException)
		};

		for (var i = 0; i < 128; i++)
		{
			var mutated = (byte[])source.Clone();
			var mutations = 1 + (i % 6);
			for (var j = 0; j < mutations; j++)
			{
				var offset = rng.Next(0, Math.Min(128, mutated.Length));
				mutated[offset] ^= (byte)(1 << rng.Next(0, 8));
			}

			try
			{
				_ = ElfReader.Parse(mutated);
			}
			catch (Exception ex)
			{
				Assert.Contains(controlled, type => type.IsAssignableFrom(ex.GetType()));
			}
		}
	}

	[Fact]
	public void ExampleUsage_ReturnsErrorCode_ForMalformedElf()
	{
		var source = File.ReadAllBytes(GetRequiredSample("nano"));
		var malformed = source[..Math.Min(96, source.Length)];

		var tempDirectory = Path.Combine(Path.GetTempPath(), $"elf-inspector-tests-{Guid.NewGuid():N}");
		Directory.CreateDirectory(tempDirectory);

		try
		{
			var malformedFile = Path.Combine(tempDirectory, "malformed.bin");
			File.WriteAllBytes(malformedFile, malformed);

			var exitCode = ExampleUsage.RunWithArgs(new[]
			{
				"--file", malformedFile,
				"--output", "report.txt",
				"--output-path", tempDirectory,
				"--deterministic"
			});

			Assert.Equal(1, exitCode);
		}
		finally
		{
			Directory.Delete(tempDirectory, recursive: true);
		}
	}

	[Fact]
	public void ExampleUsage_CompatHeaderValidation_AllowsLegacyHeaderVariants()
	{
		var source = (byte[])File.ReadAllBytes(GetRequiredSample("hello_x86_64")).Clone();
		source[6] = 0; // EI_VERSION

		var tempDirectory = Path.Combine(Path.GetTempPath(), $"elf-inspector-tests-{Guid.NewGuid():N}");
		Directory.CreateDirectory(tempDirectory);

		try
		{
			var legacyFile = Path.Combine(tempDirectory, "legacy.bin");
			File.WriteAllBytes(legacyFile, source);

			var exitCode = ExampleUsage.RunWithArgs(new[]
			{
				"--file", legacyFile,
				"--output", "report.txt",
				"--output-path", tempDirectory,
				"--deterministic",
				"--compat-header-validation"
			});

			Assert.Equal(0, exitCode);
			Assert.True(File.Exists(Path.Combine(tempDirectory, "report.txt")));
		}
		finally
		{
			Directory.Delete(tempDirectory, recursive: true);
		}
	}

	private static IReadOnlyList<string> GetSampleElfFiles()
	{
		var sampleDirectory = GetSamplesDirectory();
		return Directory.GetFiles(sampleDirectory, "*", SearchOption.TopDirectoryOnly)
			.Where(IsElfFile)
			.OrderBy(path => path, StringComparer.Ordinal)
			.ToList();
	}

	private static string GetRequiredSample(string fileName)
	{
		var path = Path.Combine(GetSamplesDirectory(), fileName);
		if (!File.Exists(path))
			throw new InvalidOperationException($"Missing sample file: {path}");

		return path;
	}

	private static void AssertRelocationTypeName(string sampleFileName, string expectedTypeName)
	{
		var elf = ElfReader.Parse(File.ReadAllBytes(GetRequiredSample(sampleFileName)));
		Assert.Contains(elf.Relocations, relocation => string.Equals(relocation.TypeName, expectedTypeName, StringComparison.Ordinal));
		Assert.DoesNotContain(elf.Relocations, relocation => relocation.Type != 0 && relocation.TypeName.StartsWith("REL_", StringComparison.Ordinal));
	}

	private static string InvokeRelocationTypeName(ushort machine, uint type)
	{
		var method = typeof(ElfReader).GetMethod("GetRelocationTypeName", BindingFlags.Static | BindingFlags.NonPublic);
		Assert.NotNull(method);
		var value = method!.Invoke(null, new object[] { machine, type });
		return Assert.IsType<string>(value);
	}

	private static string InvokeReaderString(string methodName, object value)
	{
		var method = typeof(ElfReader).GetMethod(methodName, BindingFlags.Static | BindingFlags.NonPublic);
		Assert.NotNull(method);
		var result = method!.Invoke(null, new[] { value });
		return Assert.IsType<string>(result);
	}

	private static string InvokeReportMapperString(string methodName, object value)
	{
		var method = typeof(ElfReportMapper).GetMethod(methodName, BindingFlags.Static | BindingFlags.NonPublic);
		Assert.NotNull(method);
		var result = method!.Invoke(null, new[] { value });
		return Assert.IsType<string>(result);
	}

	private static ElfFile InvokeInternalParse(IEndianDataSource source, ElfParseOptions options)
	{
		var method = typeof(ElfReader).GetMethod(
			"Parse",
			BindingFlags.Static | BindingFlags.NonPublic,
			null,
			new[] { typeof(IEndianDataSource), typeof(ElfParseOptions) },
			null);
		Assert.NotNull(method);

		var result = method!.Invoke(null, new object[] { source, options });
		return Assert.IsType<ElfFile>(result);
	}

	private static byte[] BuildMinimalElf64Header()
	{
		var header = new byte[64];
		header[0] = 0x7F;
		header[1] = (byte)'E';
		header[2] = (byte)'L';
		header[3] = (byte)'F';
		header[4] = 2; // ELFCLASS64
		header[5] = 1; // little-endian
		header[6] = 1; // EI_VERSION
		header[7] = 0; // System V ABI
		header[8] = 0; // ABI version

		WriteUInt16(header.AsSpan(16, 2), 2, littleEndian: true); // e_type = ET_EXEC
		WriteUInt16(header.AsSpan(18, 2), 62, littleEndian: true); // e_machine = EM_X86_64
		WriteUInt32(header.AsSpan(20, 4), 1U, littleEndian: true); // e_version
		WriteUInt16(header.AsSpan(52, 2), 64, littleEndian: true); // e_ehsize
		WriteUInt16(header.AsSpan(54, 2), 0, littleEndian: true); // e_phentsize (no PH table)
		WriteUInt16(header.AsSpan(58, 2), 0, littleEndian: true); // e_shentsize (no SH table)
		return header;
	}

	private sealed class SparseEndianDataSource : IEndianDataSource
	{
		private readonly byte[] _prefix;

		public SparseEndianDataSource(ulong length, byte[] prefix)
		{
			Length = length;
			_prefix = prefix ?? Array.Empty<byte>();
		}

		public ulong Length { get; }

		public void ReadAt(ulong offset, Span<byte> destination)
		{
			if (offset > Length || (ulong)destination.Length > Length - offset)
				throw new InvalidDataException("Read exceeds sparse source bounds.");

			destination.Clear();
			if (offset >= (ulong)_prefix.Length || destination.Length == 0)
				return;

			var available = (ulong)_prefix.Length - offset;
			var bytesToCopy = (int)Math.Min((ulong)destination.Length, available);
			_prefix.AsSpan((int)offset, bytesToCopy).CopyTo(destination);
		}
	}

	private static bool IsRawFallbackRelocationTypeName(ushort machine, ElfRelocation relocation)
	{
		if (relocation.Type == 0)
			return false;

		var prefix = machine switch
		{
			40 => "R_ARM_",
			20 => "R_PPC_",
			21 => "R_PPC64_",
			22 => "R_390_",
			2 or 43 => "R_SPARC_",
			_ => string.Empty
		};

		if (string.IsNullOrEmpty(prefix))
			return false;

		return string.Equals(
			relocation.TypeName,
			$"{prefix}{relocation.Type}",
			StringComparison.Ordinal);
	}

	private static bool IsElfFile(string path)
	{
		var buffer = new byte[4];
		using var stream = File.OpenRead(path);
		var read = stream.Read(buffer, 0, buffer.Length);
		return read == 4 && buffer[0] == 0x7F && buffer[1] == (byte)'E' && buffer[2] == (byte)'L' && buffer[3] == (byte)'F';
	}

	private static string GetSamplesDirectory()
	{
		var repoRoot = FindRepoRoot();
		return Path.Combine(repoRoot, "samples");
	}

	private static string FindRepoRoot()
	{
		var current = new DirectoryInfo(AppContext.BaseDirectory);
		while (current != null)
		{
			if (File.Exists(Path.Combine(current.FullName, "ELF-Inspector.csproj")))
				return current.FullName;

			current = current.Parent;
		}

		throw new InvalidOperationException("Could not locate repository root.");
	}

	private static void CorruptHeaderOffsets(byte[] elfBytes)
	{
		if (elfBytes.Length < 64)
			throw new InvalidOperationException("Sample is too small to corrupt ELF offsets.");

		var elfClass = elfBytes[4];
		var isLittleEndian = elfBytes[5] == 1;

		if (elfClass == 1)
		{
			WriteUInt32(elfBytes.AsSpan(28, 4), uint.MaxValue - 0x1000, isLittleEndian); // e_phoff
			WriteUInt32(elfBytes.AsSpan(32, 4), uint.MaxValue - 0x1000, isLittleEndian); // e_shoff
			return;
		}

		if (elfClass == 2)
		{
			WriteUInt64(elfBytes.AsSpan(32, 8), ulong.MaxValue - 0x1000, isLittleEndian); // e_phoff
			WriteUInt64(elfBytes.AsSpan(40, 8), ulong.MaxValue - 0x1000, isLittleEndian); // e_shoff
			return;
		}

		throw new InvalidOperationException("Unsupported ELF class for corruption.");
	}

	private static void StripSectionHeaderTable(byte[] elfBytes)
	{
		if (elfBytes.Length < 64)
			throw new InvalidOperationException("Sample is too small to strip section headers.");

		var elfClass = elfBytes[4];
		var isLittleEndian = elfBytes[5] == 1;

		if (elfClass == 1)
		{
			WriteUInt32(elfBytes.AsSpan(32, 4), 0, isLittleEndian); // e_shoff
			WriteUInt16(elfBytes.AsSpan(46, 2), 0, isLittleEndian); // e_shentsize
			WriteUInt16(elfBytes.AsSpan(48, 2), 0, isLittleEndian); // e_shnum
			WriteUInt16(elfBytes.AsSpan(50, 2), 0, isLittleEndian); // e_shstrndx
			return;
		}

		if (elfClass == 2)
		{
			WriteUInt64(elfBytes.AsSpan(40, 8), 0, isLittleEndian); // e_shoff
			WriteUInt16(elfBytes.AsSpan(58, 2), 0, isLittleEndian); // e_shentsize
			WriteUInt16(elfBytes.AsSpan(60, 2), 0, isLittleEndian); // e_shnum
			WriteUInt16(elfBytes.AsSpan(62, 2), 0, isLittleEndian); // e_shstrndx
			return;
		}

		throw new InvalidOperationException("Unsupported ELF class for section header stripping.");
	}

	private static void ForceElfType(byte[] elfBytes, ushort type)
	{
		if (elfBytes.Length < 18)
			throw new InvalidOperationException("Sample is too small to patch ELF type.");

		var isLittleEndian = elfBytes[5] == 1;
		WriteUInt16(elfBytes.AsSpan(16, 2), type, isLittleEndian);
	}

	private static void WriteUInt32(Span<byte> target, uint value, bool littleEndian)
	{
		if (littleEndian)
			BinaryPrimitives.WriteUInt32LittleEndian(target, value);
		else
			BinaryPrimitives.WriteUInt32BigEndian(target, value);
	}

	private static void ReadPastEndWithEndianBinaryReader()
	{
		var reader = new ELFInspector.Endianness.EndianBinaryReader(new byte[] { 0x01, 0x02 }, isLittle: true);
		reader.ReadUInt32();
	}

	private static void SetInvalidEndianReaderPosition()
	{
		var reader = new ELFInspector.Endianness.EndianBinaryReader(new byte[] { 0x01, 0x02 }, isLittle: true);
		reader.Position = -1;
	}

	private static void WriteUInt16(Span<byte> target, ushort value, bool littleEndian)
	{
		if (littleEndian)
			BinaryPrimitives.WriteUInt16LittleEndian(target, value);
		else
			BinaryPrimitives.WriteUInt16BigEndian(target, value);
	}

	private static void WriteUInt32(Span<byte> target, int value, bool littleEndian)
	{
		WriteUInt32(target, unchecked((uint)value), littleEndian);
	}

	private static void WriteUInt64(Span<byte> target, ulong value, bool littleEndian)
	{
		if (littleEndian)
			BinaryPrimitives.WriteUInt64LittleEndian(target, value);
		else
			BinaryPrimitives.WriteUInt64BigEndian(target, value);
	}

	private static byte[] BuildNoteSection(params byte[][] notes)
	{
		var result = new List<byte>();
		foreach (var note in notes)
			result.AddRange(note);
		return result.ToArray();
	}

	private static byte[] BuildElfCompressedSectionPayload(ulong uncompressedSize, uint compressionType, byte[] compressedPayload, bool littleEndian, bool isElf64)
	{
		if (compressedPayload == null)
			throw new ArgumentNullException(nameof(compressedPayload));

		var header = isElf64 ? new byte[24] : new byte[12];
		WriteUInt32(header.AsSpan(0, 4), compressionType, littleEndian);
		if (isElf64)
		{
			WriteUInt32(header.AsSpan(4, 4), 0, littleEndian); // ch_reserved
			WriteUInt64(header.AsSpan(8, 8), uncompressedSize, littleEndian);
			WriteUInt64(header.AsSpan(16, 8), 1, littleEndian); // ch_addralign
		}
		else
		{
			WriteUInt32(header.AsSpan(4, 4), checked((uint)uncompressedSize), littleEndian);
			WriteUInt32(header.AsSpan(8, 4), 1, littleEndian); // ch_addralign
		}

		var result = new byte[header.Length + compressedPayload.Length];
		Buffer.BlockCopy(header, 0, result, 0, header.Length);
		Buffer.BlockCopy(compressedPayload, 0, result, header.Length, compressedPayload.Length);
		return result;
	}

	private static byte[] BuildGnuZdebugSectionPayload(string codecHeader, ulong uncompressedSize, byte[] compressedPayload)
	{
		if (codecHeader is null || codecHeader.Length != 4)
			throw new ArgumentException("GNU .zdebug codec header must be exactly 4 characters.", nameof(codecHeader));
		if (compressedPayload == null)
			throw new ArgumentNullException(nameof(compressedPayload));

		var header = new byte[12];
		Encoding.ASCII.GetBytes(codecHeader).CopyTo(header, 0);
		BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(4, 8), uncompressedSize);

		var result = new byte[header.Length + compressedPayload.Length];
		Buffer.BlockCopy(header, 0, result, 0, header.Length);
		Buffer.BlockCopy(compressedPayload, 0, result, header.Length, compressedPayload.Length);
		return result;
	}

	private static byte[] BuildZstdRawSingleSegmentFrame(byte[] payload)
	{
		if (payload == null)
			throw new ArgumentNullException(nameof(payload));
		if (payload.Length > 255)
			throw new ArgumentOutOfRangeException(nameof(payload), "Payload must fit in the single-byte ZSTD frame content size field.");
		if (payload.Length > 0x1F_FFFF)
			throw new ArgumentOutOfRangeException(nameof(payload), "Payload is too large for a single raw block header.");

		var frame = new List<byte>(payload.Length + 9);
		frame.AddRange(new byte[] { 0x28, 0xB5, 0x2F, 0xFD }); // ZSTD magic (little endian)
		frame.Add(0x20); // single_segment=1, no dict, no checksum, fcs_flag=0
		frame.Add((byte)payload.Length); // frame content size (single segment, 1-byte field)

		var blockHeader = 1U | ((uint)payload.Length << 3); // last_block=1, block_type=raw(0)
		frame.Add((byte)(blockHeader & 0xFF));
		frame.Add((byte)((blockHeader >> 8) & 0xFF));
		frame.Add((byte)((blockHeader >> 16) & 0xFF));
		frame.AddRange(payload);
		return frame.ToArray();
	}

	private static byte[] BuildZstdConcatenatedRawFrames(params byte[][] payloads)
	{
		var result = new List<byte>();
		foreach (var payload in payloads)
			result.AddRange(BuildZstdRawSingleSegmentFrame(payload));
		return result.ToArray();
	}

	private static byte[] CreateNote(string name, uint type, byte[] descriptor)
	{
		var nameBytes = Encoding.ASCII.GetBytes(name + "\0");
		var result = new List<byte>(12 + Align4(nameBytes.Length) + Align4(descriptor.Length));

		var header = new byte[12];
		BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(0, 4), (uint)nameBytes.Length);
		BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(4, 4), (uint)descriptor.Length);
		BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8, 4), type);
		result.AddRange(header);

		result.AddRange(nameBytes);
		for (var i = nameBytes.Length; i < Align4(nameBytes.Length); i++)
			result.Add(0);

		result.AddRange(descriptor);
		for (var i = descriptor.Length; i < Align4(descriptor.Length); i++)
			result.Add(0);

		return result.ToArray();
	}

	private static int Align4(int value)
	{
		return (value + 3) & ~3;
	}
}
