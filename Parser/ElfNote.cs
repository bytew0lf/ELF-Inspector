namespace ELFInspector.Parser;

public class ElfNote
{
	public string Name { get; set; }
	public uint Type { get; set; }
	public string TypeName { get; set; }
	public byte[] Descriptor { get; set; }
	public string DecodedDescription { get; set; }
}

public static partial class ElfReader
{
	private const uint NtGnuAbiTag = 1;
	private const uint NtGnuHwcap = 2;
	private const uint NtGnuBuildId = 3;
	private const uint NtGnuGoldVersion = 4;
	private const uint NtGnuPropertyType0 = 5;
	private const uint NtGnuBuildAttributeOpen = 0x100;
	private const uint NtGnuBuildAttributeFunc = 0x101;
	private const uint NtFdoPackagingMetadata = 0xCAFE1A7E;
	private const uint NtGoBuildId = 4;
	private const uint NtStapSdt = 3;
	private const uint NtFreeBsdAbiTag = 1;
	private const uint NtFreeBsdNocopyOnProtected = 2;
	private const uint NtNetBsdIdent = 1;
	private const uint NtOpenBsdIdent = 1;
	private const uint NtAndroidAbi = 1;
	private const uint NtAndroidMemtagLevelAsync = 0x100;
	private const uint NtAndroidMemtagLevelSync = 0x101;
	private const uint NtXenElfNoteEntry = 1;
	private const uint NtXenElfNoteHypercallPage = 2;
	private const uint NtXenElfNoteVirtBase = 3;
	private const uint NtXenElfNotePaddrOffset = 4;
	private const uint NtXenElfNoteXenVersion = 5;
	private const uint NtXenElfNoteGuestOs = 6;
	private const uint NtXenElfNoteGuestVersion = 7;
	private const uint NtXenElfNoteLoader = 8;
	private const uint NtXenElfNotePaeMode = 9;
	private const uint NtXenElfNoteFeatures = 10;
	private const uint NtXenElfNoteBsdSymtab = 11;
	private const uint NtXenElfNoteHpet = 12;
	private const uint NtXenElfNoteSuspendCancel = 14;
	private const uint NtXenElfNoteModStartPfn = 15;
	private const uint NtXenElfNotePhys32Entry = 18;
	private const uint NtCoreFpRegSet = 2;
	private const uint NtCorePpcVmx = 0x100;
	private const uint NtCorePpcSpe = 0x101;
	private const uint NtCorePpcVsx = 0x102;
	private const uint NtCorePrXfpReg = 0x46E62B7F;
	private const uint NtCore386Tls = 0x200;
	private const uint NtCore386Ioperm = 0x201;
	private const uint NtCoreX86Xstate = 0x202;
	private const uint NtCoreX86Cet = 0x203;
	private const uint NtCoreS390HighGprs = 0x300;
	private const uint NtCoreS390Timer = 0x301;
	private const uint NtCoreS390TodCmp = 0x302;
	private const uint NtCoreS390TodPreg = 0x303;
	private const uint NtCoreS390Ctrs = 0x304;
	private const uint NtCoreS390Prefix = 0x305;
	private const uint NtCoreS390LastBreak = 0x306;
	private const uint NtCoreS390SystemCall = 0x307;
	private const uint NtCoreS390Tdb = 0x308;
	private const uint NtCoreS390VxrsLow = 0x309;
	private const uint NtCoreS390VxrsHigh = 0x30A;
	private const uint NtCoreS390GuardedStorage = 0x30B;
	private const uint NtCoreS390RuntimeInstr = 0x30C;
	private const uint NtCoreS390VxrsExt = 0x30D;
	private const uint NtCoreArmVfp = 0x400;
	private const uint NtCoreArmTls = 0x401;
	private const uint NtCoreArmHwBreakpoint = 0x402;
	private const uint NtCoreArmHwWatchpoint = 0x403;
	private const uint NtCoreArmSystemCall = 0x404;
	private const uint NtCoreArmSve = 0x405;
	private const uint NtCoreArmPacMask = 0x406;
	private const uint NtCoreArmPacAKeys = 0x407;
	private const uint NtCoreArmPacGKeys = 0x408;
	private const uint NtCoreArmTaggedAddrCtrl = 0x409;
	private const uint NtCoreArmPacEnabledKeys = 0x40A;
	private const uint NtCoreArmSsve = 0x40B;
	private const uint NtCoreArmZa = 0x40C;
	private const uint NtCoreArmZt = 0x40D;
	private const uint NtCoreArmFpmr = 0x40E;
	private const uint NtCorePpcTmCgpr = 0x108;
	private const uint NtCorePpcTmCfpr = 0x109;
	private const uint NtCorePpcTmCvmx = 0x10A;
	private const uint NtCorePpcTmCvsx = 0x10B;
	private const uint NtCorePpcTmSpr = 0x10C;
	private const uint NtCorePpcTmCtar = 0x10D;
	private const uint NtCorePpcTmCppr = 0x10E;
	private const uint NtCorePpcTmCdscr = 0x10F;
	private const uint NtCorePpcPkey = 0x110;
	private const uint NtCorePpcDexcr = 0x111;
	private const uint NtCorePpcHashkeyr = 0x112;
	private const uint GnuPropertyAArch64Feature1And = 0xC0000000;
	private const uint GnuPropertyX86Feature1And = 0xC0000002;
	private const uint GnuPropertyX86Isa1Needed = 0xC0008002;
	private const uint GnuPropertyX86Isa1Used = 0xC0010002;
	private const uint GnuPropertyStackSize = 0xA0000000;
	private const uint GnuPropertyNoCopyOnProtected = 0xA0000001;
	private const ulong AuxvAtNull = 0;
	private const ulong MaxNoteNameBytes = 1UL * 1024UL * 1024UL;
	private const ulong MaxNoteDescriptorBytes = 64UL * 1024UL * 1024UL;
	private const ulong NotePreviewBytes = 64UL;

	public static void ParseNotes(IEndianDataSource data, ElfFile elf)
	{
		elf.Notes.Clear();
		var dedupeKeys = new HashSet<string>(StringComparer.Ordinal);

		foreach (var section in elf.Sections)
		{
			if (section.Type != ShtNote)
				continue;

			ParseNoteSection(data, elf, section, dedupeKeys);
		}

		ParseNoteProgramHeaders(data, elf, dedupeKeys);
	}

	public static void ParseNotes(ReadOnlySpan<byte> data, ElfFile elf)
	{
		using var source = ElfDataSourceFactory.CreateInMemory(data);
		ParseNotes(source, elf);
	}

	private static void ParseNoteSection(IEndianDataSource data, ElfFile elf, ElfSectionHeader section, HashSet<string> dedupeKeys)
	{
		if (section.Size == 0)
			return;

		EnsureReadableRange(data, section.Offset, section.Size, "NOTE section");

		var sectionStart = section.Offset;
		var sectionEnd = checked(section.Offset + section.Size);
		var align = section.AddressAlign;
		if (align == 0 || (align & (align - 1)) != 0 || align > 8)
			align = 4;

		ParseNoteBlock(data, elf, sectionStart, sectionEnd, align, dedupeKeys);
	}

	private static void ParseNoteProgramHeaders(IEndianDataSource data, ElfFile elf, HashSet<string> dedupeKeys)
	{
		foreach (var programHeader in elf.ProgramHeaders)
		{
			if (programHeader.Type != PtNote || programHeader.FileSize == 0)
				continue;

			EnsureReadableRange(data, programHeader.Offset, programHeader.FileSize, "PT_NOTE");
			var start = programHeader.Offset;
			var end = checked(programHeader.Offset + programHeader.FileSize);
			ParseNoteBlock(data, elf, start, end, 4, dedupeKeys);
		}
	}

	private static void ParseNoteBlock(IEndianDataSource data, ElfFile elf, ulong start, ulong end, ulong align, HashSet<string> dedupeKeys)
	{
		var cursor = start;

		while (cursor + 12 <= end)
		{
			var reader = new EndianDataReader(data, elf.Header.IsLittleEndian)
			{
				Position = cursor
			};

			var nameSize = reader.ReadUInt32();
			var descSize = reader.ReadUInt32();
			var type = reader.ReadUInt32();
			cursor += 12;

			if (cursor + nameSize > end)
				throw new InvalidDataException("Invalid NOTE name size.");

			var name = ReadNoteName(data, cursor, nameSize);
			cursor = AlignUp(cursor + nameSize, align);

			if (cursor + descSize > end)
				throw new InvalidDataException("Invalid NOTE descriptor size.");

			var descriptor = ReadNoteDescriptor(data, cursor, descSize, out var descriptorDecodeOverride);
			cursor = AlignUp(cursor + descSize, align);

			var note = new ElfNote
			{
				Name = name,
				Type = type,
				TypeName = GetNoteTypeName(name, type),
				Descriptor = descriptor,
				DecodedDescription = string.IsNullOrEmpty(descriptorDecodeOverride)
					? DecodeNoteDescriptor(elf.Header, name, type, descriptor)
					: descriptorDecodeOverride
			};
			AddNoteDeduplicated(elf, note, dedupeKeys);
		}
	}

	private static string ReadNoteName(IEndianDataSource data, ulong offset, ulong nameSize)
	{
		if (nameSize == 0)
			return string.Empty;

		var nameBytesToRead = Math.Min(nameSize, MaxNoteNameBytes);
		var rawName = Encoding.ASCII.GetString(ReadBytes(data, offset, nameBytesToRead, "NOTE name"));
		var normalizedName = NormalizeNoteNamespace(rawName.TrimEnd('\0'));

		if (!string.IsNullOrEmpty(normalizedName))
			return normalizedName;
		if (nameSize > MaxNoteNameBytes)
			return $"NOTE_NAME_OVERSIZE_{nameSize}";

		return string.Empty;
	}

	private static byte[] ReadNoteDescriptor(IEndianDataSource data, ulong offset, ulong descSize, out string decodeOverride)
	{
		decodeOverride = string.Empty;
		if (descSize == 0)
			return Array.Empty<byte>();

		if (descSize <= MaxNoteDescriptorBytes)
			return ReadBytes(data, offset, descSize, "NOTE descriptor");

		var previewLength = Math.Min(NotePreviewBytes, descSize);
		var preview = ReadBytes(data, offset, previewLength, "NOTE descriptor preview");
		decodeOverride = $"descriptor truncated: bytes={descSize}, preview=0x{Convert.ToHexString(preview)}";
		return preview;
	}

	private static void AddNoteDeduplicated(ElfFile elf, ElfNote note, HashSet<string> dedupeKeys)
	{
		var key = string.Concat(note.Name, "\0", note.Type.ToString(), "\0", Convert.ToHexString(note.Descriptor));
		if (dedupeKeys.Add(key))
			elf.Notes.Add(note);
	}

	private static string GetCoreNoteTypeName(uint type)
	{
		return type switch
		{
			NtCorePrStatus => "NT_PRSTATUS",
			NtCoreFpRegSet => "NT_FPREGSET",
			NtCorePrPsInfo => "NT_PRPSINFO",
			4 => "NT_TASKSTRUCT",
			NtCoreAuxv => "NT_AUXV",
			NtCoreFile => "NT_FILE",
			NtCoreSigInfo => "NT_SIGINFO",
			NtCorePrXfpReg => "NT_PRXFPREG",
				NtCorePpcVmx => "NT_PPC_VMX",
				NtCorePpcSpe => "NT_PPC_SPE",
				NtCorePpcVsx => "NT_PPC_VSX",
				NtCorePpcTmCgpr => "NT_PPC_TM_CGPR",
				NtCorePpcTmCfpr => "NT_PPC_TM_CFPR",
				NtCorePpcTmCvmx => "NT_PPC_TM_CVMX",
				NtCorePpcTmCvsx => "NT_PPC_TM_CVSX",
				NtCorePpcTmSpr => "NT_PPC_TM_SPR",
				NtCorePpcTmCtar => "NT_PPC_TM_CTAR",
				NtCorePpcTmCppr => "NT_PPC_TM_CPPR",
				NtCorePpcTmCdscr => "NT_PPC_TM_CDSCR",
				NtCorePpcPkey => "NT_PPC_PKEY",
				NtCorePpcDexcr => "NT_PPC_DEXCR",
				NtCorePpcHashkeyr => "NT_PPC_HASHKEYR",
				NtCore386Tls => "NT_386_TLS",
				NtCore386Ioperm => "NT_386_IOPERM",
				NtCoreX86Xstate => "NT_X86_XSTATE",
				NtCoreX86Cet => "NT_X86_CET",
			NtCoreS390HighGprs => "NT_S390_HIGH_GPRS",
			NtCoreS390Timer => "NT_S390_TIMER",
			NtCoreS390TodCmp => "NT_S390_TODCMP",
			NtCoreS390TodPreg => "NT_S390_TODPREG",
			NtCoreS390Ctrs => "NT_S390_CTRS",
			NtCoreS390Prefix => "NT_S390_PREFIX",
			NtCoreS390LastBreak => "NT_S390_LAST_BREAK",
			NtCoreS390SystemCall => "NT_S390_SYSTEM_CALL",
			NtCoreS390Tdb => "NT_S390_TDB",
			NtCoreS390VxrsLow => "NT_S390_VXRS_LOW",
			NtCoreS390VxrsHigh => "NT_S390_VXRS_HIGH",
			NtCoreS390GuardedStorage => "NT_S390_GS_CB",
			NtCoreS390RuntimeInstr => "NT_S390_RI_CB",
			NtCoreS390VxrsExt => "NT_S390_VXRS_EXT",
			NtCoreArmVfp => "NT_ARM_VFP",
			NtCoreArmTls => "NT_ARM_TLS",
			NtCoreArmHwBreakpoint => "NT_ARM_HW_BREAK",
			NtCoreArmHwWatchpoint => "NT_ARM_HW_WATCH",
			NtCoreArmSystemCall => "NT_ARM_SYSTEM_CALL",
			NtCoreArmSve => "NT_ARM_SVE",
			NtCoreArmPacMask => "NT_ARM_PAC_MASK",
			NtCoreArmPacAKeys => "NT_ARM_PACA_KEYS",
			NtCoreArmPacGKeys => "NT_ARM_PACG_KEYS",
			NtCoreArmTaggedAddrCtrl => "NT_ARM_TAGGED_ADDR_CTRL",
			NtCoreArmPacEnabledKeys => "NT_ARM_PAC_ENABLED_KEYS",
			NtCoreArmSsve => "NT_ARM_SSVE",
			NtCoreArmZa => "NT_ARM_ZA",
			NtCoreArmZt => "NT_ARM_ZT",
				NtCoreArmFpmr => "NT_ARM_FPMR",
				_ => string.Empty
			};
		}

	private static bool IsKnownCoreNoteType(uint type)
	{
		return !string.IsNullOrEmpty(GetCoreNoteTypeName(type));
	}

	private static string GetNoteTypeName(string name, uint type)
	{
		if (name == "GNU")
		{
			return type switch
			{
				NtGnuAbiTag => "NT_GNU_ABI_TAG",
				NtGnuHwcap => "NT_GNU_HWCAP",
				NtGnuBuildId => "NT_GNU_BUILD_ID",
				NtGnuGoldVersion => "NT_GNU_GOLD_VERSION",
				NtGnuPropertyType0 => "NT_GNU_PROPERTY_TYPE_0",
				NtGnuBuildAttributeOpen => "NT_GNU_BUILD_ATTRIBUTE_OPEN",
				NtGnuBuildAttributeFunc => "NT_GNU_BUILD_ATTRIBUTE_FUNC",
				_ => $"NT_GNU_0x{type:X}"
			};
		}

		if (name == "FDO")
		{
			return type switch
			{
				NtFdoPackagingMetadata => "NT_FDO_PACKAGING_METADATA",
				_ => $"NT_FDO_0x{type:X}"
			};
		}

		if (name == "Go")
		{
			return type switch
			{
				NtGoBuildId => "NT_GO_BUILD_ID",
				_ => $"NT_GO_0x{type:X}"
			};
		}

		if (name == "stapsdt")
		{
			return type switch
			{
				NtStapSdt => "NT_STAPSDT",
				_ => $"NT_STAPSDT_0x{type:X}"
			};
		}

		if (name == "FreeBSD")
		{
			return type switch
			{
				NtFreeBsdAbiTag => "NT_FREEBSD_ABI_TAG",
				NtFreeBsdNocopyOnProtected => "NT_FREEBSD_NOCOPY_ON_PROTECTED",
				_ => $"NT_FREEBSD_0x{type:X}"
			};
		}

		if (name == "NetBSD")
		{
			return type switch
			{
				NtNetBsdIdent => "NT_NETBSD_IDENT",
				_ => $"NT_NETBSD_0x{type:X}"
			};
		}

		if (name == "OpenBSD")
		{
			return type switch
			{
				NtOpenBsdIdent => "NT_OPENBSD_IDENT",
				_ => $"NT_OPENBSD_0x{type:X}"
			};
		}

		if (name == "Android")
		{
			return type switch
			{
				NtAndroidAbi => "NT_ANDROID_ABI",
				NtAndroidMemtagLevelAsync => "NT_ANDROID_MEMTAG_LEVEL_ASYNC",
				NtAndroidMemtagLevelSync => "NT_ANDROID_MEMTAG_LEVEL_SYNC",
				_ => $"NT_ANDROID_0x{type:X}"
			};
		}

		if (name == "Xen")
		{
			return type switch
			{
				NtXenElfNoteEntry => "NT_XEN_ELFNOTE_ENTRY",
				NtXenElfNoteHypercallPage => "NT_XEN_ELFNOTE_HYPERCALL_PAGE",
				NtXenElfNoteVirtBase => "NT_XEN_ELFNOTE_VIRT_BASE",
				NtXenElfNotePaddrOffset => "NT_XEN_ELFNOTE_PADDR_OFFSET",
				NtXenElfNoteXenVersion => "NT_XEN_ELFNOTE_XEN_VERSION",
				NtXenElfNoteGuestOs => "NT_XEN_ELFNOTE_GUEST_OS",
				NtXenElfNoteGuestVersion => "NT_XEN_ELFNOTE_GUEST_VERSION",
				NtXenElfNoteLoader => "NT_XEN_ELFNOTE_LOADER",
				NtXenElfNotePaeMode => "NT_XEN_ELFNOTE_PAE_MODE",
				NtXenElfNoteFeatures => "NT_XEN_ELFNOTE_FEATURES",
				NtXenElfNoteBsdSymtab => "NT_XEN_ELFNOTE_BSD_SYMTAB",
				NtXenElfNoteHpet => "NT_XEN_ELFNOTE_HPET",
				NtXenElfNoteSuspendCancel => "NT_XEN_ELFNOTE_SUSPEND_CANCEL",
				NtXenElfNoteModStartPfn => "NT_XEN_ELFNOTE_MOD_START_PFN",
				NtXenElfNotePhys32Entry => "NT_XEN_ELFNOTE_PHYS32_ENTRY",
				_ => $"NT_XEN_0x{type:X}"
			};
		}

		if (name == "LINUX")
		{
			var linuxCoreName = GetCoreNoteTypeName(type);
			if (!string.IsNullOrEmpty(linuxCoreName))
				return linuxCoreName;
			var linuxArchSpecific = FormatUnknownCoreNoteTypeName(type, includeCoreFallback: false);
			if (!string.IsNullOrEmpty(linuxArchSpecific))
				return linuxArchSpecific;

			return type switch
			{
				NtStapSdt => "NT_STAPSDT",
				_ => $"NT_LINUX_0x{type:X}"
			};
		}

		if (IsCoreNoteNamespace(name))
		{
			var coreName = GetCoreNoteTypeName(type);
			return string.IsNullOrEmpty(coreName) ? FormatUnknownCoreNoteTypeName(type, includeCoreFallback: true) : coreName;
		}

		return FormatUnknownNoteTypeName(name, type);
	}

	private static string DecodeNoteDescriptor(ElfHeader header, string name, uint type, byte[] descriptor)
	{
		if (descriptor.Length == 0)
			return string.Empty;

		if (name == "GNU" && type == NtGnuBuildId)
			return Convert.ToHexString(descriptor).ToLowerInvariant();

		if (name == "GNU" && type == NtGnuAbiTag)
			return DecodeGnuAbiTag(header.IsLittleEndian, descriptor);

		if (name == "GNU" && type == NtGnuHwcap)
			return DecodeGnuHwcap(header.IsLittleEndian, descriptor);

		if (name == "GNU" && type == NtGnuGoldVersion)
			return DecodeAsciiDescriptor(descriptor);

		if (name == "GNU" && type == NtGnuPropertyType0)
			return DecodeGnuPropertyNote(header.IsLittleEndian, descriptor);

		if (name == "GNU" && (type == NtGnuBuildAttributeOpen || type == NtGnuBuildAttributeFunc))
			return DecodeAsciiDescriptor(descriptor);

		if (name == "FDO" && type == NtFdoPackagingMetadata)
			return DecodeAsciiDescriptor(descriptor);

		if (name == "Go" && type == NtGoBuildId)
			return DecodeAsciiDescriptor(descriptor);

		if (name == "FreeBSD")
			return DecodeBsdNoteDescriptor("FreeBSD", type, descriptor, header.IsLittleEndian);

		if (name == "NetBSD")
			return DecodeBsdNoteDescriptor("NetBSD", type, descriptor, header.IsLittleEndian);

		if (name == "OpenBSD")
			return DecodeBsdNoteDescriptor("OpenBSD", type, descriptor, header.IsLittleEndian);

		if (name == "Android")
			return DecodeAndroidNoteDescriptor(type, descriptor, header.IsLittleEndian);

		if (name == "Xen")
			return DecodeXenNoteDescriptor(type, descriptor, header.IsLittleEndian);

		if (name == "LINUX")
		{
			if (IsKnownCoreNoteType(type))
				return DecodeCoreNoteDescriptor(header, type, descriptor);
			if (type == NtStapSdt)
				return DecodeStapSdtDescriptor(header, descriptor);

			return DecodeLinuxNoteDescriptor(type, descriptor, header.IsLittleEndian);
		}

		if (name == "stapsdt" && type == NtStapSdt)
			return DecodeStapSdtDescriptor(header, descriptor);

		if (IsCoreNoteNamespace(name))
			return DecodeCoreNoteDescriptor(header, type, descriptor);

		return DecodeUnknownNoteDescriptor(descriptor, header.IsLittleEndian);
	}

	private static string NormalizeNoteNamespace(string name)
	{
		if (string.IsNullOrWhiteSpace(name))
			return string.Empty;

		if (string.Equals(name, "GNU", StringComparison.OrdinalIgnoreCase))
			return "GNU";
		if (string.Equals(name, "FDO", StringComparison.OrdinalIgnoreCase))
			return "FDO";
		if (string.Equals(name, "Go", StringComparison.OrdinalIgnoreCase))
			return "Go";
		if (string.Equals(name, "stapsdt", StringComparison.OrdinalIgnoreCase))
			return "stapsdt";
		if (string.Equals(name, "FreeBSD", StringComparison.OrdinalIgnoreCase))
			return "FreeBSD";
		if (string.Equals(name, "NetBSD", StringComparison.OrdinalIgnoreCase))
			return "NetBSD";
		if (string.Equals(name, "OpenBSD", StringComparison.OrdinalIgnoreCase))
			return "OpenBSD";
		if (string.Equals(name, "Android", StringComparison.OrdinalIgnoreCase))
			return "Android";
		if (string.Equals(name, "Xen", StringComparison.OrdinalIgnoreCase))
			return "Xen";
		if (string.Equals(name, "LINUX", StringComparison.OrdinalIgnoreCase))
			return "LINUX";
		if (string.Equals(name, "CORE", StringComparison.OrdinalIgnoreCase))
			return "CORE";

		return name;
	}

	private static string FormatUnknownNoteTypeName(string name, uint type)
	{
		if (string.IsNullOrWhiteSpace(name))
			return $"NOTE_0x{type:X}";

		var sanitizedNamespace = new string(name
			.Select(c => char.IsLetterOrDigit(c) ? char.ToUpperInvariant(c) : '_')
			.ToArray())
			.Trim('_');
		if (string.IsNullOrEmpty(sanitizedNamespace))
			return $"NOTE_0x{type:X}";

		return $"NT_{sanitizedNamespace}_0x{type:X}";
	}

	private static string FormatUnknownCoreNoteTypeName(uint type, bool includeCoreFallback)
	{
		if (type >= 0x100 && type <= 0x1FF)
			return $"NT_PPC_0x{type:X}";
		if (type >= 0x200 && type <= 0x2FF)
			return $"NT_X86_0x{type:X}";
		if (type >= 0x300 && type <= 0x3FF)
			return $"NT_S390_0x{type:X}";
		if (type >= 0x400 && type <= 0x4FF)
			return $"NT_ARM_0x{type:X}";

		return includeCoreFallback ? $"NT_CORE_0x{type:X}" : string.Empty;
	}

	private static string DecodeUnknownNoteDescriptor(byte[] descriptor, bool isLittleEndian)
	{
		if (descriptor.Length == 0)
			return string.Empty;

		if (descriptor.Length == 16)
		{
			return $"uuid={FormatUuid(descriptor)}";
		}

		if (descriptor.Length == 4)
		{
			var value = isLittleEndian
				? BinaryPrimitives.ReadUInt32LittleEndian(descriptor)
				: BinaryPrimitives.ReadUInt32BigEndian(descriptor);
			return $"u32={value} (0x{value:X})";
		}

		if (descriptor.Length == 8)
		{
			var value = isLittleEndian
				? BinaryPrimitives.ReadUInt64LittleEndian(descriptor)
				: BinaryPrimitives.ReadUInt64BigEndian(descriptor);
			return $"u64={value} (0x{value:X})";
		}

		var ascii = DecodeAsciiDescriptor(descriptor);
		if (!string.IsNullOrEmpty(ascii) && !ascii.StartsWith("bytes=", StringComparison.Ordinal))
			return ascii;

		var previewLength = Math.Min(descriptor.Length, 16);
		var preview = Convert.ToHexString(descriptor.AsSpan(0, previewLength));
		return descriptor.Length > previewLength
			? $"bytes={descriptor.Length}, preview=0x{preview}..."
			: $"bytes={descriptor.Length}, preview=0x{preview}";
	}

	private static string FormatUuid(byte[] value)
	{
		if (value == null || value.Length != 16)
			return string.Empty;

		return $"{Convert.ToHexString(value.AsSpan(0, 4)).ToLowerInvariant()}-"
			+ $"{Convert.ToHexString(value.AsSpan(4, 2)).ToLowerInvariant()}-"
			+ $"{Convert.ToHexString(value.AsSpan(6, 2)).ToLowerInvariant()}-"
			+ $"{Convert.ToHexString(value.AsSpan(8, 2)).ToLowerInvariant()}-"
			+ $"{Convert.ToHexString(value.AsSpan(10, 6)).ToLowerInvariant()}";
	}

	private static string DecodeXenNoteDescriptor(uint type, byte[] descriptor, bool isLittleEndian)
	{
		switch (type)
		{
			case NtXenElfNoteXenVersion:
			case NtXenElfNoteGuestOs:
			case NtXenElfNoteGuestVersion:
			case NtXenElfNoteLoader:
			case NtXenElfNotePaeMode:
			case NtXenElfNoteFeatures:
			{
				var ascii = DecodeAsciiDescriptor(descriptor);
				return string.IsNullOrEmpty(ascii) ? DecodeUnknownNoteDescriptor(descriptor, isLittleEndian) : ascii;
			}
			case NtXenElfNoteEntry:
			case NtXenElfNoteHypercallPage:
			case NtXenElfNoteVirtBase:
			case NtXenElfNotePaddrOffset:
			case NtXenElfNoteBsdSymtab:
			case NtXenElfNoteHpet:
			case NtXenElfNoteSuspendCancel:
			case NtXenElfNoteModStartPfn:
			case NtXenElfNotePhys32Entry:
			{
				if (descriptor.Length >= 8)
				{
					var value = isLittleEndian
						? BinaryPrimitives.ReadUInt64LittleEndian(descriptor.AsSpan(0, 8))
						: BinaryPrimitives.ReadUInt64BigEndian(descriptor.AsSpan(0, 8));
					return $"0x{value:X}";
				}

				if (descriptor.Length >= 4)
				{
					var value = isLittleEndian
						? BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(0, 4))
						: BinaryPrimitives.ReadUInt32BigEndian(descriptor.AsSpan(0, 4));
					return $"0x{value:X}";
				}

				return DecodeUnknownNoteDescriptor(descriptor, isLittleEndian);
			}
			default:
				return DecodeUnknownNoteDescriptor(descriptor, isLittleEndian);
		}
	}

	private static string DecodeCoreNoteDescriptor(ElfHeader header, uint type, byte[] descriptor)
	{
		if (type == NtCorePrStatus)
		{
			var span = descriptor.AsSpan();
			var signal = TryReadCoreInt32At(span, 0, header.IsLittleEndian);
			var currentSignal = TryReadCoreUInt16At(span, 12, header.IsLittleEndian);

			var details = new List<string>();
			if (signal.HasValue)
				details.Add($"signal={signal.Value}");
			if (currentSignal.HasValue)
				details.Add($"cursig={currentSignal.Value}");
			var wordSize = GetCoreWordSize(header);
			if (TryGetCorePrStatusLayout(header, descriptor.Length, wordSize, out var layout))
			{
				var tid = TryReadCoreInt32At(span, layout.ThreadIdOffset, header.IsLittleEndian);
				if (tid.HasValue)
					details.Add($"tid={tid.Value}");
				details.Add($"regs={layout.RegisterCount}");
			}
			else
			{
				var tid = TryReadFirstPlausibleCoreInt32(span, header.IsLittleEndian, 24, 28, 32, 48, 72, 80);
				if (tid.HasValue)
					details.Add($"tid={tid.Value}");
			}

			if (details.Count == 0)
				return string.Empty;

			return string.Join(", ", details);
		}

		if (type == NtCorePrPsInfo)
		{
			var processName = ExtractCoreProcessName(descriptor, header);
			return string.IsNullOrEmpty(processName) ? string.Empty : $"process={processName}";
		}

		if (type == NtCoreAuxv)
			return DecodeCoreAuxvDescriptor(header, descriptor);

		if (type == NtCoreFile)
			return DecodeCoreFileDescriptor(header, descriptor);

		if (type == NtCoreSigInfo)
		{
			var signal = TryReadCoreInt32At(descriptor.AsSpan(), 0, header.IsLittleEndian);
			var code = TryReadCoreInt32At(descriptor.AsSpan(), 4, header.IsLittleEndian);
			var error = TryReadCoreInt32At(descriptor.AsSpan(), 8, header.IsLittleEndian);
			var details = new List<string>();
			if (signal.HasValue)
				details.Add($"signal={signal.Value}");
			if (code.HasValue)
				details.Add($"code={code.Value}");
			if (error.HasValue)
				details.Add($"errno={error.Value}");
			return details.Count == 0 ? string.Empty : string.Join(", ", details);
		}

		return type switch
		{
			NtCoreFpRegSet => DecodeCoreRegisterSetDescriptor("fpregset", descriptor),
			NtCorePrXfpReg => DecodeCoreRegisterSetDescriptor("x86_prxfpreg", descriptor),
				NtCorePpcVmx => DecodeCoreRegisterSetDescriptor("ppc_vmx", descriptor),
				NtCorePpcSpe => DecodeCoreRegisterSetDescriptor("ppc_spe", descriptor),
				NtCorePpcVsx => DecodeCoreRegisterSetDescriptor("ppc_vsx", descriptor),
				NtCorePpcTmCgpr => DecodeCoreRegisterSetDescriptor("ppc_tm_cgpr", descriptor),
				NtCorePpcTmCfpr => DecodeCoreRegisterSetDescriptor("ppc_tm_cfpr", descriptor),
				NtCorePpcTmCvmx => DecodeCoreRegisterSetDescriptor("ppc_tm_cvmx", descriptor),
				NtCorePpcTmCvsx => DecodeCoreRegisterSetDescriptor("ppc_tm_cvsx", descriptor),
				NtCorePpcTmSpr => DecodeCoreRegisterSetDescriptor("ppc_tm_spr", descriptor),
				NtCorePpcTmCtar => DecodeCoreRegisterSetDescriptor("ppc_tm_ctar", descriptor),
				NtCorePpcTmCppr => DecodeCoreRegisterSetDescriptor("ppc_tm_cppr", descriptor),
				NtCorePpcTmCdscr => DecodeCoreRegisterSetDescriptor("ppc_tm_cdscr", descriptor),
				NtCorePpcPkey => DecodeCoreRegisterSetDescriptor("ppc_pkey", descriptor),
				NtCorePpcDexcr => DecodeCoreRegisterSetDescriptor("ppc_dexcr", descriptor),
				NtCorePpcHashkeyr => DecodeCoreRegisterSetDescriptor("ppc_hashkeyr", descriptor),
				NtCore386Tls => DecodeCoreRegisterSetDescriptor("x86_tls", descriptor),
				NtCore386Ioperm => DecodeCoreRegisterSetDescriptor("x86_ioperm", descriptor),
				NtCoreX86Xstate => DecodeX86XstateDescriptor(header, descriptor),
				NtCoreX86Cet => DecodeCoreRegisterSetDescriptor("x86_cet", descriptor),
			NtCoreS390HighGprs => DecodeCoreRegisterSetDescriptor("s390_high_gprs", descriptor),
			NtCoreS390Timer => DecodeCoreRegisterSetDescriptor("s390_timer", descriptor),
			NtCoreS390TodCmp => DecodeCoreRegisterSetDescriptor("s390_todcmp", descriptor),
			NtCoreS390TodPreg => DecodeCoreRegisterSetDescriptor("s390_todpreg", descriptor),
			NtCoreS390Ctrs => DecodeCoreRegisterSetDescriptor("s390_ctrs", descriptor),
			NtCoreS390Prefix => DecodeCoreRegisterSetDescriptor("s390_prefix", descriptor),
			NtCoreS390LastBreak => DecodeCoreRegisterSetDescriptor("s390_last_break", descriptor),
			NtCoreS390SystemCall => DecodeCoreRegisterSetDescriptor("s390_system_call", descriptor),
			NtCoreS390Tdb => DecodeCoreRegisterSetDescriptor("s390_tdb", descriptor),
			NtCoreS390VxrsLow => DecodeCoreRegisterSetDescriptor("s390_vxrs_low", descriptor),
			NtCoreS390VxrsHigh => DecodeCoreRegisterSetDescriptor("s390_vxrs_high", descriptor),
			NtCoreS390GuardedStorage => DecodeCoreRegisterSetDescriptor("s390_guarded_storage", descriptor),
			NtCoreS390RuntimeInstr => DecodeCoreRegisterSetDescriptor("s390_runtime_instr", descriptor),
			NtCoreS390VxrsExt => DecodeCoreRegisterSetDescriptor("s390_vxrs_ext", descriptor),
			NtCoreArmVfp => DecodeCoreRegisterSetDescriptor("arm_vfp", descriptor),
			NtCoreArmTls => DecodeCoreRegisterSetDescriptor("arm_tls", descriptor),
			NtCoreArmHwBreakpoint => DecodeCoreRegisterSetDescriptor("arm_hw_breakpoint", descriptor),
			NtCoreArmHwWatchpoint => DecodeCoreRegisterSetDescriptor("arm_hw_watchpoint", descriptor),
			NtCoreArmSystemCall => DecodeArmSystemCallDescriptor(descriptor, header.IsLittleEndian),
			NtCoreArmSve => DecodeArmSveDescriptor(descriptor, header.IsLittleEndian),
			NtCoreArmPacMask => DecodeArmPacMaskDescriptor(descriptor, header.IsLittleEndian),
			NtCoreArmPacAKeys => DecodeCoreRegisterSetDescriptor("arm_paca_keys", descriptor),
			NtCoreArmPacGKeys => DecodeCoreRegisterSetDescriptor("arm_pacg_keys", descriptor),
			NtCoreArmTaggedAddrCtrl => DecodeCoreRegisterSetDescriptor("arm_tagged_addr_ctrl", descriptor),
			NtCoreArmPacEnabledKeys => DecodeCoreRegisterSetDescriptor("arm_pac_enabled_keys", descriptor),
			NtCoreArmSsve => DecodeCoreRegisterSetDescriptor("arm_ssve", descriptor),
			NtCoreArmZa => DecodeCoreRegisterSetDescriptor("arm_za", descriptor),
			NtCoreArmZt => DecodeCoreRegisterSetDescriptor("arm_zt", descriptor),
				NtCoreArmFpmr => DecodeCoreRegisterSetDescriptor("arm_fpmr", descriptor),
				_ => DecodeUnknownNoteDescriptor(descriptor, header.IsLittleEndian)
			};
		}

	private static string DecodeGnuAbiTag(bool isLittleEndian, byte[] descriptor)
	{
		if (descriptor.Length < 16)
			return string.Empty;

		var span = descriptor.AsSpan();
		var os = ReadUInt32(span.Slice(0, 4), isLittleEndian);
		var major = ReadUInt32(span.Slice(4, 4), isLittleEndian);
		var minor = ReadUInt32(span.Slice(8, 4), isLittleEndian);
		var patch = ReadUInt32(span.Slice(12, 4), isLittleEndian);

		var osName = os switch
		{
			0 => "Linux",
			1 => "GNU",
			2 => "Solaris",
			3 => "FreeBSD",
			4 => "NetBSD",
			5 => "Syllable",
			6 => "NaCl",
			_ => $"OS#{os}"
		};

		return $"{osName} {major}.{minor}.{patch}";
	}

	private static string DecodeGnuPropertyNote(bool isLittleEndian, byte[] descriptor)
	{
		var properties = new List<string>();
		var span = descriptor.AsSpan();
		var cursor = 0;

		while (cursor + 8 <= span.Length)
		{
			var propertyType = ReadUInt32(span.Slice(cursor, 4), isLittleEndian);
			var dataSize = ReadUInt32(span.Slice(cursor + 4, 4), isLittleEndian);
			cursor += 8;

			if (dataSize > int.MaxValue)
				break;

			var size = (int)dataSize;
			if (cursor + size > span.Length)
				break;

			var payload = span.Slice(cursor, size);
			var payloadText = DecodeGnuPropertyPayload(propertyType, payload, isLittleEndian);

			properties.Add($"{GetGnuPropertyTypeName(propertyType)}={payloadText}");
			cursor += size;

			cursor = (int)AlignUp((ulong)cursor, 8);
		}

		return properties.Count == 0 ? string.Empty : string.Join(", ", properties);
	}

	private static string GetGnuPropertyTypeName(uint propertyType)
	{
		return propertyType switch
		{
			GnuPropertyAArch64Feature1And => "GNU_PROPERTY_AARCH64_FEATURE_1_AND",
			GnuPropertyX86Feature1And => "GNU_PROPERTY_X86_FEATURE_1_AND",
			GnuPropertyX86Isa1Needed => "GNU_PROPERTY_X86_ISA_1_NEEDED",
			GnuPropertyX86Isa1Used => "GNU_PROPERTY_X86_ISA_1_USED",
			0xC0000004 => "GNU_PROPERTY_X86_FEATURE_2_USED",
			0xC0000005 => "GNU_PROPERTY_X86_FEATURE_2_NEEDED",
			GnuPropertyStackSize => "GNU_PROPERTY_STACK_SIZE",
			GnuPropertyNoCopyOnProtected => "GNU_PROPERTY_NO_COPY_ON_PROTECTED",
			_ => $"GNU_PROPERTY_0x{propertyType:X}"
		};
	}

	private static string DecodeGnuPropertyPayload(uint propertyType, ReadOnlySpan<byte> payload, bool isLittleEndian)
	{
		if (payload.Length == 4)
		{
			var value = ReadUInt32(payload, isLittleEndian);
			return propertyType switch
			{
				GnuPropertyAArch64Feature1And => FormatBitMask(value, "BTI", "PAC"),
				GnuPropertyX86Feature1And => FormatBitMask(value, "IBT", "SHSTK", "LAM_U48", "LAM_U57"),
				GnuPropertyX86Isa1Needed or GnuPropertyX86Isa1Used => FormatBitMask(value, "BASELINE", "V2", "V3", "V4"),
				_ => $"0x{value:X}"
			};
		}

		return Convert.ToHexString(payload);
	}

	private static string FormatBitMask(uint value, params string[] bits)
	{
		if (value == 0)
			return "0x0";

		var names = new List<string>();
		var remaining = value;
		for (var i = 0; i < bits.Length; i++)
		{
			var bit = 1U << i;
			if ((value & bit) == 0)
				continue;

			names.Add(bits[i]);
			remaining &= ~bit;
		}

		return remaining == 0
			? $"{string.Join("|", names)} (0x{value:X})"
			: $"{string.Join("|", names)}|0x{remaining:X} (0x{value:X})";
	}

	private static string DecodeCoreAuxvDescriptor(ElfHeader header, byte[] descriptor)
	{
		var wordSize = GetCoreWordSize(header);
		var entrySize = wordSize * 2;
		if (entrySize <= 0)
			return string.Empty;

		var maxEntriesByLength = descriptor.Length / entrySize;
		var maxEntries = (int)Math.Min((ulong)maxEntriesByLength, MaxParserEntryCount);
		var preview = new List<string>();
		var count = 0;
		var offset = 0;
		while (count < maxEntries && offset + entrySize <= descriptor.Length)
		{
			if (!TryReadCoreWordAt(descriptor, offset, header.IsLittleEndian, wordSize, out var type))
				break;
			if (!TryReadCoreWordAt(descriptor, offset + wordSize, header.IsLittleEndian, wordSize, out var value))
				break;

			count++;
			if (preview.Count < 4)
				preview.Add($"{GetAuxvTypeName(type)}=0x{value:X}");

			offset += entrySize;
			if (type == AuxvAtNull)
				break;
		}

		if (count == 0)
			return string.Empty;

		return preview.Count == 0
			? $"auxv_entries={count}"
			: $"auxv_entries={count}, preview=[{string.Join(", ", preview)}]";
	}

	private static string DecodeCoreFileDescriptor(ElfHeader header, byte[] descriptor)
	{
		var wordSize = GetCoreWordSize(header);
		if (!TryReadCoreWordAt(descriptor, 0, header.IsLittleEndian, wordSize, out var declaredCount))
			return string.Empty;
		if (!TryReadCoreWordAt(descriptor, wordSize, header.IsLittleEndian, wordSize, out var pageSize))
			return $"file_mappings={declaredCount}";

		var entrySize = wordSize * 3;
		var tableOffset = wordSize * 2;
		var parsedCount = 0UL;
		if (entrySize > 0 && descriptor.Length > tableOffset)
		{
			var tableBytes = descriptor.Length - tableOffset;
			var maxByLength = (ulong)(tableBytes / entrySize);
			parsedCount = Math.Min(declaredCount, maxByLength);
		}

		return $"file_mappings={parsedCount} (declared={declaredCount}), page_size={pageSize}";
	}

	private static string DecodeGnuHwcap(bool isLittleEndian, byte[] descriptor)
	{
		if (descriptor.Length < 4 || (descriptor.Length % 4) != 0)
			return $"hwcap_bytes={descriptor.Length}";

		var wordCount = descriptor.Length / 4;
		var previewCount = Math.Min(wordCount, 4);
		var values = new List<string>(previewCount);
		for (var i = 0; i < previewCount; i++)
		{
			var word = ReadUInt32(descriptor.AsSpan(i * 4, 4), isLittleEndian);
			values.Add($"0x{word:X8}");
		}

		var suffix = wordCount > previewCount ? $", ... +{wordCount - previewCount}" : string.Empty;
		return $"hwcap_words={wordCount}, values=[{string.Join(", ", values)}{suffix}]";
	}

	private static string DecodeAsciiDescriptor(byte[] descriptor)
	{
		if (descriptor.Length == 0)
			return string.Empty;

		var trimmed = descriptor;
		var zeroIndex = Array.IndexOf(trimmed, (byte)0);
		if (zeroIndex >= 0)
			trimmed = descriptor.Take(zeroIndex).ToArray();
		if (trimmed.Length == 0)
			return string.Empty;

		foreach (var b in trimmed)
		{
			if (b is < 0x20 or > 0x7E)
				return $"bytes={descriptor.Length}";
		}

		return Encoding.ASCII.GetString(trimmed);
	}

	private static string DecodeBsdNoteDescriptor(string osName, uint type, byte[] descriptor, bool isLittleEndian)
	{
		if (descriptor.Length >= 4)
		{
			var value = ReadUInt32(descriptor.AsSpan(0, 4), isLittleEndian);
			if (osName == "FreeBSD" && type == NtFreeBsdAbiTag)
				return $"{osName}_abi={value}";

			if ((osName == "NetBSD" && type == NtNetBsdIdent)
				|| (osName == "OpenBSD" && type == NtOpenBsdIdent))
				return $"{osName}_ident={value}";

			return $"{osName}_value={value}";
		}

		return DecodeAsciiDescriptor(descriptor);
	}

	private static string DecodeAndroidNoteDescriptor(uint type, byte[] descriptor, bool isLittleEndian)
	{
		if (descriptor.Length >= 4)
		{
			var value = ReadUInt32(descriptor.AsSpan(0, 4), isLittleEndian);
			return type switch
			{
				NtAndroidAbi => $"android_abi={value}",
				NtAndroidMemtagLevelAsync => $"android_memtag_async={value}",
				NtAndroidMemtagLevelSync => $"android_memtag_sync={value}",
				_ => $"android_value={value}"
			};
		}

		return DecodeAsciiDescriptor(descriptor);
	}

		private static string DecodeLinuxNoteDescriptor(uint type, byte[] descriptor, bool isLittleEndian)
		{
			var ascii = DecodeAsciiDescriptor(descriptor);
			if (!string.IsNullOrEmpty(ascii) && !ascii.StartsWith("bytes=", StringComparison.Ordinal))
				return $"linux_note_0x{type:X}={ascii}";

			if (descriptor.Length >= 8)
			{
				var first = ReadUInt32(descriptor.AsSpan(0, 4), isLittleEndian);
				var second = ReadUInt32(descriptor.AsSpan(4, 4), isLittleEndian);
				return $"linux_note_0x{type:X}=[0x{first:X}, 0x{second:X}], bytes={descriptor.Length}";
			}

			if (descriptor.Length >= 4)
			{
				var value = ReadUInt32(descriptor.AsSpan(0, 4), isLittleEndian);
				return $"linux_note_0x{type:X}=0x{value:X}";
			}

			return DecodeUnknownNoteDescriptor(descriptor, isLittleEndian);
		}

	private static string DecodeX86XstateDescriptor(ElfHeader header, byte[] descriptor)
	{
		var details = new List<string> { $"x86_xstate_bytes={descriptor.Length}" };
		if (descriptor.Length >= 8)
		{
			var xstateBv = header.IsLittleEndian
				? BinaryPrimitives.ReadUInt64LittleEndian(descriptor.AsSpan(0, 8))
				: BinaryPrimitives.ReadUInt64BigEndian(descriptor.AsSpan(0, 8));
			details.Add($"xstate_bv=0x{xstateBv:X}");
		}

		if (descriptor.Length >= 16)
		{
			var xcompBv = header.IsLittleEndian
				? BinaryPrimitives.ReadUInt64LittleEndian(descriptor.AsSpan(8, 8))
				: BinaryPrimitives.ReadUInt64BigEndian(descriptor.AsSpan(8, 8));
			details.Add($"xcomp_bv=0x{xcompBv:X}");
		}

		return string.Join(", ", details);
	}

	private static string DecodeArmSystemCallDescriptor(byte[] descriptor, bool isLittleEndian)
	{
		var syscall = TryReadCoreInt32At(descriptor.AsSpan(), 0, isLittleEndian);
		if (syscall.HasValue)
			return $"arm_system_call={syscall.Value}";

		return DecodeCoreRegisterSetDescriptor("arm_system_call", descriptor);
	}

	private static string DecodeArmSveDescriptor(byte[] descriptor, bool isLittleEndian)
	{
		if (descriptor.Length < 16)
			return DecodeCoreRegisterSetDescriptor("arm_sve", descriptor);

		var size = ReadUInt32(descriptor.AsSpan(0, 4), isLittleEndian);
		var maxSize = ReadUInt32(descriptor.AsSpan(4, 4), isLittleEndian);
		var vl = isLittleEndian
			? BinaryPrimitives.ReadUInt16LittleEndian(descriptor.AsSpan(8, 2))
			: BinaryPrimitives.ReadUInt16BigEndian(descriptor.AsSpan(8, 2));
		var maxVl = isLittleEndian
			? BinaryPrimitives.ReadUInt16LittleEndian(descriptor.AsSpan(10, 2))
			: BinaryPrimitives.ReadUInt16BigEndian(descriptor.AsSpan(10, 2));
		var flags = isLittleEndian
			? BinaryPrimitives.ReadUInt16LittleEndian(descriptor.AsSpan(12, 2))
			: BinaryPrimitives.ReadUInt16BigEndian(descriptor.AsSpan(12, 2));
		return $"arm_sve_size={size}, max_size={maxSize}, vl={vl}, max_vl={maxVl}, flags=0x{flags:X}";
	}

	private static string DecodeArmPacMaskDescriptor(byte[] descriptor, bool isLittleEndian)
	{
		if (descriptor.Length < 16)
			return DecodeCoreRegisterSetDescriptor("arm_pac_mask", descriptor);

		var dataMask = isLittleEndian
			? BinaryPrimitives.ReadUInt64LittleEndian(descriptor.AsSpan(0, 8))
			: BinaryPrimitives.ReadUInt64BigEndian(descriptor.AsSpan(0, 8));
		var instructionMask = isLittleEndian
			? BinaryPrimitives.ReadUInt64LittleEndian(descriptor.AsSpan(8, 8))
			: BinaryPrimitives.ReadUInt64BigEndian(descriptor.AsSpan(8, 8));
		return $"arm_pac_data_mask=0x{dataMask:X}, arm_pac_instr_mask=0x{instructionMask:X}";
	}

	private static string DecodeStapSdtDescriptor(ElfHeader header, byte[] descriptor)
	{
		var wordSize = header.Class == ElfClass.Elf64 ? 8 : 4;
		if (descriptor.Length < wordSize * 3)
			return $"stapsdt_bytes={descriptor.Length}";

		if (!TryReadNoteWord(descriptor, 0, wordSize, header.IsLittleEndian, out var location)
			|| !TryReadNoteWord(descriptor, wordSize, wordSize, header.IsLittleEndian, out var baseAddress)
			|| !TryReadNoteWord(descriptor, wordSize * 2, wordSize, header.IsLittleEndian, out var semaphore))
		{
			return $"stapsdt_bytes={descriptor.Length}";
		}

		var cursor = wordSize * 3;
		var provider = ReadNullTerminatedAscii(descriptor, ref cursor);
		var name = ReadNullTerminatedAscii(descriptor, ref cursor);
		var args = ReadNullTerminatedAscii(descriptor, ref cursor);

		var details = new List<string>
		{
			$"pc=0x{location:X}",
			$"base=0x{baseAddress:X}",
			$"sema=0x{semaphore:X}"
		};

		if (!string.IsNullOrEmpty(provider))
			details.Add($"provider={provider}");
		if (!string.IsNullOrEmpty(name))
			details.Add($"name={name}");
		if (!string.IsNullOrEmpty(args))
			details.Add($"args={args}");

		return string.Join(", ", details);
	}

	private static string DecodeCoreRegisterSetDescriptor(string name, byte[] descriptor)
	{
		return $"{name}_bytes={descriptor.Length}";
	}

	private static bool TryReadNoteWord(byte[] descriptor, int offset, int wordSize, bool isLittleEndian, out ulong value)
	{
		value = 0;
		if (wordSize == 4)
		{
			if (offset < 0 || offset + 4 > descriptor.Length)
				return false;
			value = isLittleEndian
				? BinaryPrimitives.ReadUInt32LittleEndian(descriptor.AsSpan(offset, 4))
				: BinaryPrimitives.ReadUInt32BigEndian(descriptor.AsSpan(offset, 4));
			return true;
		}

		if (wordSize == 8)
		{
			if (offset < 0 || offset + 8 > descriptor.Length)
				return false;
			value = isLittleEndian
				? BinaryPrimitives.ReadUInt64LittleEndian(descriptor.AsSpan(offset, 8))
				: BinaryPrimitives.ReadUInt64BigEndian(descriptor.AsSpan(offset, 8));
			return true;
		}

		return false;
	}

	private static string ReadNullTerminatedAscii(byte[] descriptor, ref int cursor)
	{
		if (cursor < 0 || cursor >= descriptor.Length)
			return string.Empty;

		var start = cursor;
		while (cursor < descriptor.Length && descriptor[cursor] != 0)
			cursor++;

		var length = cursor - start;
		if (cursor < descriptor.Length && descriptor[cursor] == 0)
			cursor++;

		if (length <= 0)
			return string.Empty;

		var value = Encoding.ASCII.GetString(descriptor, start, length);
		foreach (var c in value)
		{
			if (c is < ' ' or > '~')
				return string.Empty;
		}

		return value;
	}

	private static string GetAuxvTypeName(ulong type)
	{
		return type switch
		{
			0 => "AT_NULL",
			1 => "AT_IGNORE",
			2 => "AT_EXECFD",
			3 => "AT_PHDR",
			4 => "AT_PHENT",
			5 => "AT_PHNUM",
			6 => "AT_PAGESZ",
			7 => "AT_BASE",
			8 => "AT_FLAGS",
			9 => "AT_ENTRY",
			11 => "AT_UID",
			12 => "AT_EUID",
			13 => "AT_GID",
			14 => "AT_EGID",
			15 => "AT_PLATFORM",
			16 => "AT_HWCAP",
			17 => "AT_CLKTCK",
			23 => "AT_SECURE",
			24 => "AT_BASE_PLATFORM",
			25 => "AT_RANDOM",
			26 => "AT_HWCAP2",
			31 => "AT_EXECFN",
			33 => "AT_SYSINFO_EHDR",
			_ => $"AT_{type}"
		};
	}

	private static uint ReadUInt32(ReadOnlySpan<byte> span, bool isLittleEndian)
	{
		return isLittleEndian
			? BinaryPrimitives.ReadUInt32LittleEndian(span)
			: BinaryPrimitives.ReadUInt32BigEndian(span);
	}
}
