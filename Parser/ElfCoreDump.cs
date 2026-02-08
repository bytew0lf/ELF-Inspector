namespace ELFInspector.Parser;

public static partial class ElfReader
{
	private const ushort Em386 = 3;
	private const ushort EmMips = 8;
	private const ushort EmSparc = 2;
	private const ushort EmArm = 40;
	private const ushort EmX86_64 = 62;
	private const ushort EmAArch64 = 183;
	private const ushort EmPpc = 20;
	private const ushort EmPpc64 = 21;
	private const ushort EmS390 = 22;
	private const ushort EmSparc64 = 43;
	private const ushort EmRiscV = 243;
	private const ushort EmLoongArch = 258;

	private const ushort EtCore = 4;
	private const uint NtCorePrStatus = 1;
	private const uint NtCorePrPsInfo = 3;
	private const uint NtCoreAuxv = 6;
	private const uint NtCoreFile = 0x46494C45;
	private const uint NtCoreSigInfo = 0x53494749;

	private readonly struct CorePrStatusLayout
	{
		public CorePrStatusLayout(
			int signalOffset,
			int currentSignalOffset,
			int threadIdOffset,
			int registersOffset,
			int registerCount,
			int? parentProcessIdOffset = null,
			int? processGroupIdOffset = null,
			int? sessionIdOffset = null)
		{
			SignalOffset = signalOffset;
			CurrentSignalOffset = currentSignalOffset;
			ThreadIdOffset = threadIdOffset;
			RegistersOffset = registersOffset;
			RegisterCount = registerCount;
			ParentProcessIdOffset = parentProcessIdOffset;
			ProcessGroupIdOffset = processGroupIdOffset;
			SessionIdOffset = sessionIdOffset;
		}

		public int SignalOffset { get; }
		public int CurrentSignalOffset { get; }
		public int ThreadIdOffset { get; }
		public int RegistersOffset { get; }
		public int RegisterCount { get; }
		public int? ParentProcessIdOffset { get; }
		public int? ProcessGroupIdOffset { get; }
		public int? SessionIdOffset { get; }
	}

	public static void ParseCoreDumpInfo(ElfFile elf)
	{
		using var empty = ElfDataSourceFactory.CreateInMemory(Array.Empty<byte>());
		ParseCoreDumpInfo(empty, elf);
	}

	public static void ParseCoreDumpInfo(ReadOnlySpan<byte> data, ElfFile elf)
	{
		using var source = ElfDataSourceFactory.CreateInMemory(data);
		ParseCoreDumpInfo(source, elf);
	}

	public static void ParseCoreDumpInfo(IEndianDataSource data, ElfFile elf)
	{
		var core = new ElfCoreDumpInfo
		{
			IsCoreDump = elf.Header.Type == EtCore,
			ProcessName = string.Empty
		};

		if (!core.IsCoreDump)
		{
			elf.CoreDump = core;
			return;
		}

		var isLittleEndian = elf.Header.IsLittleEndian;
		var wordSize = GetCoreWordSize(elf.Header);
		foreach (var note in elf.Notes)
		{
			if (!IsCoreNoteNamespace(note.Name))
				continue;

			switch (note.Type)
			{
				case NtCorePrStatus:
					ParseCorePrStatusNote(core, note.Descriptor, elf.Header);
					break;
				case NtCorePrPsInfo:
					ParseCorePrPsInfoNote(core, note.Descriptor, elf.Header);
					break;
				case NtCoreAuxv:
					ParseCoreAuxvNote(core, note.Descriptor, isLittleEndian, wordSize);
					break;
				case NtCoreFile:
					ParseCoreFileNote(core, note.Descriptor, isLittleEndian, wordSize);
					break;
				case NtCoreSigInfo:
					ParseCoreSigInfoNote(core, note.Descriptor, isLittleEndian);
					break;
				case NtCoreFpRegSet:
				case NtCorePrXfpReg:
				case NtCoreX86Xstate:
					case NtCorePpcVmx:
					case NtCorePpcSpe:
					case NtCorePpcVsx:
					case NtCorePpcTmCgpr:
					case NtCorePpcTmCfpr:
					case NtCorePpcTmCvmx:
					case NtCorePpcTmCvsx:
					case NtCorePpcTmSpr:
					case NtCorePpcTmCtar:
					case NtCorePpcTmCppr:
					case NtCorePpcTmCdscr:
					case NtCorePpcPkey:
					case NtCorePpcDexcr:
					case NtCorePpcHashkeyr:
					case NtCore386Tls:
					case NtCore386Ioperm:
					case NtCoreS390HighGprs:
				case NtCoreS390Timer:
				case NtCoreS390TodCmp:
				case NtCoreS390TodPreg:
				case NtCoreS390Ctrs:
				case NtCoreS390Prefix:
				case NtCoreS390LastBreak:
				case NtCoreS390SystemCall:
				case NtCoreS390Tdb:
				case NtCoreS390VxrsLow:
				case NtCoreS390VxrsHigh:
				case NtCoreS390GuardedStorage:
				case NtCoreS390RuntimeInstr:
				case NtCoreS390VxrsExt:
				case NtCoreArmVfp:
				case NtCoreArmTls:
				case NtCoreArmHwBreakpoint:
				case NtCoreArmHwWatchpoint:
				case NtCoreArmSystemCall:
				case NtCoreArmSve:
				case NtCoreArmPacMask:
				case NtCoreArmPacAKeys:
				case NtCoreArmPacGKeys:
				case NtCoreArmTaggedAddrCtrl:
				case NtCoreArmPacEnabledKeys:
				case NtCoreArmSsve:
				case NtCoreArmZa:
				case NtCoreArmZt:
					case NtCoreArmFpmr:
					case NtCoreX86Cet:
						ParseCoreSupplementalRegisterNote(core, note.Descriptor, isLittleEndian, wordSize);
						break;
				}
		}

		core.Signals.Sort();
		ParseCoreThreadUnwind(data, elf, core);
		elf.CoreDump = core;
	}

	private static bool IsCoreNoteNamespace(string name)
	{
		return string.Equals(name, "CORE", StringComparison.OrdinalIgnoreCase)
			|| string.Equals(name, "LINUX", StringComparison.OrdinalIgnoreCase);
	}

	private static void ParseCorePrStatusNote(ElfCoreDumpInfo core, byte[] descriptor, ElfHeader header)
	{
		var span = descriptor.AsSpan();
		var isLittleEndian = header.IsLittleEndian;
		var wordSize = GetCoreWordSize(header);
		var hasKnownLayout = TryGetCorePrStatusLayout(header, descriptor.Length, wordSize, out var layout);

		var signalOffset = hasKnownLayout ? layout.SignalOffset : 0;
		var currentSignalOffset = hasKnownLayout ? layout.CurrentSignalOffset : 12;
		var signal = TryReadCoreInt32At(span, signalOffset, isLittleEndian);
		var currentSignal = TryReadCoreUInt16At(span, currentSignalOffset, isLittleEndian);
		var threadId = hasKnownLayout
			? TryReadCoreInt32At(span, layout.ThreadIdOffset, isLittleEndian)
			: TryReadFirstPlausibleCoreInt32(span, isLittleEndian, 24, 28, 32, 48, 72, 80);
		var parentProcessId = hasKnownLayout && layout.ParentProcessIdOffset.HasValue
			? TryReadCoreInt32At(span, layout.ParentProcessIdOffset.Value, isLittleEndian)
			: null;
		var processGroupId = hasKnownLayout && layout.ProcessGroupIdOffset.HasValue
			? TryReadCoreInt32At(span, layout.ProcessGroupIdOffset.Value, isLittleEndian)
			: null;
		var sessionId = hasKnownLayout && layout.SessionIdOffset.HasValue
			? TryReadCoreInt32At(span, layout.SessionIdOffset.Value, isLittleEndian)
			: null;

		var thread = new ElfCoreThreadInfo
		{
			Index = core.Threads.Count,
			ThreadId = threadId,
			ParentProcessId = parentProcessId,
			ProcessGroupId = processGroupId,
			SessionId = sessionId,
			Signal = signal,
			CurrentSignal = currentSignal
		};
		ExtractCoreRegisterPreview(span, isLittleEndian, wordSize, hasKnownLayout ? layout : null, thread.RegisterPreview);
		core.Threads.Add(thread);

		if (signal.HasValue)
		{
			AddCoreSignal(core, signal.Value);
			if (!core.Signal.HasValue)
				core.Signal = signal.Value;
		}

		if (!core.ProcessId.HasValue && threadId.HasValue)
			core.ProcessId = threadId;
	}

	private static void ParseCorePrPsInfoNote(ElfCoreDumpInfo core, byte[] descriptor, ElfHeader header)
	{
		var span = descriptor.AsSpan();
		var isLittleEndian = header.IsLittleEndian;
		var processName = ExtractCoreProcessName(span, header);
		if (!string.IsNullOrEmpty(processName))
			core.ProcessName = processName;

		if (!core.ProcessId.HasValue)
		{
			var pid = TryReadCoreProcessIdFromPrPsInfo(span, header, isLittleEndian)
				?? TryReadFirstPlausibleCoreInt32(span, isLittleEndian, 16, 24, 28, 32, 36, 40);
			if (pid.HasValue)
				core.ProcessId = pid.Value;
		}
	}

	private static void ParseCoreAuxvNote(ElfCoreDumpInfo core, byte[] descriptor, bool isLittleEndian, int wordSize)
	{
		var entrySize = wordSize * 2;
		if (entrySize <= 0)
			return;

		var maxEntriesByLength = descriptor.Length / entrySize;
		var maxEntries = (int)Math.Min((ulong)maxEntriesByLength, MaxParserEntryCount);
		var count = 0;
		var offset = 0;
		while (count < maxEntries && offset + entrySize <= descriptor.Length)
		{
			if (!TryReadCoreWordAt(descriptor, offset, isLittleEndian, wordSize, out var type))
				break;
			if (!TryReadCoreWordAt(descriptor, offset + wordSize, isLittleEndian, wordSize, out var value))
				break;

			count++;
			offset += entrySize;
			if (type == 0 && value == 0)
				break;
		}

		core.AuxVectorEntryCount = AddSaturated(core.AuxVectorEntryCount, count);
	}

	private static void ParseCoreFileNote(ElfCoreDumpInfo core, byte[] descriptor, bool isLittleEndian, int wordSize)
	{
		if (!TryReadCoreWordAt(descriptor, 0, isLittleEndian, wordSize, out var fileCount))
			return;
		if (fileCount == 0)
			return;

		var fileTableOffset = wordSize * 2;
		var entrySize = wordSize * 3;
		if (entrySize <= 0 || descriptor.Length <= fileTableOffset)
			return;

		var tableBytes = descriptor.Length - fileTableOffset;
		var maxEntriesByLength = tableBytes / entrySize;
		var clampedCount = Math.Min(fileCount, (ulong)maxEntriesByLength);
		clampedCount = Math.Min(clampedCount, MaxParserEntryCount);
		var addCount = clampedCount > int.MaxValue ? int.MaxValue : (int)clampedCount;
		core.FileMappingCount = AddSaturated(core.FileMappingCount, addCount);
	}

	private static void ParseCoreSigInfoNote(ElfCoreDumpInfo core, byte[] descriptor, bool isLittleEndian)
	{
		var signal = TryReadCoreInt32At(descriptor.AsSpan(), 0, isLittleEndian);
		if (!signal.HasValue)
			return;

		AddCoreSignal(core, signal.Value);
		if (!core.Signal.HasValue)
			core.Signal = signal.Value;
	}

	private static void ParseCoreSupplementalRegisterNote(ElfCoreDumpInfo core, byte[] descriptor, bool isLittleEndian, int wordSize)
	{
		if (descriptor == null || descriptor.Length == 0 || wordSize is not (4 or 8))
			return;

		var thread = core.Threads.Count == 0
			? new ElfCoreThreadInfo { Index = 0 }
			: core.Threads[^1];
		if (core.Threads.Count == 0)
			core.Threads.Add(thread);

		var maxWords = Math.Min(32, descriptor.Length / wordSize);
		for (var i = 0; i < maxWords; i++)
		{
			if (!TryReadCoreWordAt(descriptor, i * wordSize, isLittleEndian, wordSize, out var value))
				break;

			thread.RegisterPreview.Add(value);
		}
	}

	private static void AddCoreSignal(ElfCoreDumpInfo core, int signal)
	{
		if (signal <= 0)
			return;
		if (!core.Signals.Contains(signal))
			core.Signals.Add(signal);
	}

	private static void ExtractCoreRegisterPreview(
		ReadOnlySpan<byte> descriptor,
		bool isLittleEndian,
		int wordSize,
		CorePrStatusLayout? layout,
		List<ulong> target)
	{
		target.Clear();
		if (wordSize is not (4 or 8))
			return;

		if (layout.HasValue && TryExtractStructuredCoreRegisterPreview(descriptor, isLittleEndian, wordSize, layout.Value, target))
			return;

		var availableWords = descriptor.Length / wordSize;
		if (availableWords == 0)
			return;

		var previewCount = Math.Min(availableWords, 64);
		var startWord = availableWords - previewCount;
		for (var i = startWord; i < availableWords; i++)
		{
			var offset = i * wordSize;
			if (!TryReadCoreWordAt(descriptor, offset, isLittleEndian, wordSize, out var value))
				continue;

			target.Add(value);
		}
	}

	private static bool TryExtractStructuredCoreRegisterPreview(
		ReadOnlySpan<byte> descriptor,
		bool isLittleEndian,
		int wordSize,
		CorePrStatusLayout layout,
		List<ulong> target)
	{
		if (layout.RegisterCount <= 0 || layout.RegistersOffset < 0)
			return false;

		var registerBytes = checked(layout.RegisterCount * wordSize);
		if (layout.RegistersOffset > descriptor.Length || registerBytes > descriptor.Length - layout.RegistersOffset)
			return false;

		var previewCount = Math.Min(layout.RegisterCount, 64);
		for (var i = 0; i < previewCount; i++)
		{
			var offset = checked(layout.RegistersOffset + (i * wordSize));
			if (!TryReadCoreWordAt(descriptor, offset, isLittleEndian, wordSize, out var value))
				return false;

			target.Add(value);
		}

		return target.Count > 0;
	}

	private static string ExtractCoreProcessName(ReadOnlySpan<byte> descriptor, ElfHeader header)
	{
		var fixedNameOffset = GetCorePrPsInfoNameOffset(header);
		if (fixedNameOffset.HasValue && fixedNameOffset.Value + 16 <= descriptor.Length)
		{
			var fixedName = ReadCoreAsciiString(descriptor.Slice(fixedNameOffset.Value, 16));
			if (!string.IsNullOrEmpty(fixedName))
				return fixedName;
		}

		if (descriptor.Length >= 96)
		{
			var fixedNameStart = descriptor.Length - 96;
			var fixedName = ReadCoreAsciiString(descriptor.Slice(fixedNameStart, 16));
			if (!string.IsNullOrEmpty(fixedName))
				return fixedName;
		}

		var best = string.Empty;
		var cursor = 0;
		while (cursor < descriptor.Length)
		{
			while (cursor < descriptor.Length && !IsPrintableAscii(descriptor[cursor]))
				cursor++;
			if (cursor >= descriptor.Length)
				break;

			var start = cursor;
			while (cursor < descriptor.Length && IsPrintableAscii(descriptor[cursor]))
				cursor++;

			var candidate = Encoding.ASCII.GetString(descriptor.Slice(start, cursor - start));
			if (candidate.Length > best.Length)
				best = candidate;
		}

		return best.Length >= 2 ? best : string.Empty;
	}

	private static int? TryReadCoreProcessIdFromPrPsInfo(ReadOnlySpan<byte> descriptor, ElfHeader header, bool isLittleEndian)
	{
		var offset = GetCorePrPsInfoPidOffset(header);
		if (!offset.HasValue)
			return null;

		var value = TryReadCoreInt32At(descriptor, offset.Value, isLittleEndian);
		if (!value.HasValue || value.Value <= 0)
			return null;

		return value.Value;
	}

	private static int? GetCorePrPsInfoNameOffset(ElfHeader header)
	{
		if (header.Class == ElfClass.Elf64)
			return 40;
		if (header.Class == ElfClass.Elf32)
			return 32;

		return null;
	}

	private static int? GetCorePrPsInfoPidOffset(ElfHeader header)
	{
		if (header.Class == ElfClass.Elf64)
			return 24;
		if (header.Class == ElfClass.Elf32)
			return 16;

		return null;
	}

	private static bool TryGetCorePrStatusLayout(ElfHeader header, int descriptorLength, int wordSize, out CorePrStatusLayout layout)
	{
		layout = default;
		if (wordSize == 8)
		{
			if (header.Machine == EmX86_64)
			{
				layout = new CorePrStatusLayout(
					signalOffset: 0,
					currentSignalOffset: 12,
					threadIdOffset: 32,
					registersOffset: 112,
					registerCount: 27,
					parentProcessIdOffset: 36,
					processGroupIdOffset: 40,
					sessionIdOffset: 44);
				return IsLayoutReadable(layout, descriptorLength, wordSize);
			}

			if (header.Machine == EmAArch64)
			{
				layout = new CorePrStatusLayout(
					signalOffset: 0,
					currentSignalOffset: 12,
					threadIdOffset: 32,
					registersOffset: 112,
					registerCount: 34,
					parentProcessIdOffset: 36,
					processGroupIdOffset: 40,
					sessionIdOffset: 44);
				return IsLayoutReadable(layout, descriptorLength, wordSize);
			}

			if (header.Machine == EmPpc64)
			{
				layout = new CorePrStatusLayout(
					signalOffset: 0,
					currentSignalOffset: 12,
					threadIdOffset: 32,
					registersOffset: 112,
					registerCount: 48,
					parentProcessIdOffset: 36,
					processGroupIdOffset: 40,
					sessionIdOffset: 44);
				return IsLayoutReadable(layout, descriptorLength, wordSize);
			}

			if (header.Machine == EmS390)
			{
				layout = new CorePrStatusLayout(
					signalOffset: 0,
					currentSignalOffset: 12,
					threadIdOffset: 32,
					registersOffset: 112,
					registerCount: 18,
					parentProcessIdOffset: 36,
					processGroupIdOffset: 40,
					sessionIdOffset: 44);
				return IsLayoutReadable(layout, descriptorLength, wordSize);
			}

			if (header.Machine == EmRiscV)
			{
				layout = new CorePrStatusLayout(
					signalOffset: 0,
					currentSignalOffset: 12,
					threadIdOffset: 32,
					registersOffset: 112,
					registerCount: 33,
					parentProcessIdOffset: 36,
					processGroupIdOffset: 40,
					sessionIdOffset: 44);
				return IsLayoutReadable(layout, descriptorLength, wordSize);
			}

			if (header.Machine == EmMips)
			{
				layout = new CorePrStatusLayout(
					signalOffset: 0,
					currentSignalOffset: 12,
					threadIdOffset: 32,
					registersOffset: 112,
					registerCount: 45,
					parentProcessIdOffset: 36,
					processGroupIdOffset: 40,
					sessionIdOffset: 44);
				return IsLayoutReadable(layout, descriptorLength, wordSize);
			}

			if (header.Machine == EmSparc64)
			{
				layout = new CorePrStatusLayout(
					signalOffset: 0,
					currentSignalOffset: 12,
					threadIdOffset: 32,
					registersOffset: 112,
					registerCount: 36,
					parentProcessIdOffset: 36,
					processGroupIdOffset: 40,
					sessionIdOffset: 44);
				return IsLayoutReadable(layout, descriptorLength, wordSize);
			}

			if (header.Machine == EmLoongArch)
			{
				layout = new CorePrStatusLayout(
					signalOffset: 0,
					currentSignalOffset: 12,
					threadIdOffset: 32,
					registersOffset: 112,
					registerCount: 34,
					parentProcessIdOffset: 36,
					processGroupIdOffset: 40,
					sessionIdOffset: 44);
				return IsLayoutReadable(layout, descriptorLength, wordSize);
			}
		}
		else if (wordSize == 4)
		{
			if (header.Machine == Em386)
			{
				layout = new CorePrStatusLayout(
					signalOffset: 0,
					currentSignalOffset: 12,
					threadIdOffset: 24,
					registersOffset: 72,
					registerCount: 17,
					parentProcessIdOffset: 28,
					processGroupIdOffset: 32,
					sessionIdOffset: 36);
				return IsLayoutReadable(layout, descriptorLength, wordSize);
			}

			if (header.Machine == EmArm)
			{
				layout = new CorePrStatusLayout(
					signalOffset: 0,
					currentSignalOffset: 12,
					threadIdOffset: 24,
					registersOffset: 72,
					registerCount: 18,
					parentProcessIdOffset: 28,
					processGroupIdOffset: 32,
					sessionIdOffset: 36);
				return IsLayoutReadable(layout, descriptorLength, wordSize);
			}

			if (header.Machine == EmPpc)
			{
				layout = new CorePrStatusLayout(
					signalOffset: 0,
					currentSignalOffset: 12,
					threadIdOffset: 24,
					registersOffset: 72,
					registerCount: 48,
					parentProcessIdOffset: 28,
					processGroupIdOffset: 32,
					sessionIdOffset: 36);
				return IsLayoutReadable(layout, descriptorLength, wordSize);
			}

			if (header.Machine == EmMips)
			{
				layout = new CorePrStatusLayout(
					signalOffset: 0,
					currentSignalOffset: 12,
					threadIdOffset: 24,
					registersOffset: 72,
					registerCount: 45,
					parentProcessIdOffset: 28,
					processGroupIdOffset: 32,
					sessionIdOffset: 36);
				return IsLayoutReadable(layout, descriptorLength, wordSize);
			}

			if (header.Machine == EmSparc)
			{
				layout = new CorePrStatusLayout(
					signalOffset: 0,
					currentSignalOffset: 12,
					threadIdOffset: 24,
					registersOffset: 72,
					registerCount: 38,
					parentProcessIdOffset: 28,
					processGroupIdOffset: 32,
					sessionIdOffset: 36);
				return IsLayoutReadable(layout, descriptorLength, wordSize);
			}

			if (header.Machine == EmS390)
			{
				layout = new CorePrStatusLayout(
					signalOffset: 0,
					currentSignalOffset: 12,
					threadIdOffset: 24,
					registersOffset: 72,
					registerCount: 18,
					parentProcessIdOffset: 28,
					processGroupIdOffset: 32,
					sessionIdOffset: 36);
				return IsLayoutReadable(layout, descriptorLength, wordSize);
			}

			if (header.Machine == EmRiscV)
			{
				layout = new CorePrStatusLayout(
					signalOffset: 0,
					currentSignalOffset: 12,
					threadIdOffset: 24,
					registersOffset: 72,
					registerCount: 33,
					parentProcessIdOffset: 28,
					processGroupIdOffset: 32,
					sessionIdOffset: 36);
				return IsLayoutReadable(layout, descriptorLength, wordSize);
			}

			if (header.Machine == EmLoongArch)
			{
				layout = new CorePrStatusLayout(
					signalOffset: 0,
					currentSignalOffset: 12,
					threadIdOffset: 24,
					registersOffset: 72,
					registerCount: 34,
					parentProcessIdOffset: 28,
					processGroupIdOffset: 32,
					sessionIdOffset: 36);
				return IsLayoutReadable(layout, descriptorLength, wordSize);
			}
		}

		return false;
	}

	private static bool IsLayoutReadable(CorePrStatusLayout layout, int descriptorLength, int wordSize)
	{
		if (layout.SignalOffset + 4 > descriptorLength
			|| layout.CurrentSignalOffset + 2 > descriptorLength
			|| layout.ThreadIdOffset + 4 > descriptorLength)
		{
			return false;
		}

		var registerBytes = checked(layout.RegisterCount * wordSize);
		return layout.RegistersOffset <= descriptorLength
			&& registerBytes <= descriptorLength - layout.RegistersOffset;
	}

	private static string ReadCoreAsciiString(ReadOnlySpan<byte> span)
	{
		var end = span.IndexOf((byte)0);
		if (end < 0)
			end = span.Length;
		if (end <= 0)
			return string.Empty;

		return Encoding.ASCII.GetString(span.Slice(0, end)).Trim();
	}

	private static bool IsPrintableAscii(byte value)
	{
		return value >= 0x20 && value <= 0x7E;
	}

	private static int GetCoreWordSize(ElfHeader header)
	{
		return header.Class == ElfClass.Elf64 ? 8 : 4;
	}

	private static int? TryReadFirstPlausibleCoreInt32(ReadOnlySpan<byte> descriptor, bool isLittleEndian, params int[] offsets)
	{
		foreach (var offset in offsets)
		{
			var value = TryReadCoreInt32At(descriptor, offset, isLittleEndian);
			if (!value.HasValue)
				continue;

			if (value.Value > 0 && value.Value < 1_000_000)
				return value.Value;
		}

		return null;
	}

	private static int? TryReadCoreInt32At(ReadOnlySpan<byte> descriptor, int offset, bool isLittleEndian)
	{
		if (offset < 0 || offset + 4 > descriptor.Length)
			return null;

		return isLittleEndian
			? BinaryPrimitives.ReadInt32LittleEndian(descriptor.Slice(offset, 4))
			: BinaryPrimitives.ReadInt32BigEndian(descriptor.Slice(offset, 4));
	}

	private static int? TryReadCoreUInt16At(ReadOnlySpan<byte> descriptor, int offset, bool isLittleEndian)
	{
		if (offset < 0 || offset + 2 > descriptor.Length)
			return null;

		var value = isLittleEndian
			? BinaryPrimitives.ReadUInt16LittleEndian(descriptor.Slice(offset, 2))
			: BinaryPrimitives.ReadUInt16BigEndian(descriptor.Slice(offset, 2));
		return value;
	}

	private static bool TryReadCoreWordAt(ReadOnlySpan<byte> descriptor, int offset, bool isLittleEndian, int wordSize, out ulong value)
	{
		value = 0;
		if (wordSize == 4)
		{
			if (offset < 0 || offset + 4 > descriptor.Length)
				return false;

			value = isLittleEndian
				? BinaryPrimitives.ReadUInt32LittleEndian(descriptor.Slice(offset, 4))
				: BinaryPrimitives.ReadUInt32BigEndian(descriptor.Slice(offset, 4));
			return true;
		}

		if (wordSize == 8)
		{
			if (offset < 0 || offset + 8 > descriptor.Length)
				return false;

			value = isLittleEndian
				? BinaryPrimitives.ReadUInt64LittleEndian(descriptor.Slice(offset, 8))
				: BinaryPrimitives.ReadUInt64BigEndian(descriptor.Slice(offset, 8));
			return true;
		}

		return false;
	}

	private static int AddSaturated(int current, int value)
	{
		if (value <= 0 || current == int.MaxValue)
			return current;

		var sum = (long)current + value;
		return sum >= int.MaxValue ? int.MaxValue : (int)sum;
	}
}
