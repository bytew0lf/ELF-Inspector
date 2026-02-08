namespace ELFInspector.Parser;

public static partial class ElfReader
{
	private const uint PfExecute = 0x1;

	private sealed class CoreMemorySegment
	{
		public ulong VirtualStart { get; init; }
		public ulong VirtualEnd { get; init; }
		public ulong FileOffset { get; init; }
		public ulong FileSize { get; init; }
		public bool Executable { get; init; }
	}

	private static void ParseCoreThreadUnwind(IEndianDataSource data, ElfFile elf, ElfCoreDumpInfo core)
	{
		core.UnwindThreads.Clear();
		if (!core.IsCoreDump || core.Threads.Count == 0)
			return;

		var wordSize = GetCoreWordSize(elf.Header);
		var segments = BuildCoreMemorySegments(data, elf);
		for (var i = 0; i < core.Threads.Count; i++)
		{
			var thread = core.Threads[i];
			var unwind = new ElfCoreThreadUnwindInfo
			{
				ThreadIndex = thread.Index,
				ThreadId = thread.ThreadId,
				Strategy = "none",
				Complete = false
			};

			if (!TryGetThreadRegisterState(elf.Header, thread.RegisterPreview, out var ip, out var sp, out var fp, out var linkRegister, out var strategy))
			{
				core.UnwindThreads.Add(unwind);
				continue;
			}

			unwind.Strategy = strategy;
			unwind.Frames.Add(CreateCoreUnwindFrame(elf, 0, ip, sp, fp, strategy));

			var cfiWalkWorked = TryUnwindByEhFrameCfi(
				data,
				elf,
				segments,
				ip,
				sp,
				fp,
				wordSize,
				unwind.Frames,
				"eh-frame-cfi");

			var framePointerWalkWorked = false;
			if (!cfiWalkWorked)
			{
				framePointerWalkWorked = TryUnwindByFramePointer(
					data,
					elf,
					segments,
					ip,
					sp,
					fp,
					wordSize,
					unwind.Frames,
					strategy);
			}

			var linkRegisterWalkWorked = false;
			var linkRegisterStrategy = $"{strategy}-link-register";
			if (!framePointerWalkWorked && !cfiWalkWorked && linkRegister.HasValue)
			{
				linkRegisterWalkWorked = TryUnwindByLinkRegister(
					elf,
					segments,
					sp,
					fp,
					linkRegister.Value,
					unwind.Frames,
					linkRegisterStrategy);
			}

			var stackScanWalkWorked = false;
			if (!framePointerWalkWorked && !cfiWalkWorked && !linkRegisterWalkWorked)
			{
				stackScanWalkWorked = TryUnwindByStackScan(
					data,
					elf,
					segments,
					sp,
					wordSize,
					unwind.Frames,
					"stack-scan");
			}

			unwind.Strategy = cfiWalkWorked
				? "eh-frame-cfi"
				: framePointerWalkWorked
					? strategy
					: linkRegisterWalkWorked
						? linkRegisterStrategy
						: stackScanWalkWorked
							? "stack-scan"
							: strategy;
			unwind.Complete = unwind.Frames.Count > 1;
			core.UnwindThreads.Add(unwind);
		}
	}

	private static List<CoreMemorySegment> BuildCoreMemorySegments(IEndianDataSource data, ElfFile elf)
	{
		var result = new List<CoreMemorySegment>();
		for (var i = 0; i < elf.ProgramHeaders.Count; i++)
		{
			var segment = elf.ProgramHeaders[i];
			if (segment.Type != PtLoad || segment.FileSize == 0)
				continue;

			if (segment.Offset > data.Length || segment.FileSize > data.Length - segment.Offset)
				continue;

			var end = segment.VirtualAddress + segment.MemorySize;
			if (end < segment.VirtualAddress)
				end = ulong.MaxValue;

			result.Add(new CoreMemorySegment
			{
				VirtualStart = segment.VirtualAddress,
				VirtualEnd = end,
				FileOffset = segment.Offset,
				FileSize = segment.FileSize,
				Executable = (segment.Flags & PfExecute) != 0
			});
		}

		result.Sort((a, b) => a.VirtualStart.CompareTo(b.VirtualStart));
		return result;
	}

	private static bool TryGetThreadRegisterState(
		ElfHeader header,
		List<ulong> registers,
		out ulong ip,
		out ulong sp,
		out ulong? fp,
		out ulong? linkRegister,
		out string strategy)
	{
		ip = 0;
		sp = 0;
		fp = null;
		linkRegister = null;
		strategy = string.Empty;

		if (registers == null || registers.Count == 0)
			return false;

		switch (header.Machine)
		{
				case EmX86_64:
				{
				if (registers.Count < 20)
					return false;
				// Linux x86_64 gregset: ... RBP[4], RIP[16], RSP[19]
					fp = registers[4];
					ip = registers[16];
					sp = registers[19];
					strategy = "x86_64-frame-pointer";
					return ip != 0;
			}
				case Em386:
				{
				if (registers.Count < 16)
					return false;
				// Linux i386 gregset: ... EBP[6], EIP[12], ESP[15]
					fp = registers[6];
					ip = registers[12];
					sp = registers[15];
					strategy = "i386-frame-pointer";
					return ip != 0;
			}
				case EmAArch64:
				{
					if (registers.Count < 32)
						return false;
					// x0-x30, sp, pc, pstate
					fp = registers[29];
					sp = registers[31];
					linkRegister = registers[30];
					ip = registers.Count > 32 ? registers[32] : linkRegister.Value;
					strategy = "aarch64-frame-pointer";
					return ip != 0;
				}
				case EmArm:
				{
				if (registers.Count < 16)
					return false;
				// r0-r15, where r11=fp, r13=sp, r15=pc
					fp = registers[11];
					sp = registers[13];
					ip = registers[15];
					linkRegister = registers[14];
					strategy = "arm-frame-pointer";
					return ip != 0;
				}
				case EmPpc:
				{
					if (registers.Count < 33)
						return false;
					// Linux powerpc: gpr0..gpr31, nip, ...
					sp = registers[1];
					fp = registers.Count > 31 ? registers[31] : 0;
					ip = registers[32];
					linkRegister = registers.Count > 36 ? registers[36] : null;
						strategy = "ppc-stack";
						return ip != 0;
					}
					case EmPpc64:
				{
					if (registers.Count < 33)
						return false;
					// Linux ppc64: gpr0..gpr31, nip, ...
					sp = registers[1];
					fp = registers.Count > 31 ? registers[31] : 0;
					ip = registers[32];
					linkRegister = registers.Count > 36 ? registers[36] : null;
						strategy = "ppc64-stack";
						return ip != 0;
					}
				case EmS390:
				{
					if (registers.Count < 18)
						return false;
					// Linux s390/s390x preview: psw_mask, psw_addr, gpr0..gpr15
					ip = registers[1];
					sp = registers[17];
					fp = registers.Count > 13 ? registers[13] : null;
					linkRegister = registers.Count > 16 ? registers[16] : null;
					strategy = "s390-stack";
					return ip != 0;
				}
				case EmRiscV:
				{
					if (registers.Count < 9)
						return false;
					// Linux riscv64: x0..x31, pc
					sp = registers[2];
					fp = registers[8];
					linkRegister = registers.Count > 1 ? registers[1] : 0UL;
					ip = registers.Count > 32 ? registers[32] : linkRegister.Value;
					strategy = "riscv64-stack";
					return ip != 0;
				}
				case EmMips:
				{
				if (registers.Count < 32)
					return false;
				// Linux mips{32,64}: r29=sp, r30=fp, cp0_epc is near tail.
					sp = registers[29];
					fp = registers[30];
					ip = registers.Count > 35 ? registers[35] : registers[31];
					linkRegister = registers[31];
					strategy = "mips-stack";
					return ip != 0;
				}
			case EmSparc:
			case EmSparc64:
			{
				if (registers.Count < 15)
					return false;
				// Linux sparc/sparc64: tpc/pc near head, o6 holds stack pointer.
				ip = registers[1];
				sp = registers[14];
				fp = registers.Count > 30 ? registers[30] : null;
					strategy = "sparc-stack";
					return ip != 0;
				}
				case EmLoongArch:
				{
					if (registers.Count < 4)
						return false;
					// loongarch64: r3=sp, r22=fp, r1=ra, tail entries include exception-era/pc.
					sp = registers[3];
					fp = registers.Count > 22 ? registers[22] : null;
					linkRegister = registers.Count > 1 ? registers[1] : 0UL;
					ip = registers.Count > 33 ? registers[^1] : linkRegister.Value;
					strategy = "loongarch64-stack";
					return ip != 0;
				}
				default:
					return false;
			}
		}

	private static bool TryUnwindByLinkRegister(
		ElfFile elf,
		List<CoreMemorySegment> segments,
		ulong stackPointer,
		ulong? framePointer,
		ulong linkRegister,
		List<ElfCoreUnwindFrameInfo> frames,
		string strategy)
	{
		if (linkRegister == 0 || !IsExecutableAddress(segments, linkRegister))
			return false;

		for (var i = 0; i < frames.Count; i++)
		{
			if (frames[i].InstructionPointer == linkRegister)
				return false;
		}

		frames.Add(CreateCoreUnwindFrame(elf, frames.Count, linkRegister, stackPointer, framePointer, strategy));
		return true;
	}

	private static bool TryUnwindByEhFrameCfi(
		IEndianDataSource data,
		ElfFile elf,
		List<CoreMemorySegment> segments,
		ulong initialIp,
		ulong initialSp,
		ulong? initialFp,
		int wordSize,
		List<ElfCoreUnwindFrameInfo> frames,
		string strategy)
	{
		if (wordSize is not (4 or 8))
			return false;
		if (segments.Count == 0)
			return false;

		var fdeEntries = elf.Unwind?.EhFrame?.FdeEntries;
		if (fdeEntries == null || fdeEntries.Count == 0)
			return false;

		var ip = initialIp;
		var sp = initialSp;
		var fp = initialFp;
		var depth = frames.Count;
		var seen = new HashSet<ulong>();
		var maxDepth = 64;

		while (depth < maxDepth)
		{
			var fde = FindEhFrameFdeByAddress(fdeEntries, ip);
			if (fde == null || !fde.CfaRuleAvailable || !fde.ReturnAddressOffsetAvailable)
				break;

			if (!TryResolveCfaBaseRegister(
				elf.Header.Machine,
				fde.CfaRegister,
				sp,
				fp,
				out var cfaBase))
			{
				break;
			}

			if (!TryApplySignedOffset(cfaBase, fde.CfaOffset, out var cfa))
				break;
			if (!TryApplySignedOffset(cfa, fde.ReturnAddressOffset, out var returnAddressLocation))
				break;
			if (!TryReadCoreMemoryWord(data, elf.Header.IsLittleEndian, wordSize, segments, returnAddressLocation, out var returnAddress))
				break;
			if (returnAddress == 0 || !IsExecutableAddress(segments, returnAddress))
				break;

			var dedupe = returnAddress ^ (cfa << 1);
			if (!seen.Add(dedupe))
				break;

			sp = cfa;
			ip = returnAddress;
			frames.Add(CreateCoreUnwindFrame(elf, depth, ip, sp, fp, strategy));
			depth++;
		}

		return frames.Count > 1;
	}

	private static ElfEhFrameFdeInfo FindEhFrameFdeByAddress(List<ElfEhFrameFdeInfo> fdeEntries, ulong address)
	{
		ElfEhFrameFdeInfo best = null;
		for (var i = 0; i < fdeEntries.Count; i++)
		{
			var fde = fdeEntries[i];
			if (!fde.CfaRuleAvailable || !fde.ReturnAddressOffsetAvailable)
				continue;

			if (fde.InitialLocation == 0 && fde.EndLocation == 0)
				continue;

			if (address >= fde.InitialLocation && address < fde.EndLocation)
				return fde;

			if (address >= fde.InitialLocation)
				best = fde;
		}

		return best;
	}

	private static bool TryResolveCfaBaseRegister(
		ushort machine,
		ulong cfaRegister,
		ulong sp,
		ulong? fp,
		out ulong value)
	{
		value = 0;
		switch (machine)
		{
			case EmX86_64:
				if (cfaRegister == 7)
				{
					value = sp;
					return true;
				}
				if (cfaRegister == 6 && fp.HasValue)
				{
					value = fp.Value;
					return true;
				}
				return false;
			case Em386:
				if (cfaRegister == 4)
				{
					value = sp;
					return true;
				}
				if (cfaRegister == 5 && fp.HasValue)
				{
					value = fp.Value;
					return true;
				}
				return false;
			case EmAArch64:
				if (cfaRegister == 31)
				{
					value = sp;
					return true;
				}
				if (cfaRegister == 29 && fp.HasValue)
				{
					value = fp.Value;
					return true;
				}
				return false;
			case EmArm:
				if (cfaRegister == 13)
				{
					value = sp;
					return true;
				}
				if (cfaRegister == 11 && fp.HasValue)
				{
					value = fp.Value;
					return true;
				}
				return false;
				case EmPpc:
				case EmPpc64:
					if (cfaRegister == 1)
					{
						value = sp;
						return true;
					}
					if (cfaRegister == 31 && fp.HasValue)
					{
						value = fp.Value;
						return true;
					}
					return false;
				case EmS390:
					if (cfaRegister == 15)
					{
						value = sp;
						return true;
					}
					if (cfaRegister == 11 && fp.HasValue)
					{
						value = fp.Value;
						return true;
					}
					return false;
			case EmRiscV:
				if (cfaRegister == 2)
				{
					value = sp;
					return true;
				}
				if (cfaRegister == 8 && fp.HasValue)
				{
					value = fp.Value;
					return true;
				}
				return false;
			case EmMips:
				if (cfaRegister == 29)
				{
					value = sp;
					return true;
				}
				if (cfaRegister == 30 && fp.HasValue)
				{
					value = fp.Value;
					return true;
				}
				return false;
				case EmSparc:
				case EmSparc64:
					if (cfaRegister == 14)
					{
					value = sp;
					return true;
				}
				if (cfaRegister == 30 && fp.HasValue)
				{
					value = fp.Value;
					return true;
					}
					return false;
				case EmLoongArch:
					if (cfaRegister == 3)
					{
						value = sp;
						return true;
					}
					if (cfaRegister == 22 && fp.HasValue)
					{
						value = fp.Value;
						return true;
					}
					return false;
				default:
					return false;
			}
		}

	private static bool TryApplySignedOffset(ulong baseValue, long offset, out ulong value)
	{
		value = 0;
		try
		{
			value = offset >= 0
				? checked(baseValue + (ulong)offset)
				: checked(baseValue - (ulong)(-offset));
			return true;
		}
		catch (OverflowException)
		{
			return false;
		}
	}

	private static bool TryUnwindByFramePointer(
		IEndianDataSource data,
		ElfFile elf,
		List<CoreMemorySegment> segments,
		ulong initialIp,
		ulong initialSp,
		ulong? initialFp,
		int wordSize,
		List<ElfCoreUnwindFrameInfo> frames,
		string strategy)
	{
		if (!initialFp.HasValue || initialFp.Value == 0)
			return false;
		if (segments.Count == 0)
			return false;
		if (wordSize is not (4 or 8))
			return false;

		var ip = initialIp;
		var sp = initialSp;
		var fp = initialFp.Value;
		var depth = 1;
		var maxDepth = 64;

		while (depth < maxDepth)
		{
			if (!TryReadCoreMemoryWord(data, elf.Header.IsLittleEndian, wordSize, segments, fp, out var nextFp))
				break;
			if (!TryReadCoreMemoryWord(data, elf.Header.IsLittleEndian, wordSize, segments, checked(fp + (ulong)wordSize), out var returnAddress))
				break;

			if (returnAddress == 0)
				break;
			if (nextFp == 0)
			{
				var terminalSp = GetNextStackPointerAfterFrame(elf.Header.Machine, fp, wordSize);
				frames.Add(CreateCoreUnwindFrame(elf, depth, returnAddress, terminalSp, null, strategy));
				break;
			}
			if (nextFp <= fp)
				break;
			if (nextFp - fp > 0x100000UL)
				break;

			var nextSp = GetNextStackPointerAfterFrame(elf.Header.Machine, fp, wordSize);
			ip = returnAddress;
			sp = nextSp;
			fp = nextFp;

			frames.Add(CreateCoreUnwindFrame(elf, depth, ip, sp, fp, strategy));
			depth++;
		}

		return frames.Count > 1;
	}

	private static ulong GetNextStackPointerAfterFrame(ushort machine, ulong framePointer, int wordSize)
	{
		return machine switch
		{
			EmAArch64 => checked(framePointer + 16UL),
			_ => checked(framePointer + ((ulong)wordSize * 2UL))
		};
	}

	private static bool TryUnwindByStackScan(
		IEndianDataSource data,
		ElfFile elf,
		List<CoreMemorySegment> segments,
		ulong initialSp,
		int wordSize,
		List<ElfCoreUnwindFrameInfo> frames,
		string strategy)
	{
		var initialFrameCount = frames.Count;
		if (wordSize is not (4 or 8))
			return false;
		if (initialSp == 0)
			return false;
		if (segments.Count == 0)
			return false;

		var maxWords = 1024;
		var depth = frames.Count;
		var maxDepth = 32;
		var cursor = initialSp;
		var seen = new HashSet<ulong>();

		for (var i = 0; i < maxWords && depth < maxDepth; i++)
		{
			if (!TryReadCoreMemoryWord(data, elf.Header.IsLittleEndian, wordSize, segments, cursor, out var candidate))
				break;

			if (candidate != 0 && IsExecutableAddress(segments, candidate) && seen.Add(candidate))
			{
				var sp = checked(cursor + (ulong)wordSize);
				frames.Add(CreateCoreUnwindFrame(elf, depth, candidate, sp, null, strategy));
				depth++;
			}

			cursor = checked(cursor + (ulong)wordSize);
		}

		return frames.Count > initialFrameCount;
	}

	private static bool TryReadCoreMemoryWord(
		IEndianDataSource data,
		bool isLittleEndian,
		int wordSize,
		List<CoreMemorySegment> segments,
		ulong virtualAddress,
		out ulong value)
	{
		value = 0;
		var segment = FindCoreMemorySegment(segments, virtualAddress);
		if (segment == null)
			return false;

		var relative = virtualAddress - segment.VirtualStart;
		if (relative > segment.FileSize)
			return false;
		if ((ulong)wordSize > segment.FileSize - relative)
			return false;

		var fileOffset = segment.FileOffset + relative;
		if (fileOffset > data.Length || (ulong)wordSize > data.Length - fileOffset)
			return false;

		if (wordSize is not (4 or 8))
			return false;

		Span<byte> buffer = stackalloc byte[8];
		var target = buffer.Slice(0, wordSize);
		data.ReadAt(fileOffset, target);
		value = wordSize == 4
			? (isLittleEndian
				? BinaryPrimitives.ReadUInt32LittleEndian(target)
				: BinaryPrimitives.ReadUInt32BigEndian(target))
			: (isLittleEndian
				? BinaryPrimitives.ReadUInt64LittleEndian(target)
				: BinaryPrimitives.ReadUInt64BigEndian(target));
		return true;
	}

	private static CoreMemorySegment FindCoreMemorySegment(List<CoreMemorySegment> segments, ulong address)
	{
		for (var i = 0; i < segments.Count; i++)
		{
			var segment = segments[i];
			if (address < segment.VirtualStart || address >= segment.VirtualEnd)
				continue;
			return segment;
		}

		return null;
	}

	private static bool IsExecutableAddress(List<CoreMemorySegment> segments, ulong address)
	{
		for (var i = 0; i < segments.Count; i++)
		{
			var segment = segments[i];
			if (!segment.Executable)
				continue;
			if (address >= segment.VirtualStart && address < segment.VirtualEnd)
				return true;
		}

		return false;
	}

	private static ElfCoreUnwindFrameInfo CreateCoreUnwindFrame(
		ElfFile elf,
		int index,
		ulong ip,
		ulong sp,
		ulong? fp,
		string strategy)
	{
		return new ElfCoreUnwindFrameInfo
		{
			Index = index,
			InstructionPointer = ip,
			StackPointer = sp,
			FramePointer = fp,
			SymbolName = ResolveSymbolNameByAddress(elf, ip),
			Strategy = strategy
		};
	}

	private static string ResolveSymbolNameByAddress(ElfFile elf, ulong address)
	{
		if (address == 0)
			return string.Empty;

		ElfSymbol best = null;
		ulong bestDistance = ulong.MaxValue;
		for (var i = 0; i < elf.Symbols.Count; i++)
		{
			var symbol = elf.Symbols[i];
			if (string.IsNullOrEmpty(symbol.Name) || symbol.Value == 0)
				continue;
			if (symbol.Value > address)
				continue;

			var size = symbol.Size;
			if (size > 0 && address < symbol.Value + size)
				return symbol.QualifiedName ?? symbol.Name;

			var distance = address - symbol.Value;
			if (distance < bestDistance)
			{
				bestDistance = distance;
				best = symbol;
			}
		}

		return best?.QualifiedName ?? best?.Name ?? string.Empty;
	}
}
