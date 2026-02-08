namespace ELFInspector.Parser;

/// <summary>
/// Represents a public API member.
/// </summary>
public static partial class ElfReader
{
	private static bool TryVirtualAddressToFileOffset(ElfFile elf, ulong virtualAddress, out ulong fileOffset)
	{
		fileOffset = 0;
		foreach (var programHeader in elf.ProgramHeaders)
		{
			if (programHeader.Type != PtLoad || programHeader.FileSize == 0)
				continue;

			var start = programHeader.VirtualAddress;
			var end = start + programHeader.FileSize;
			if (end < start)
				end = ulong.MaxValue;

			if (virtualAddress < start || virtualAddress >= end)
				continue;

			var delta = virtualAddress - start;
			fileOffset = programHeader.Offset + delta;
			return true;
		}

		return false;
	}

	private static bool TryMapVirtualRangeToFile(ElfFile elf, ulong virtualAddress, ulong size, out ulong fileOffset)
	{
		fileOffset = 0;
		if (!TryVirtualAddressToFileOffset(elf, virtualAddress, out var candidateOffset))
			return false;
		if (!TryGetMappedFileRange(elf, virtualAddress, out _, out var maxSize))
			return false;
		if (size > maxSize)
			return false;

		fileOffset = candidateOffset;
		return true;
	}

	private static bool TryGetMappedFileRange(ElfFile elf, ulong virtualAddress, out ulong fileOffset, out ulong maxSize)
	{
		fileOffset = 0;
		maxSize = 0;

		foreach (var programHeader in elf.ProgramHeaders)
		{
			if (programHeader.Type != PtLoad || programHeader.FileSize == 0)
				continue;

			var start = programHeader.VirtualAddress;
			var end = start + programHeader.FileSize;
			if (end < start)
				end = ulong.MaxValue;

			if (virtualAddress < start || virtualAddress >= end)
				continue;

			var delta = virtualAddress - start;
			fileOffset = programHeader.Offset + delta;
			maxSize = programHeader.FileSize - delta;
			return true;
		}

		return false;
	}
}
