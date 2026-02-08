using ELFInspector.Endianness;

namespace ELFInspector.Parser;

public enum ElfClass : byte
{
	None = 0,
	Elf32 = 1,
	Elf64 = 2
}

public enum ElfData : byte
{
	None = 0,
	LittleEndian = 1,
	BigEndian = 2
}

public class ElfHeader
{
	public ElfClass Class { get; set; }
	public ElfData DataEncoding { get; set; }
	public bool IsLittleEndian => DataEncoding == ElfData.LittleEndian;
	public byte IdentVersion { get; set; }
	public byte OsAbi { get; set; }
	public byte AbiVersion { get; set; }

	public ushort Type { get; set; }
	public ushort Machine { get; set; }
	public uint Version { get; set; }

	public ulong EntryPoint { get; set; }
	public ulong ProgramHeaderOffset { get; set; }
	public ulong SectionHeaderOffset { get; set; }
	public uint Flags { get; set; }

	public ushort HeaderSize { get; set; }
	public ushort ProgramHeaderEntrySize { get; set; }
	public ushort ProgramHeaderCount { get; set; }
	public ushort SectionHeaderEntrySize { get; set; }
	public ushort SectionHeaderCount { get; set; }
	public ushort SectionHeaderStringIndex { get; set; }
}
