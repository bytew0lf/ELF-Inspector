using ELFInspector.Endianness;

namespace ELFInspector.Parser;

/// <summary>
/// Represents a public API member.
/// </summary>
public enum ElfClass : byte
{
	/// <summary>
	/// No class specified.
	/// </summary>
	None = 0,
	/// <summary>
	/// 32-bit ELF object.
	/// </summary>
	Elf32 = 1,
	/// <summary>
	/// 64-bit ELF object.
	/// </summary>
	Elf64 = 2
}

/// <summary>
/// Represents a public API member.
/// </summary>
public enum ElfData : byte
{
	/// <summary>
	/// No data encoding specified.
	/// </summary>
	None = 0,
	/// <summary>
	/// Little-endian byte order.
	/// </summary>
	LittleEndian = 1,
	/// <summary>
	/// Big-endian byte order.
	/// </summary>
	BigEndian = 2
}

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfHeader
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ElfClass Class { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ElfData DataEncoding { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public bool IsLittleEndian => DataEncoding == ElfData.LittleEndian;
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte IdentVersion { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte OsAbi { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte AbiVersion { get; set; }

	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ushort Type { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ushort Machine { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint Version { get; set; }

	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong EntryPoint { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong ProgramHeaderOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong SectionHeaderOffset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint Flags { get; set; }

	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ushort HeaderSize { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ushort ProgramHeaderEntrySize { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ushort ProgramHeaderCount { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ushort SectionHeaderEntrySize { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ushort SectionHeaderCount { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ushort SectionHeaderStringIndex { get; set; }
}
