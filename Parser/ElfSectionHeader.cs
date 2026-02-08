namespace ELFInspector.Parser;

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfSectionHeader
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint NameIndex { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public string Name { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint Type { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Flags { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Address { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Offset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Size { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint Link { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint Info { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong AddressAlign { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong EntrySize { get; set; }
}
