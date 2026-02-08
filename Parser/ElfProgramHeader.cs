namespace ELFInspector.Parser;

/// <summary>
/// Represents a public API member.
/// </summary>
public class ElfProgramHeader
{
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint Type { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint Flags { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Offset { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong VirtualAddress { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong PhysicalAddress { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong FileSize { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong MemorySize { get; set; }
	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Align { get; set; }
}
