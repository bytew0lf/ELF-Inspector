namespace ELFInspector.Parser;

public class ElfSectionHeader
{
	public uint NameIndex { get; set; }
	public string Name { get; set; }
	public uint Type { get; set; }
	public ulong Flags { get; set; }
	public ulong Address { get; set; }
	public ulong Offset { get; set; }
	public ulong Size { get; set; }
	public uint Link { get; set; }
	public uint Info { get; set; }
	public ulong AddressAlign { get; set; }
	public ulong EntrySize { get; set; }
}
