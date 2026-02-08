namespace ELFInspector.Parser;

public class ElfProgramHeader
{
	public uint Type { get; set; }
	public uint Flags { get; set; }
	public ulong Offset { get; set; }
	public ulong VirtualAddress { get; set; }
	public ulong PhysicalAddress { get; set; }
	public ulong FileSize { get; set; }
	public ulong MemorySize { get; set; }
	public ulong Align { get; set; }
}
