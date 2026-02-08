namespace ELFInspector.Endianness;

public interface IEndianDataSource
{
	ulong Length { get; }
	void ReadAt(ulong offset, Span<byte> destination);
}
