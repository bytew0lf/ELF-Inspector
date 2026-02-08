namespace ELFInspector.Endianness;

/// <summary>
/// Represents a public API member.
/// </summary>
public interface IEndianDataSource
{
	/// <summary>
	/// Gets the total readable byte length.
	/// </summary>
	ulong Length { get; }

	/// <summary>
	/// Reads bytes starting at a specific absolute offset into the provided destination buffer.
	/// </summary>
	/// <param name="offset">The absolute byte offset in the source.</param>
	/// <param name="destination">The destination buffer to fill.</param>
	void ReadAt(ulong offset, Span<byte> destination);
}
