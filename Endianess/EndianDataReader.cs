namespace ELFInspector.Endianness;

/// <summary>
/// Represents a public API member.
/// </summary>
public ref struct EndianDataReader
{
	private readonly IEndianDataSource _data;
	private readonly bool _isLittle;
	private ulong _position;

	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong Position
	{
		get => _position;
		set
		{
			if (value > _data.Length)
				throw new InvalidDataException("Reader position exceeds data bounds.");

			_position = value;
		}
	}

	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public EndianDataReader(IEndianDataSource data, bool isLittle)
	{
		_data = data ?? throw new ArgumentNullException(nameof(data));
		_isLittle = isLittle;
		_position = 0;
	}

	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ushort ReadUInt16()
	{
		EnsureCanRead(2);
		Span<byte> buffer = stackalloc byte[2];
		_data.ReadAt(_position, buffer);
		_position += 2;
		return _isLittle
			? BinaryPrimitives.ReadUInt16LittleEndian(buffer)
			: BinaryPrimitives.ReadUInt16BigEndian(buffer);
	}

	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public uint ReadUInt32()
	{
		EnsureCanRead(4);
		Span<byte> buffer = stackalloc byte[4];
		_data.ReadAt(_position, buffer);
		_position += 4;
		return _isLittle
			? BinaryPrimitives.ReadUInt32LittleEndian(buffer)
			: BinaryPrimitives.ReadUInt32BigEndian(buffer);
	}

	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public ulong ReadUInt64()
	{
		EnsureCanRead(8);
		Span<byte> buffer = stackalloc byte[8];
		_data.ReadAt(_position, buffer);
		_position += 8;
		return _isLittle
			? BinaryPrimitives.ReadUInt64LittleEndian(buffer)
			: BinaryPrimitives.ReadUInt64BigEndian(buffer);
	}

	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public byte ReadByte()
	{
		EnsureCanRead(1);
		Span<byte> buffer = stackalloc byte[1];
		_data.ReadAt(_position, buffer);
		_position += 1;
		return buffer[0];
	}

	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public void Skip(ulong count)
	{
		Position = checked(_position + count);
	}

	private void EnsureCanRead(ulong byteCount)
	{
		if (byteCount > _data.Length - _position)
			throw new InvalidDataException("Reader attempted to read beyond available data.");
	}
}
