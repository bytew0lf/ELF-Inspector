namespace ELFInspector.Endianness;

public ref struct EndianBinaryReader
{
	private readonly ReadOnlySpan<byte> _data;
	private readonly bool _isLittle;
	private int _position;

	public int Position
	{
		get => _position;
		set
		{
			if ((uint)value > (uint)_data.Length)
				throw new InvalidDataException("Reader position exceeds data bounds.");

			_position = value;
		}
	}

	public EndianBinaryReader(ReadOnlySpan<byte> data, bool isLittle)
	{
		_data = data;
		_isLittle = isLittle;
		_position = 0;
	}

	public ushort ReadUInt16()
	{
		EnsureCanRead(2);
		var val = _isLittle
			? BinaryPrimitives.ReadUInt16LittleEndian(_data.Slice(_position, 2))
			: BinaryPrimitives.ReadUInt16BigEndian(_data.Slice(_position, 2));
		_position += 2;
		return val;
	}

	public uint ReadUInt32()
	{
		EnsureCanRead(4);
		var val = _isLittle
			? BinaryPrimitives.ReadUInt32LittleEndian(_data.Slice(_position, 4))
			: BinaryPrimitives.ReadUInt32BigEndian(_data.Slice(_position, 4));
		_position += 4;
		return val;
	}

	public ulong ReadUInt64()
	{
		EnsureCanRead(8);
		var val = _isLittle
			? BinaryPrimitives.ReadUInt64LittleEndian(_data.Slice(_position, 8))
			: BinaryPrimitives.ReadUInt64BigEndian(_data.Slice(_position, 8));
		_position += 8;
		return val;
	}

	public byte ReadByte()
	{
		EnsureCanRead(1);
		var value = _data[_position];
		_position += 1;
		return value;
	}

	public void Skip(int count)
	{
		if (count < 0)
			throw new InvalidDataException("Reader skip count must be non-negative.");

		Position = checked(_position + count);
	}

	private void EnsureCanRead(int byteCount)
	{
		if (byteCount < 0)
			throw new InvalidDataException("Reader byte count must be non-negative.");
		if (_position < 0 || byteCount > _data.Length - _position)
			throw new InvalidDataException("Reader attempted to read beyond available data.");
	}
}
