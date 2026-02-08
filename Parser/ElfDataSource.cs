using System.IO.MemoryMappedFiles;

namespace ELFInspector.Parser;

internal static class ElfDataSourceFactory
{
	public static IDisposableEndianDataSource CreateInMemory(ReadOnlySpan<byte> data)
	{
		return new InMemoryElfDataSource(data.ToArray());
	}

	public static IDisposableEndianDataSource CreateInMemory(byte[] data)
	{
		return new InMemoryElfDataSource(data ?? Array.Empty<byte>());
	}

	public static IDisposableEndianDataSource CreateStream(string filePath)
	{
		return new StreamElfDataSource(filePath);
	}

	public static IDisposableEndianDataSource CreateMemoryMapped(string filePath)
	{
		return new MemoryMappedElfDataSource(filePath);
	}
}

internal interface IDisposableEndianDataSource : IEndianDataSource, IDisposable
{
}

internal sealed class InMemoryElfDataSource : IDisposableEndianDataSource
{
	private readonly byte[] _data;

	public InMemoryElfDataSource(byte[] data)
	{
		_data = data ?? Array.Empty<byte>();
	}

	public ulong Length => (ulong)_data.LongLength;

	public void ReadAt(ulong offset, Span<byte> destination)
	{
		if (offset > Length || (ulong)destination.Length > Length - offset)
			throw new InvalidDataException("Read exceeds data bounds.");
		if (offset > int.MaxValue)
			throw new InvalidDataException("In-memory data source offset exceeds 32-bit span bounds.");

		_data.AsSpan((int)offset, destination.Length).CopyTo(destination);
	}

	public void Dispose()
	{
	}
}

internal sealed class StreamElfDataSource : IDisposableEndianDataSource
{
	private readonly FileStream _stream;

	public StreamElfDataSource(string filePath)
	{
		_stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024, FileOptions.SequentialScan);
	}

	public ulong Length => checked((ulong)_stream.Length);

	public void ReadAt(ulong offset, Span<byte> destination)
	{
		if (offset > Length || (ulong)destination.Length > Length - offset)
			throw new InvalidDataException("Read exceeds data bounds.");

		_stream.Seek((long)offset, SeekOrigin.Begin);
		var totalRead = 0;
		while (totalRead < destination.Length)
		{
			var read = _stream.Read(destination.Slice(totalRead));
			if (read <= 0)
				throw new InvalidDataException("Unexpected end of stream.");
			totalRead += read;
		}
	}

	public void Dispose()
	{
		_stream.Dispose();
	}
}

internal sealed unsafe class MemoryMappedElfDataSource : IDisposableEndianDataSource
{
	private readonly MemoryMappedFile _memoryMappedFile;
	private readonly MemoryMappedViewAccessor _viewAccessor;
	private readonly byte* _rawPointer;
	private readonly byte* _basePointer;
	private readonly ulong _length;
	private bool _disposed;

	public MemoryMappedElfDataSource(string filePath)
	{
		var length = new FileInfo(filePath).Length;
		_length = checked((ulong)Math.Max(0L, length));
		_memoryMappedFile = MemoryMappedFile.CreateFromFile(filePath, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
		_viewAccessor = _memoryMappedFile.CreateViewAccessor(0, length, MemoryMappedFileAccess.Read);

		byte* pointer = null;
		_viewAccessor.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);
		if (pointer == null)
			throw new InvalidOperationException("Failed to acquire memory-mapped pointer.");

		_rawPointer = pointer;
		_basePointer = pointer + _viewAccessor.PointerOffset;
	}

	public ulong Length => _length;

	public void ReadAt(ulong offset, Span<byte> destination)
	{
		if (_disposed)
			throw new ObjectDisposedException(nameof(MemoryMappedElfDataSource));
		if (offset > Length || (ulong)destination.Length > Length - offset)
			throw new InvalidDataException("Read exceeds data bounds.");
		if (offset > long.MaxValue)
			throw new InvalidDataException("Offset exceeds supported memory map range.");

		var start = _basePointer + (nint)offset;
		new ReadOnlySpan<byte>(start, destination.Length).CopyTo(destination);
	}

	public void Dispose()
	{
		if (_disposed)
			return;

		_viewAccessor.SafeMemoryMappedViewHandle.ReleasePointer();
		_viewAccessor.Dispose();
		_memoryMappedFile.Dispose();
		_disposed = true;
	}
}
