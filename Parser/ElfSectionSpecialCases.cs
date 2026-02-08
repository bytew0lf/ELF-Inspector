using System.IO.Compression;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ELFInspector.Parser;

/// <summary>
/// Represents a public API member.
/// </summary>
public static partial class ElfReader
{
	private const ulong ShfCompressedSection = 0x800;
	private const uint ElfCompressZlib = 1;
	private const uint ElfCompressZstd = 2;
	private const uint GrpComdat = 0x1;
	private const uint ShtGroup = 17;
	private const ulong MaxSectionDecompressionSize = 256UL * 1024UL * 1024UL;
	private const uint ZstdFrameMagic = 0xFD2FB528;
	private const uint ZstdSkippableFrameMagicStart = 0x184D2A50;
	private const uint ZstdSkippableFrameMagicEnd = 0x184D2A5F;
	private const ulong ZstdContentSizeUnknown = ulong.MaxValue;
	private const ulong ZstdContentSizeError = ulong.MaxValue - 1UL;

	private static readonly object ZstdInitLock = new();
	private static bool s_zstdProbed;
	private static bool s_zstdAvailable;
	private static string s_zstdUnavailableReason = "libzstd not initialized.";
	private static ZstdGetFrameContentSizeDelegate s_zstdGetFrameContentSize;
	private static ZstdDecompressDelegate s_zstdDecompress;
	private static ZstdIsErrorDelegate s_zstdIsError;
	private static ZstdGetErrorNameDelegate s_zstdGetErrorName;
	private static ZstdCreateDStreamDelegate s_zstdCreateDStream;
	private static ZstdFreeDStreamDelegate s_zstdFreeDStream;
	private static ZstdInitDStreamDelegate s_zstdInitDStream;
	private static ZstdDecompressStreamDelegate s_zstdDecompressStream;

	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	private delegate ulong ZstdGetFrameContentSizeDelegate(IntPtr src, nuint srcSize);
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	private delegate nuint ZstdDecompressDelegate(IntPtr dst, nuint dstCapacity, IntPtr src, nuint srcSize);
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	private delegate nuint ZstdIsErrorDelegate(nuint code);
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	private delegate IntPtr ZstdGetErrorNameDelegate(nuint code);
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	private delegate IntPtr ZstdCreateDStreamDelegate();
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	private delegate nuint ZstdFreeDStreamDelegate(IntPtr dstream);
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	private delegate nuint ZstdInitDStreamDelegate(IntPtr dstream);
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	private delegate nuint ZstdDecompressStreamDelegate(IntPtr dstream, ref ZstdOutBuffer output, ref ZstdInBuffer input);

	[StructLayout(LayoutKind.Sequential)]
	private struct ZstdInBuffer
	{
		/// <summary>
		/// Represents a public API member.
		/// </summary>
		public IntPtr src;
		/// <summary>
		/// Represents a public API member.
		/// </summary>
		public nuint size;
		/// <summary>
		/// Represents a public API member.
		/// </summary>
		public nuint pos;
	}

	[StructLayout(LayoutKind.Sequential)]
	private struct ZstdOutBuffer
	{
		/// <summary>
		/// Represents a public API member.
		/// </summary>
		public IntPtr dst;
		/// <summary>
		/// Represents a public API member.
		/// </summary>
		public nuint size;
		/// <summary>
		/// Represents a public API member.
		/// </summary>
		public nuint pos;
	}

	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public static void ParseSectionSpecialCases(IEndianDataSource data, ElfFile elf)
	{
		elf.CompressedSections.Clear();
		elf.SectionGroups.Clear();

		ParseCompressedSections(data, elf);
		ParseSectionGroups(data, elf);
	}

	/// <summary>
	/// Represents a public API member.
	/// </summary>
	public static void ParseSectionSpecialCases(ReadOnlySpan<byte> data, ElfFile elf)
	{
		using var source = ElfDataSourceFactory.CreateInMemory(data);
		ParseSectionSpecialCases(source, elf);
	}

	private static void ParseCompressedSections(IEndianDataSource data, ElfFile elf)
	{
		foreach (var section in elf.Sections)
		{
			var isFlagCompressed = (section.Flags & ShfCompressedSection) != 0;
			var isGnuCompressed = !string.IsNullOrEmpty(section.Name) && section.Name.StartsWith(".zdebug", StringComparison.Ordinal);
			if (!isFlagCompressed && !isGnuCompressed)
				continue;

			var compressedInfo = new ElfCompressedSection
			{
				Name = section.Name ?? string.Empty,
				CompressionType = 0,
				CompressionTypeName = "UNKNOWN",
				CompressedSize = section.Size,
				UncompressedSize = 0,
				Alignment = section.AddressAlign,
				IsGnuStyleZdebug = isGnuCompressed,
				DecompressionSucceeded = false,
				Error = string.Empty
			};

			var canRead = TryReadSectionPayload(
				data,
				elf,
				section,
				out var payload,
				out var isCompressed,
				out var compressionType,
				out var declaredUncompressedSize,
				out var compressionAlignment,
				out var isGnuStyleZdebug,
				out var error);

			if (isCompressed)
			{
				compressedInfo.CompressionType = compressionType;
				compressedInfo.CompressionTypeName = GetCompressionTypeName(compressionType, isGnuStyleZdebug);
				compressedInfo.UncompressedSize = declaredUncompressedSize;
				compressedInfo.Alignment = compressionAlignment;
				compressedInfo.IsGnuStyleZdebug = isGnuStyleZdebug;
			}

			compressedInfo.DecompressionSucceeded = canRead;
			compressedInfo.Error = canRead ? string.Empty : error;
			if (canRead && compressedInfo.UncompressedSize == 0)
				compressedInfo.UncompressedSize = (ulong)payload.Length;

			elf.CompressedSections.Add(compressedInfo);
		}
	}

	private static void ParseSectionGroups(IEndianDataSource data, ElfFile elf)
	{
		foreach (var section in elf.Sections)
		{
			if (section.Type != ShtGroup || section.Size < 4)
				continue;

			EnsureReadableRange(data, section.Offset, section.Size, "SHT_GROUP section");
			var entryCount = section.Size / 4UL;
			EnsureReasonableEntryCount(entryCount, "SHT_GROUP entries");

			var reader = new EndianDataReader(data, elf.Header.IsLittleEndian)
			{
				Position = section.Offset
			};

			var flags = reader.ReadUInt32();
			var group = new ElfSectionGroup
			{
				Name = section.Name ?? string.Empty,
				Flags = flags,
				IsComdat = (flags & GrpComdat) != 0,
				SignatureSymbolIndex = section.Info,
				SignatureSymbolName = string.Empty
			};

			for (ulong i = 1; i < entryCount; i++)
			{
				reader.Position = checked(section.Offset + (i * 4UL));
				var memberSectionIndex = reader.ReadUInt32();
				group.MemberSectionIndexes.Add(memberSectionIndex);
				group.MemberSectionNames.Add(ResolveSectionName(elf, memberSectionIndex));
			}

			var signatureSymbol = elf.Symbols.FirstOrDefault(symbol =>
				symbol.TableSectionIndex == section.Link && symbol.Index == section.Info);
			if (signatureSymbol != null)
				group.SignatureSymbolName = signatureSymbol.Name ?? string.Empty;

			elf.SectionGroups.Add(group);
		}
	}

	private static string GetCompressionTypeName(uint compressionType, bool isGnuStyleZdebug)
	{
		if (isGnuStyleZdebug)
		{
			return compressionType switch
			{
				ElfCompressZlib => "ELFCOMPRESS_ZLIB (GNU)",
				ElfCompressZstd => "ELFCOMPRESS_ZSTD (GNU)",
				_ => "GNU-ZDEBUG"
			};
		}

		return compressionType switch
		{
			ElfCompressZlib => "ELFCOMPRESS_ZLIB",
			ElfCompressZstd => "ELFCOMPRESS_ZSTD",
			_ => $"ELFCOMPRESS_{compressionType}"
		};
	}

	private static bool TryReadSectionPayload(
		IEndianDataSource data,
		ElfFile elf,
		ElfSectionHeader section,
		out byte[] payload,
		out bool isCompressed,
		out uint compressionType,
		out ulong declaredUncompressedSize,
		out ulong compressionAlignment,
		out bool isGnuStyleZdebug,
		out string error)
	{
		payload = Array.Empty<byte>();
		error = string.Empty;
		isCompressed = false;
		compressionType = 0;
		declaredUncompressedSize = section.Size;
		compressionAlignment = section.AddressAlign;
		isGnuStyleZdebug = false;

		if (section.Size == 0)
			return true;

		EnsureReadableRange(data, section.Offset, section.Size, "section data");

		var isFlagCompressed = (section.Flags & ShfCompressedSection) != 0;
		var isGnuCompressed = !string.IsNullOrEmpty(section.Name) && section.Name.StartsWith(".zdebug", StringComparison.Ordinal);
		if (!isFlagCompressed && !isGnuCompressed)
		{
			if (!TryGetManagedBufferLength(section.Size, "section payload", out _, out error))
				return false;

			payload = ReadBytes(data, section.Offset, section.Size, "section payload");
			return true;
		}

		isCompressed = true;
		isGnuStyleZdebug = isGnuCompressed;

		if (isFlagCompressed)
		{
			var compressionHeaderSize = elf.Header.Class == ElfClass.Elf32 ? 12UL : 24UL;
			if (section.Size < compressionHeaderSize)
			{
				error = "Compressed section header is truncated.";
				return false;
			}

			var reader = new EndianDataReader(data, elf.Header.IsLittleEndian)
			{
				Position = section.Offset
			};

			if (elf.Header.Class == ElfClass.Elf32)
			{
				compressionType = reader.ReadUInt32();
				declaredUncompressedSize = reader.ReadUInt32();
				compressionAlignment = reader.ReadUInt32();
			}
			else
			{
				compressionType = reader.ReadUInt32();
				reader.ReadUInt32(); // ch_reserved
				declaredUncompressedSize = reader.ReadUInt64();
				compressionAlignment = reader.ReadUInt64();
			}

				var compressedPayloadOffset = checked(section.Offset + compressionHeaderSize);
				var compressedPayloadSize = section.Size - compressionHeaderSize;
				EnsureReadableRange(data, compressedPayloadOffset, compressedPayloadSize, "compressed section payload");
				if (!TryGetManagedBufferLength(compressedPayloadSize, "compressed section payload", out _, out error))
					return false;

				if (compressionType == ElfCompressZlib)
				{
					var compressedPayload = ReadBytes(data, compressedPayloadOffset, compressedPayloadSize, "compressed section payload");
					return TryDecompressZlibPayload(compressedPayload, declaredUncompressedSize, out payload, out error);
			}

			if (compressionType == ElfCompressZstd)
			{
				var compressedPayload = ReadBytes(data, compressedPayloadOffset, compressedPayloadSize, "compressed section payload");
				return TryDecompressZstdPayload(
					compressedPayload,
					declaredUncompressedSize,
					elf.ParseOptions ?? ElfParseOptions.StrictDefault,
					out payload,
					out error);
			}

			error = $"Unsupported ELF compression type: {compressionType}.";
			return false;
		}

		if (section.Size < 12)
		{
			error = "GNU .zdebug section is too small.";
			return false;
		}

		var zdebugHeader = ReadBytes(data, section.Offset, 12, "GNU .zdebug header");
		var isZlibHeader = zdebugHeader[0] == (byte)'Z' && zdebugHeader[1] == (byte)'L' && zdebugHeader[2] == (byte)'I' && zdebugHeader[3] == (byte)'B';
		var isZstdHeader = zdebugHeader[0] == (byte)'Z' && zdebugHeader[1] == (byte)'S' && zdebugHeader[2] == (byte)'T' && zdebugHeader[3] == (byte)'D';
		if (!isZlibHeader && !isZstdHeader)
		{
			error = "GNU .zdebug section has an invalid header.";
			return false;
		}

			compressionType = isZstdHeader ? ElfCompressZstd : ElfCompressZlib;
			declaredUncompressedSize = BinaryPrimitives.ReadUInt64BigEndian(zdebugHeader.AsSpan(4, 8));
			var gnuPayloadOffset = checked(section.Offset + 12UL);
			var gnuPayloadSize = section.Size - 12UL;
			EnsureReadableRange(data, gnuPayloadOffset, gnuPayloadSize, "GNU .zdebug payload");
			if (!TryGetManagedBufferLength(gnuPayloadSize, "GNU .zdebug payload", out _, out error))
				return false;

			var gnuPayload = ReadBytes(data, gnuPayloadOffset, gnuPayloadSize, "GNU .zdebug payload");
		if (compressionType == ElfCompressZstd)
		{
			return TryDecompressZstdPayload(
				gnuPayload,
				declaredUncompressedSize,
				elf.ParseOptions ?? ElfParseOptions.StrictDefault,
				out payload,
				out error);
		}

		return TryDecompressZlibPayload(gnuPayload, declaredUncompressedSize, out payload, out error);
	}

	private static bool TryDecompressZlibPayload(ReadOnlySpan<byte> compressedPayload, ulong expectedSize, out byte[] payload, out string error)
	{
		payload = Array.Empty<byte>();
		error = string.Empty;

		if (expectedSize > MaxSectionDecompressionSize)
		{
			error = $"Uncompressed payload exceeds safety limit ({MaxSectionDecompressionSize} bytes).";
			return false;
		}

		try
		{
			using var input = new MemoryStream(compressedPayload.ToArray());
			using var stream = new ZLibStream(input, CompressionMode.Decompress, leaveOpen: false);
			using var output = new MemoryStream();
			stream.CopyTo(output);

			var decompressed = output.ToArray();
			if ((ulong)decompressed.Length > MaxSectionDecompressionSize)
			{
				error = $"Uncompressed payload exceeds safety limit ({MaxSectionDecompressionSize} bytes).";
				return false;
			}

			if (expectedSize != 0 && (ulong)decompressed.Length != expectedSize)
			{
				error = $"Uncompressed payload size mismatch (expected {expectedSize}, got {(ulong)decompressed.Length}).";
				return false;
			}

			payload = decompressed;
			return true;
		}
		catch (Exception ex)
		{
			error = ex.Message;
			return false;
		}
	}

	private static bool TryDecompressZstdPayload(ReadOnlySpan<byte> compressedPayload, ulong expectedSize, ElfParseOptions parseOptions, out byte[] payload, out string error)
	{
		payload = Array.Empty<byte>();
		error = string.Empty;

		if (expectedSize > MaxSectionDecompressionSize)
		{
			error = $"Uncompressed payload exceeds safety limit ({MaxSectionDecompressionSize} bytes).";
			return false;
		}

		if (TryDecompressZstdPayloadNative(compressedPayload, expectedSize, out payload, out error))
			return true;

		var nativeError = error;
		if (TryDecompressZstdPayloadExternalTool(compressedPayload, expectedSize, parseOptions, out payload, out error))
			return true;

		var externalError = error;
		if (TryDecompressZstdPayloadRawRleFallback(compressedPayload, expectedSize, out payload, out error))
			return true;

		var details = new List<string>();
		if (!string.IsNullOrEmpty(nativeError))
			details.Add($"native={nativeError}");
		if (!string.IsNullOrEmpty(externalError))
			details.Add($"external={externalError}");
		if (!string.IsNullOrEmpty(error))
			details.Add($"fallback={error}");
		error = string.Join(" | ", details.Where(static detail => !string.IsNullOrEmpty(detail)));
		if (string.IsNullOrEmpty(error))
			error = "ZSTD decompression failed.";

		return false;
	}

	private static bool TryDecompressZstdPayloadNative(ReadOnlySpan<byte> compressedPayload, ulong expectedSize, out byte[] payload, out string error)
	{
		payload = Array.Empty<byte>();
		error = string.Empty;

		if (!TryEnsureZstdNativeLoaded(out var loadError))
		{
			error = loadError;
			return false;
		}

		IntPtr srcPtr = IntPtr.Zero;
		IntPtr outPtr = IntPtr.Zero;
		IntPtr dstream = IntPtr.Zero;
		try
		{
			var srcLength = compressedPayload.Length;
			if (srcLength == 0)
			{
				payload = Array.Empty<byte>();
				return expectedSize == 0;
			}

			srcPtr = Marshal.AllocHGlobal(srcLength);
			Marshal.Copy(compressedPayload.ToArray(), 0, srcPtr, srcLength);

			var frameSize = s_zstdGetFrameContentSize(srcPtr, (nuint)srcLength);
			if (frameSize == ZstdContentSizeError)
			{
				error = "Invalid ZSTD frame.";
				return false;
			}

			if (expectedSize > 0 && expectedSize <= MaxSectionDecompressionSize && expectedSize <= int.MaxValue)
			{
				// Fast path with fixed-size output when the section declares its decompressed size.
				var destinationSize = expectedSize;
				outPtr = Marshal.AllocHGlobal((int)destinationSize);
				var decodedSize = s_zstdDecompress(outPtr, (nuint)destinationSize, srcPtr, (nuint)srcLength);
				if (IsZstdError(decodedSize, out var directError))
				{
					error = $"ZSTD decompression failed: {directError}.";
					return false;
				}

				var actualSize = (ulong)decodedSize;
				if (actualSize != expectedSize)
				{
					error = $"Uncompressed payload size mismatch (expected {expectedSize}, got {actualSize}).";
					return false;
				}

				payload = new byte[(int)actualSize];
				if (payload.Length > 0)
					Marshal.Copy(outPtr, payload, 0, payload.Length);
				return true;
			}

			if (frameSize != ZstdContentSizeUnknown && frameSize <= MaxSectionDecompressionSize && frameSize <= int.MaxValue)
			{
				// Fast path for frames with known content size.
				outPtr = Marshal.AllocHGlobal((int)frameSize);
				var decodedSize = s_zstdDecompress(outPtr, (nuint)frameSize, srcPtr, (nuint)srcLength);
				if (IsZstdError(decodedSize, out var directError))
				{
					error = $"ZSTD decompression failed: {directError}.";
					return false;
				}

				var actualSize = (ulong)decodedSize;
				if (actualSize > MaxSectionDecompressionSize || actualSize > int.MaxValue)
				{
					error = $"Uncompressed payload exceeds safety limit ({MaxSectionDecompressionSize} bytes).";
					return false;
				}

				if (expectedSize != 0 && actualSize != expectedSize)
				{
					error = $"Uncompressed payload size mismatch (expected {expectedSize}, got {actualSize}).";
					return false;
				}

				payload = new byte[(int)actualSize];
				if (payload.Length > 0)
					Marshal.Copy(outPtr, payload, 0, payload.Length);
				return true;
			}

			// Generic path for unknown output sizes and/or multi-frame payloads.
			dstream = s_zstdCreateDStream();
			if (dstream == IntPtr.Zero)
			{
				error = "Failed to allocate ZSTD decompression stream.";
				return false;
			}

			var initResult = s_zstdInitDStream(dstream);
			if (IsZstdError(initResult, out var initError))
			{
				error = $"ZSTD stream initialization failed: {initError}.";
				return false;
			}

			var input = new ZstdInBuffer
			{
				src = srcPtr,
				size = (nuint)srcLength,
				pos = 0
			};
			var outputChunk = new byte[64 * 1024];
			outPtr = Marshal.AllocHGlobal(outputChunk.Length);
			using var output = new MemoryStream();

			ulong iterations = 0;
			nuint previousInputPos = nuint.MaxValue;
			while (input.pos < input.size && iterations < MaxParserEntryCount)
			{
				iterations++;

				var outBuffer = new ZstdOutBuffer
				{
					dst = outPtr,
					size = (nuint)outputChunk.Length,
					pos = 0
				};

				var decodeResult = s_zstdDecompressStream(dstream, ref outBuffer, ref input);
				if (IsZstdError(decodeResult, out var streamError))
				{
					error = $"ZSTD stream decompression failed: {streamError}.";
					return false;
				}

				var produced = (int)outBuffer.pos;
				if (produced > 0)
				{
					Marshal.Copy(outPtr, outputChunk, 0, produced);
					output.Write(outputChunk, 0, produced);
					if ((ulong)output.Length > MaxSectionDecompressionSize)
					{
						error = $"Uncompressed payload exceeds safety limit ({MaxSectionDecompressionSize} bytes).";
						return false;
					}
				}

				if (decodeResult == 0 && input.pos < input.size)
				{
					// End of frame reached while additional frames remain.
					var reinitResult = s_zstdInitDStream(dstream);
					if (IsZstdError(reinitResult, out var reinitError))
					{
						error = $"ZSTD stream reinitialization failed: {reinitError}.";
						return false;
					}
				}

				if (produced == 0 && input.pos == previousInputPos)
				{
					error = "ZSTD stream decoding stalled without making progress.";
					return false;
				}

				previousInputPos = input.pos;
			}

			if (input.pos < input.size)
			{
				error = "ZSTD stream decoding did not consume full input.";
				return false;
			}

			var decompressed = output.ToArray();
			if (expectedSize != 0 && (ulong)decompressed.Length != expectedSize)
			{
				error = $"Uncompressed payload size mismatch (expected {expectedSize}, got {(ulong)decompressed.Length}).";
				return false;
			}

			payload = decompressed;
			return true;
		}
		catch (Exception ex)
		{
			error = ex.Message;
			return false;
		}
		finally
		{
			if (srcPtr != IntPtr.Zero)
				Marshal.FreeHGlobal(srcPtr);
			if (outPtr != IntPtr.Zero)
				Marshal.FreeHGlobal(outPtr);
			if (dstream != IntPtr.Zero)
				s_zstdFreeDStream(dstream);
		}
	}

	private static bool TryEnsureZstdNativeLoaded(out string error)
	{
		lock (ZstdInitLock)
		{
			if (s_zstdProbed)
			{
				error = s_zstdAvailable ? string.Empty : s_zstdUnavailableReason;
				return s_zstdAvailable;
			}

			s_zstdProbed = true;
			var candidateNames = GetZstdLibraryCandidates();

			foreach (var candidate in candidateNames)
			{
				if (!NativeLibrary.TryLoad(candidate, out var handle))
					continue;

				if (!NativeLibrary.TryGetExport(handle, "ZSTD_getFrameContentSize", out var frameSizePtr)
					|| !NativeLibrary.TryGetExport(handle, "ZSTD_decompress", out var decompressPtr)
					|| !NativeLibrary.TryGetExport(handle, "ZSTD_isError", out var isErrorPtr)
					|| !NativeLibrary.TryGetExport(handle, "ZSTD_getErrorName", out var errorNamePtr)
					|| !NativeLibrary.TryGetExport(handle, "ZSTD_createDStream", out var createDStreamPtr)
					|| !NativeLibrary.TryGetExport(handle, "ZSTD_freeDStream", out var freeDStreamPtr)
					|| !NativeLibrary.TryGetExport(handle, "ZSTD_initDStream", out var initDStreamPtr)
					|| !NativeLibrary.TryGetExport(handle, "ZSTD_decompressStream", out var decompressStreamPtr))
				{
					continue;
				}

				s_zstdGetFrameContentSize = Marshal.GetDelegateForFunctionPointer<ZstdGetFrameContentSizeDelegate>(frameSizePtr);
				s_zstdDecompress = Marshal.GetDelegateForFunctionPointer<ZstdDecompressDelegate>(decompressPtr);
				s_zstdIsError = Marshal.GetDelegateForFunctionPointer<ZstdIsErrorDelegate>(isErrorPtr);
				s_zstdGetErrorName = Marshal.GetDelegateForFunctionPointer<ZstdGetErrorNameDelegate>(errorNamePtr);
				s_zstdCreateDStream = Marshal.GetDelegateForFunctionPointer<ZstdCreateDStreamDelegate>(createDStreamPtr);
				s_zstdFreeDStream = Marshal.GetDelegateForFunctionPointer<ZstdFreeDStreamDelegate>(freeDStreamPtr);
				s_zstdInitDStream = Marshal.GetDelegateForFunctionPointer<ZstdInitDStreamDelegate>(initDStreamPtr);
				s_zstdDecompressStream = Marshal.GetDelegateForFunctionPointer<ZstdDecompressStreamDelegate>(decompressStreamPtr);
				s_zstdAvailable = true;
				s_zstdUnavailableReason = string.Empty;
				error = string.Empty;
				return true;
			}

			s_zstdAvailable = false;
			s_zstdUnavailableReason = "libzstd is not available on this system.";
			error = s_zstdUnavailableReason;
			return false;
		}
	}

	private static IReadOnlyList<string> GetZstdLibraryCandidates()
	{
		if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			return new[]
			{
				"zstd.dll",
				"libzstd.dll"
			};
		}

		if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
		{
			return new[]
			{
				"libzstd.dylib",
				"/opt/homebrew/lib/libzstd.dylib",
				"/usr/local/lib/libzstd.dylib",
				"/usr/lib/libzstd.dylib",
				"libzstd"
			};
		}

		return new[]
		{
			"libzstd.so.1",
			"libzstd.so",
			"/usr/lib/x86_64-linux-gnu/libzstd.so.1",
			"/usr/lib/aarch64-linux-gnu/libzstd.so.1",
			"/lib/x86_64-linux-gnu/libzstd.so.1",
			"/lib/aarch64-linux-gnu/libzstd.so.1",
			"libzstd"
		};
	}

	private static bool IsZstdError(nuint code, out string error)
	{
		if (s_zstdIsError(code) == 0)
		{
			error = string.Empty;
			return false;
		}

		var errorNamePtr = s_zstdGetErrorName(code);
		error = errorNamePtr == IntPtr.Zero ? "unknown error" : Marshal.PtrToStringAnsi(errorNamePtr) ?? "unknown error";
		return true;
	}

	private static bool TryDecompressZstdPayloadExternalTool(
		ReadOnlySpan<byte> compressedPayload,
		ulong expectedSize,
		ElfParseOptions parseOptions,
		out byte[] payload,
		out string error)
	{
		payload = Array.Empty<byte>();
		error = string.Empty;

		if (!parseOptions.EnableExternalZstdToolFallback)
		{
			error = "External zstd fallback is disabled.";
			return false;
		}

		var executable = ResolveZstdExecutablePath(parseOptions.ExternalZstdToolPath);
		if (string.IsNullOrEmpty(executable))
		{
			error = "zstd executable not found.";
			return false;
		}

		try
		{
			var timeout = parseOptions.ExternalZstdToolTimeout <= TimeSpan.Zero
				? TimeSpan.FromSeconds(15)
				: parseOptions.ExternalZstdToolTimeout;
			var startInfo = new ProcessStartInfo
			{
				FileName = executable,
				Arguments = "-q -d -c --no-progress",
				RedirectStandardInput = true,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				UseShellExecute = false,
				CreateNoWindow = true
			};

			using var process = Process.Start(startInfo);
			if (process == null)
			{
				error = "Failed to start external zstd process.";
				return false;
			}

			process.StandardInput.BaseStream.Write(compressedPayload);
			process.StandardInput.Close();

			using var output = new MemoryStream();
			process.StandardOutput.BaseStream.CopyTo(output);
			var stderr = process.StandardError.ReadToEnd();

			if (!process.WaitForExit((int)timeout.TotalMilliseconds))
			{
				try
				{
					process.Kill(entireProcessTree: true);
				}
				catch
				{
					// Ignore kill failures for already-exited processes.
				}
				error = $"External zstd process timed out after {timeout.TotalSeconds:0.#}s.";
				return false;
			}

			if (process.ExitCode != 0)
			{
				error = $"External zstd failed (exit={process.ExitCode}): {stderr}".Trim();
				return false;
			}

			var decompressed = output.ToArray();
			if ((ulong)decompressed.Length > MaxSectionDecompressionSize)
			{
				error = $"Uncompressed payload exceeds safety limit ({MaxSectionDecompressionSize} bytes).";
				return false;
			}

			if (expectedSize != 0 && (ulong)decompressed.Length != expectedSize)
			{
				error = $"Uncompressed payload size mismatch (expected {expectedSize}, got {(ulong)decompressed.Length}).";
				return false;
			}

			payload = decompressed;
			return true;
		}
		catch (Exception ex)
		{
			error = ex.Message;
			return false;
		}
	}

	private static string ResolveZstdExecutablePath(string preferredPath)
	{
		if (!string.IsNullOrWhiteSpace(preferredPath))
		{
			var fullPreferredPath = Path.GetFullPath(preferredPath);
			if (File.Exists(fullPreferredPath))
				return fullPreferredPath;
		}

		var envPath = Environment.GetEnvironmentVariable("PATH");
		if (string.IsNullOrWhiteSpace(envPath))
			return string.Empty;

		var candidateNames = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
			? new[] { "zstd.exe", "zstd" }
			: new[] { "zstd" };
		var pathSeparators = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
			? ';'
			: ':';

		foreach (var directory in envPath.Split(pathSeparators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
		{
			foreach (var name in candidateNames)
			{
				var fullPath = Path.Combine(directory, name);
				if (File.Exists(fullPath))
					return fullPath;
			}
		}

		return string.Empty;
	}

	private static bool TryDecompressZstdPayloadRawRleFallback(ReadOnlySpan<byte> compressedPayload, ulong expectedSize, out byte[] payload, out string error)
	{
		payload = Array.Empty<byte>();
		error = string.Empty;
		var cursor = 0;
		var parsedAnyFrame = false;
		using var totalOutput = new MemoryStream();

		while (cursor + 8 <= compressedPayload.Length)
		{
			var magic = BinaryPrimitives.ReadUInt32LittleEndian(compressedPayload.Slice(cursor, 4));
			if (magic >= ZstdSkippableFrameMagicStart && magic <= ZstdSkippableFrameMagicEnd)
			{
				var skipSize = BinaryPrimitives.ReadUInt32LittleEndian(compressedPayload.Slice(cursor + 4, 4));
				var skipLength = checked((ulong)skipSize + 8UL);
				if (skipLength > int.MaxValue || cursor + (int)skipLength > compressedPayload.Length)
				{
					error = "Truncated ZSTD skippable frame.";
					return false;
				}

				cursor += (int)skipLength;
				continue;
			}

			if (magic != ZstdFrameMagic)
			{
				error = "Not a ZSTD frame.";
				return false;
			}

			cursor += 4;
			if (cursor >= compressedPayload.Length)
			{
				error = "Truncated ZSTD frame header.";
				return false;
			}

			var descriptor = compressedPayload[cursor++];
			var singleSegment = (descriptor & 0x20) != 0;
			var frameContentSizeFlag = (descriptor >> 6) & 0x03;
			var dictionaryIdFlag = descriptor & 0x03;
			var hasChecksum = (descriptor & 0x04) != 0;

			if (!singleSegment)
			{
				if (cursor >= compressedPayload.Length)
				{
					error = "Truncated ZSTD window descriptor.";
					return false;
				}
				cursor++; // window descriptor
			}

			var dictionaryIdSize = dictionaryIdFlag switch
			{
				0 => 0,
				1 => 1,
				2 => 2,
				_ => 4
			};
			if (cursor + dictionaryIdSize > compressedPayload.Length)
			{
				error = "Truncated ZSTD dictionary id.";
				return false;
			}
			cursor += dictionaryIdSize;

			var frameContentSizeFieldSize = frameContentSizeFlag switch
			{
				0 => singleSegment ? 1 : 0,
				1 => 2,
				2 => 4,
				_ => 8
			};
			if (cursor + frameContentSizeFieldSize > compressedPayload.Length)
			{
				error = "Truncated ZSTD frame content size.";
				return false;
			}
			cursor += frameContentSizeFieldSize;

			using var frameOutput = new MemoryStream();
			var iterations = 0UL;
			while (cursor + 3 <= compressedPayload.Length && iterations < MaxParserEntryCount)
			{
				iterations++;
				var blockHeader = (uint)(compressedPayload[cursor]
					| (compressedPayload[cursor + 1] << 8)
					| (compressedPayload[cursor + 2] << 16));
				cursor += 3;

				var isLastBlock = (blockHeader & 0x1) != 0;
				var blockType = (blockHeader >> 1) & 0x3;
				var blockSize = blockHeader >> 3;

				if (blockType == 0) // raw
				{
					if (blockSize > int.MaxValue || cursor + (int)blockSize > compressedPayload.Length)
					{
						error = "Truncated ZSTD raw block.";
						return false;
					}

					frameOutput.Write(compressedPayload.Slice(cursor, (int)blockSize));
					cursor += (int)blockSize;
				}
				else if (blockType == 1) // RLE
				{
					if (cursor >= compressedPayload.Length)
					{
						error = "Truncated ZSTD RLE block.";
						return false;
					}

					var repeated = compressedPayload[cursor++];
					if (blockSize > int.MaxValue)
					{
						error = "ZSTD RLE block exceeds parser limits.";
						return false;
					}

					for (var i = 0U; i < blockSize; i++)
						frameOutput.WriteByte(repeated);
				}
				else if (blockType == 2)
				{
					error = "Compressed ZSTD blocks require native libzstd support.";
					return false;
				}
				else
				{
					error = "Invalid ZSTD block type.";
					return false;
				}

				if ((ulong)frameOutput.Length > MaxSectionDecompressionSize)
				{
					error = $"Uncompressed payload exceeds safety limit ({MaxSectionDecompressionSize} bytes).";
					return false;
				}

				if (isLastBlock)
					break;
			}

			if (hasChecksum)
			{
				if (cursor + 4 > compressedPayload.Length)
				{
					error = "Truncated ZSTD content checksum.";
					return false;
				}
				cursor += 4;
			}

			var frameBytes = frameOutput.ToArray();
			totalOutput.Write(frameBytes, 0, frameBytes.Length);
			if ((ulong)totalOutput.Length > MaxSectionDecompressionSize)
			{
				error = $"Uncompressed payload exceeds safety limit ({MaxSectionDecompressionSize} bytes).";
				return false;
			}

			parsedAnyFrame = true;
		}

		if (!parsedAnyFrame)
		{
			error = "No valid ZSTD frame found.";
			return false;
		}

		if (cursor != compressedPayload.Length)
		{
			error = "Trailing bytes after ZSTD frame payload.";
			return false;
		}

		var decompressed = totalOutput.ToArray();
		if (expectedSize != 0 && (ulong)decompressed.Length != expectedSize)
		{
			error = $"Uncompressed payload size mismatch (expected {expectedSize}, got {(ulong)decompressed.Length}).";
			return false;
		}

		payload = decompressed;
		return true;
	}

}
