using System.Buffers.Binary;
using System.Text;

namespace NetWarden.Core.Util;

/// <summary>Minimal logging abstraction so the engine has no logging-library dependency.</summary>
public interface INwLog
{
    void Debug(string message);
    void Info(string message);
    void Warn(string message, Exception? ex = null);
    void Error(string message, Exception? ex = null);
}

public sealed class NullLog : INwLog
{
    public static readonly NullLog Instance = new();
    public void Debug(string message) { }
    public void Info(string message) { }
    public void Warn(string message, Exception? ex = null) { }
    public void Error(string message, Exception? ex = null) { }
}

/// <summary>Cooperative pause/resume used by the scan pipeline.</summary>
public sealed class PauseTokenSource
{
    private volatile TaskCompletionSource<bool>? _paused;

    public bool IsPaused => _paused != null;

    public void Pause()
    {
        Interlocked.CompareExchange(ref _paused, new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously), null);
    }

    public void Resume()
    {
        while (true)
        {
            var tcs = _paused;
            if (tcs == null) return;
            if (Interlocked.CompareExchange(ref _paused, null, tcs) == tcs)
            {
                tcs.TrySetResult(true);
                return;
            }
        }
    }

    public PauseToken Token => new(this);

    internal Task WaitWhilePausedAsync(CancellationToken ct)
    {
        var tcs = _paused;
        return tcs == null ? Task.CompletedTask : tcs.Task.WaitAsync(ct);
    }
}

public readonly struct PauseToken
{
    private readonly PauseTokenSource? _source;
    public PauseToken(PauseTokenSource source) => _source = source;
    public bool IsPaused => _source?.IsPaused ?? false;
    public Task WaitWhilePausedAsync(CancellationToken ct = default)
        => _source?.WaitWhilePausedAsync(ct) ?? Task.CompletedTask;
}

/// <summary>Big-endian/little-endian byte builder for protocol packets.</summary>
public sealed class PacketWriter
{
    private readonly MemoryStream _ms = new();
    public int Length => (int)_ms.Length;
    public PacketWriter U8(byte v) { _ms.WriteByte(v); return this; }
    public PacketWriter U16BE(ushort v) { Span<byte> b = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, v); _ms.Write(b); return this; }
    public PacketWriter U16LE(ushort v) { Span<byte> b = stackalloc byte[2]; BinaryPrimitives.WriteUInt16LittleEndian(b, v); _ms.Write(b); return this; }
    public PacketWriter U24BE(int v) { U8((byte)(v >> 16)); U8((byte)(v >> 8)); U8((byte)v); return this; }
    public PacketWriter U32BE(uint v) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, v); _ms.Write(b); return this; }
    public PacketWriter U32LE(uint v) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, v); _ms.Write(b); return this; }
    public PacketWriter U64LE(ulong v) { Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteUInt64LittleEndian(b, v); _ms.Write(b); return this; }
    public PacketWriter Bytes(ReadOnlySpan<byte> data) { _ms.Write(data); return this; }
    public PacketWriter Zeros(int count) { for (int i = 0; i < count; i++) _ms.WriteByte(0); return this; }
    public PacketWriter Ascii(string s) { Bytes(Encoding.ASCII.GetBytes(s)); return this; }
    public byte[] ToArray() => _ms.ToArray();
}

public static class ByteUtil
{
    public static string ToHex(ReadOnlySpan<byte> data, int max = 64)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < data.Length && i < max; i++) sb.Append(data[i].ToString("x2"));
        if (data.Length > max) sb.Append('…');
        return sb.ToString();
    }

    public static string PrintableAscii(ReadOnlySpan<byte> data, int max = 512)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < data.Length && i < max; i++)
        {
            var c = (char)data[i];
            if (c == '\r') continue;
            sb.Append(c == '\n' || c == '\t' || (c >= 32 && c < 127) ? c : '.');
        }
        return sb.ToString().Trim();
    }

    public static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle) => haystack.IndexOf(needle);
}

public static class TextUtil
{
    public static string Truncate(string? s, int max)
        => string.IsNullOrEmpty(s) ? "" : s.Length <= max ? s : s[..max] + "…";

    public static string FirstLine(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var i = s.IndexOfAny(new[] { '\r', '\n' });
        return (i < 0 ? s : s[..i]).Trim();
    }
}
