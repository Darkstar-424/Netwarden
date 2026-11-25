using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NetWarden.Core.Util;

/// <summary>A connected conversation with one service. Mockable for unit tests.</summary>
public interface ITcpSession : IAsyncDisposable
{
    Task SendAsync(byte[] data, CancellationToken ct);
    /// <summary>Reads what arrives within the timeout (at most maxBytes). Returns empty if nothing arrived or the peer closed.</summary>
    Task<byte[]> ReceiveAsync(int maxBytes, TimeSpan timeout, CancellationToken ct);
    /// <summary>Reads exactly count bytes or returns fewer if the peer closed / timed out.</summary>
    Task<byte[]> ReceiveExactAsync(int count, TimeSpan timeout, CancellationToken ct);
    /// <summary>Reads one CRLF/LF-terminated line (without the terminator), or null on timeout/close.</summary>
    Task<string?> ReceiveLineAsync(TimeSpan timeout, CancellationToken ct);
}

public sealed record HttpProbeResponse(int StatusCode, string Reason, IReadOnlyDictionary<string, string> Headers, string Body, bool Tls)
{
    public string? Header(string name) => Headers.TryGetValue(name, out var v) ? v : null;
}

/// <summary>Network access used by detectors and checks. The real implementation talks to the network; tests script it.</summary>
public interface IProbeClient
{
    Task<ITcpSession?> ConnectAsync(string host, int port, TimeSpan timeout, CancellationToken ct, bool tls = false, string? sniHost = null);
    Task<byte[]?> UdpExchangeAsync(string host, int port, byte[] request, TimeSpan timeout, CancellationToken ct);
    Task<HttpProbeResponse?> HttpRequestAsync(string host, int port, bool tls, string method, string path, TimeSpan timeout, CancellationToken ct, int maxBodyBytes = 65536);
    /// <summary>Completes a normal TLS handshake (accepting any certificate) only to read the server certificate.</summary>
    Task<X509Certificate2?> GetCertificateAsync(string host, int port, string? sniHost, TimeSpan timeout, CancellationToken ct);
}

public sealed class NetworkProbeClient : IProbeClient
{
    public static readonly NetworkProbeClient Instance = new();
    public const string UserAgent = "NetWarden/1.0 (authorized security assessment)";

    public async Task<ITcpSession?> ConnectAsync(string host, int port, TimeSpan timeout, CancellationToken ct, bool tls = false, string? sniHost = null)
    {
        var client = new TcpClient { NoDelay = true };
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            Stream stream = client.GetStream();
            if (tls)
            {
                var ssl = new SslStream(stream, false);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = sniHost ?? host,
                    RemoteCertificateValidationCallback = (_, _, _, _) => true,
                    EnabledSslProtocols = SslProtocols.None,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, cts.Token).ConfigureAwait(false);
                stream = ssl;
            }
            return new StreamSession(client, stream);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or IOException or AuthenticationException)
        {
            client.Dispose();
            ct.ThrowIfCancellationRequested();
            return null;
        }
    }

    public async Task<byte[]?> UdpExchangeAsync(string host, int port, byte[] request, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            using var udp = new UdpClient(AddressFamily.InterNetwork);
            udp.Connect(host, port);
            await udp.SendAsync(request, ct).ConfigureAwait(false);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            var r = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
            return r.Buffer;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            ct.ThrowIfCancellationRequested();
            return null;
        }
    }

    public async Task<HttpProbeResponse?> HttpRequestAsync(string host, int port, bool tls, string method, string path, TimeSpan timeout, CancellationToken ct, int maxBodyBytes = 65536)
    {
        if (method is not ("GET" or "HEAD" or "OPTIONS"))
            throw new InvalidOperationException("Only read-only HTTP methods (GET, HEAD, OPTIONS) are allowed.");
        await using var session = await ConnectAsync(host, port, timeout, ct, tls).ConfigureAwait(false);
        if (session == null) return null;
        var hostHeader = (tls && port == 443) || (!tls && port == 80) ? host : $"{host}:{port}";
        if (IPAddress.TryParse(host, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6)
            hostHeader = $"[{host}]" + ((tls && port == 443) || (!tls && port == 80) ? "" : $":{port}");
        var req = $"{method} {path} HTTP/1.1\r\nHost: {hostHeader}\r\nUser-Agent: {UserAgent}\r\nAccept: */*\r\nConnection: close\r\n\r\n";
        await session.SendAsync(Encoding.ASCII.GetBytes(req), ct).ConfigureAwait(false);
        var buffer = new MemoryStream();
        var deadline = DateTime.UtcNow + timeout;
        while (buffer.Length < maxBodyBytes + 16384)
        {
            var left = deadline - DateTime.UtcNow;
            if (left <= TimeSpan.Zero) break;
            var chunk = await session.ReceiveAsync(16384, left, ct).ConfigureAwait(false);
            if (chunk.Length == 0) break;
            buffer.Write(chunk);
            if (method == "HEAD" || method == "OPTIONS")
            {
                if (HttpParser.HeaderEnd(buffer.GetBuffer().AsSpan(0, (int)buffer.Length)) >= 0) break;
            }
            else if (HttpParser.IsComplete(buffer.GetBuffer().AsSpan(0, (int)buffer.Length)))
            {
                break;
            }
        }
        return HttpParser.Parse(buffer.ToArray(), tls, maxBodyBytes);
    }

    public async Task<X509Certificate2?> GetCertificateAsync(string host, int port, string? sniHost, TimeSpan timeout, CancellationToken ct)
    {
        using var client = new TcpClient { NoDelay = true };
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            X509Certificate2? captured = null;
            await using var ssl = new SslStream(client.GetStream(), false, (_, cert, _, _) =>
            {
                if (cert != null) captured = new X509Certificate2(cert);
                return true;
            });
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = sniHost ?? host,
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }, cts.Token).ConfigureAwait(false);
            return captured;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or IOException or AuthenticationException)
        {
            ct.ThrowIfCancellationRequested();
            return null;
        }
    }

    private sealed class StreamSession : ITcpSession
    {
        private readonly TcpClient _client;
        private readonly Stream _stream;
        private readonly MemoryStream _pending = new();

        public StreamSession(TcpClient client, Stream stream) { _client = client; _stream = stream; }

        public Task SendAsync(byte[] data, CancellationToken ct) => _stream.WriteAsync(data, 0, data.Length, ct);

        public async Task<byte[]> ReceiveAsync(int maxBytes, TimeSpan timeout, CancellationToken ct)
        {
            if (_pending.Length > 0) return TakePending(maxBytes);
            var buf = new byte[Math.Max(1, maxBytes)];
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            try
            {
                var n = await _stream.ReadAsync(buf.AsMemory(0, buf.Length), cts.Token).ConfigureAwait(false);
                return n <= 0 ? Array.Empty<byte>() : buf[..n];
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or SocketException)
            {
                ct.ThrowIfCancellationRequested();
                return Array.Empty<byte>();
            }
        }

        public async Task<byte[]> ReceiveExactAsync(int count, TimeSpan timeout, CancellationToken ct)
        {
            var result = new MemoryStream();
            var deadline = DateTime.UtcNow + timeout;
            while (result.Length < count)
            {
                var left = deadline - DateTime.UtcNow;
                if (left <= TimeSpan.Zero) break;
                var chunk = await ReceiveAsync(count - (int)result.Length, left, ct).ConfigureAwait(false);
                if (chunk.Length == 0) break;
                result.Write(chunk);
            }
            return result.ToArray();
        }

        public async Task<string?> ReceiveLineAsync(TimeSpan timeout, CancellationToken ct)
        {
            var line = new List<byte>();
            var deadline = DateTime.UtcNow + timeout;
            while (line.Count < 8192)
            {
                var left = deadline - DateTime.UtcNow;
                if (left <= TimeSpan.Zero) break;
                var chunk = await ReceiveAsync(512, left, ct).ConfigureAwait(false);
                if (chunk.Length == 0) break;
                for (int i = 0; i < chunk.Length; i++)
                {
                    if (chunk[i] == (byte)'\n')
                    {
                        if (i + 1 < chunk.Length) _pending.Write(chunk, i + 1, chunk.Length - i - 1);
                        return Encoding.Latin1.GetString(line.ToArray()).TrimEnd('\r');
                    }
                    line.Add(chunk[i]);
                }
            }
            return line.Count > 0 ? Encoding.Latin1.GetString(line.ToArray()).TrimEnd('\r') : null;
        }

        private byte[] TakePending(int max)
        {
            var all = _pending.ToArray();
            var take = Math.Min(max, all.Length);
            _pending.SetLength(0);
            if (take < all.Length) _pending.Write(all, take, all.Length - take);
            return all[..take];
        }

        public async ValueTask DisposeAsync()
        {
            try { await _stream.DisposeAsync().ConfigureAwait(false); } catch { /* ignore */ }
            _client.Dispose();
        }
    }
}

public static class HttpParser
{
    public static int HeaderEnd(ReadOnlySpan<byte> data)
    {
        var i = data.IndexOf("\r\n\r\n"u8);
        return i < 0 ? -1 : i + 4;
    }

    public static bool IsComplete(ReadOnlySpan<byte> data)
    {
        var end = HeaderEnd(data);
        if (end < 0) return false;
        var head = Encoding.Latin1.GetString(data[..end]);
        foreach (var line in head.Split("\r\n"))
        {
            if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)
                && int.TryParse(line[15..].Trim(), out var len))
                return data.Length - end >= len;
        }
        if (head.Contains("Transfer-Encoding: chunked", StringComparison.OrdinalIgnoreCase))
            return data[end..].IndexOf("\r\n0\r\n"u8) >= 0 || data[end..].StartsWith("0\r\n"u8);
        return false;
    }

    public static HttpProbeResponse? Parse(byte[] raw, bool tls, int maxBodyBytes = 65536)
    {
        if (raw.Length < 12) return null;
        var end = HeaderEnd(raw);
        var headText = Encoding.Latin1.GetString(raw, 0, end < 0 ? raw.Length : end);
        var lines = headText.Split("\r\n");
        var status = lines[0].Split(' ', 3);
        if (status.Length < 2 || !status[0].StartsWith("HTTP/", StringComparison.Ordinal) || !int.TryParse(status[1], out var code))
            return null;
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1))
        {
            var c = line.IndexOf(':');
            if (c <= 0) continue;
            var k = line[..c].Trim();
            var v = line[(c + 1)..].Trim();
            headers[k] = headers.TryGetValue(k, out var existing) ? existing + ", " + v : v;
        }
        var body = "";
        if (end >= 0 && end < raw.Length)
        {
            var bodyBytes = raw.AsSpan(end);
            if (headers.TryGetValue("Transfer-Encoding", out var te) && te.Contains("chunked", StringComparison.OrdinalIgnoreCase))
                bodyBytes = Dechunk(bodyBytes);
            if (bodyBytes.Length > maxBodyBytes) bodyBytes = bodyBytes[..maxBodyBytes];
            body = Encoding.UTF8.GetString(bodyBytes);
        }
        return new HttpProbeResponse(code, status.Length > 2 ? status[2] : "", headers, body, tls);
    }

    private static byte[] Dechunk(ReadOnlySpan<byte> data)
    {
        var output = new MemoryStream();
        int pos = 0;
        while (pos < data.Length)
        {
            var lineEnd = data[pos..].IndexOf("\r\n"u8);
            if (lineEnd < 0) break;
            var sizeText = Encoding.ASCII.GetString(data.Slice(pos, lineEnd)).Split(';')[0].Trim();
            if (!int.TryParse(sizeText, System.Globalization.NumberStyles.HexNumber, null, out var size) || size <= 0) break;
            pos += lineEnd + 2;
            var take = Math.Min(size, data.Length - pos);
            output.Write(data.Slice(pos, take));
            pos += take + 2;
        }
        return output.ToArray();
    }
}
