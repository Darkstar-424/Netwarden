using System.Security.Cryptography.X509Certificates;
using System.Text;
using NetWarden.Core.Checks;
using NetWarden.Core.Models;
using NetWarden.Core.Profiles;
using NetWarden.Core.Util;

namespace NetWarden.Tests;

/// <summary>
/// A fake network: each TCP connection to a port plays back a script of responses, one per receive call.
/// Lets protocol detectors and checks be tested with canned bytes, no sockets involved.
/// </summary>
public sealed class ScriptedProbe : IProbeClient
{
    private readonly Dictionary<int, Queue<List<byte[]>>> _tcp = new();
    private readonly Dictionary<int, byte[]> _udp = new();
    private readonly Dictionary<string, HttpProbeResponse> _http = new();
    public List<(int Port, byte[] Data)> Sent { get; } = new();
    public List<string> HttpRequests { get; } = new();

    /// <summary>Adds one scripted connection to a port. Each element is returned by one receive call.</summary>
    public ScriptedProbe Tcp(int port, params byte[][] responses)
    {
        if (!_tcp.TryGetValue(port, out var q)) _tcp[port] = q = new Queue<List<byte[]>>();
        q.Enqueue(responses.ToList());
        return this;
    }

    public ScriptedProbe Udp(int port, byte[] response) { _udp[port] = response; return this; }

    public ScriptedProbe Http(string method, string path, int status, string body, params (string, string)[] headers)
    {
        _http[$"{method} {path}"] = new HttpProbeResponse(status, "OK", headers.ToDictionary(h => h.Item1, h => h.Item2, StringComparer.OrdinalIgnoreCase), body, false);
        return this;
    }

    public Task<ITcpSession?> ConnectAsync(string host, int port, TimeSpan timeout, CancellationToken ct, bool tls = false, string? sniHost = null)
    {
        if (!_tcp.TryGetValue(port, out var q) || q.Count == 0) return Task.FromResult<ITcpSession?>(null);
        return Task.FromResult<ITcpSession?>(new Session(port, q.Dequeue(), this));
    }

    public Task<byte[]?> UdpExchangeAsync(string host, int port, byte[] request, TimeSpan timeout, CancellationToken ct)
        => Task.FromResult(_udp.TryGetValue(port, out var r) ? r : null);

    public Task<HttpProbeResponse?> HttpRequestAsync(string host, int port, bool tls, string method, string path, TimeSpan timeout, CancellationToken ct, int maxBodyBytes = 65536)
    {
        HttpRequests.Add($"{method} {path}");
        return Task.FromResult(_http.TryGetValue($"{method} {path}", out var r) ? r : null);
    }

    public Task<X509Certificate2?> GetCertificateAsync(string host, int port, string? sniHost, TimeSpan timeout, CancellationToken ct)
        => Task.FromResult<X509Certificate2?>(null);

    private sealed class Session : ITcpSession
    {
        private readonly int _port;
        private readonly Queue<byte[]> _responses;
        private readonly ScriptedProbe _owner;
        private readonly MemoryStream _pending = new();

        public Session(int port, List<byte[]> responses, ScriptedProbe owner)
        {
            _port = port;
            _responses = new Queue<byte[]>(responses);
            _owner = owner;
        }

        public Task SendAsync(byte[] data, CancellationToken ct) { _owner.Sent.Add((_port, data)); return Task.CompletedTask; }

        private void Fill()
        {
            if (_pending.Length == 0 && _responses.Count > 0) _pending.Write(_responses.Dequeue());
        }

        private byte[] Take(int max)
        {
            var all = _pending.ToArray();
            var n = Math.Min(max, all.Length);
            _pending.SetLength(0);
            _pending.Write(all, n, all.Length - n);
            return all[..n];
        }

        public Task<byte[]> ReceiveAsync(int maxBytes, TimeSpan timeout, CancellationToken ct)
        {
            Fill();
            return Task.FromResult(Take(maxBytes));
        }

        public Task<byte[]> ReceiveExactAsync(int count, TimeSpan timeout, CancellationToken ct)
        {
            var result = new MemoryStream();
            while (result.Length < count)
            {
                Fill();
                if (_pending.Length == 0) break;
                result.Write(Take(count - (int)result.Length));
            }
            return Task.FromResult(result.ToArray());
        }

        public Task<string?> ReceiveLineAsync(TimeSpan timeout, CancellationToken ct)
        {
            var line = new List<byte>();
            while (true)
            {
                Fill();
                if (_pending.Length == 0) return Task.FromResult<string?>(line.Count > 0 ? Encoding.Latin1.GetString(line.ToArray()) : null);
                var b = Take(1)[0];
                if (b == '\n') return Task.FromResult<string?>(Encoding.Latin1.GetString(line.ToArray()).TrimEnd('\r'));
                line.Add(b);
            }
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

public static class TestData
{
    public static HostResult Host(string address = "192.168.1.10") => new() { Address = address, IsUp = true };

    public static PortResult Port(int port, string service, params (string Key, string Value)[] facts)
    {
        var s = new ServiceInfo { Name = service };
        foreach (var (k, v) in facts) s.Facts[k] = v;
        return new PortResult { Port = port, Protocol = TransportProtocol.Tcp, State = PortState.Open, Service = s };
    }

    public static CheckContext Context(HostResult host, PortResult? port, IProbeClient? probe = null, ICveRepository? cves = null, DateTimeOffset? now = null)
    {
        if (port != null && !host.Ports.Contains(port)) host.Ports.Add(port);
        return new CheckContext
        {
            Target = new CheckTarget(host, port),
            Profile = BuiltInProfiles.Get(BuiltInProfiles.Standard),
            Probe = probe ?? new ScriptedProbe(),
            Cves = cves,
            Timeout = TimeSpan.FromMilliseconds(200),
            Now = now ?? DateTimeOffset.UtcNow
        };
    }

    public static byte[] Bytes(params int[] values) => values.Select(v => (byte)v).ToArray();
    public static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

    public static Stream Resource(string name)
        => typeof(TestData).Assembly.GetManifestResourceStream(typeof(TestData).Assembly.GetManifestResourceNames().Single(n => n.EndsWith(name, StringComparison.Ordinal)))!;
}

/// <summary>In-memory CVE repository for check tests.</summary>
public sealed class FakeCveRepository : ICveRepository
{
    public List<CveMatchRule> Rules { get; } = new();
    public Dictionary<string, CveRecord> Records { get; } = new();
    public bool IsAvailable => true;
    public IReadOnlyList<CveMatchRule> GetRules(string vendor, string product) => Rules.Where(r => r.Vendor == vendor && r.Product == product).ToList();
    public CveRecord? Get(string cveId) => Records.TryGetValue(cveId, out var r) ? r : null;

    public FakeCveRepository Add(string id, double cvss, bool kev, string vendor, string product, string? endExcl = null, string version = "*", string? startIncl = null)
    {
        Records[id] = new CveRecord(id, $"Test vulnerability {id}", cvss, "CVSS:3.1/AV:N", null, null, new[] { "https://example.invalid/" + id }, kev, kev ? "Apply updates per vendor instructions." : null, null);
        Rules.Add(new CveMatchRule(id, vendor, product, $"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*", startIncl, null, null, endExcl));
        return this;
    }
}
