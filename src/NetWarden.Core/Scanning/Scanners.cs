using NetWarden.Core.Fingerprinting;
using System.Net;
using System.Net.Sockets;
using NetWarden.Core.Models;
using NetWarden.Core.Protocols;
using NetWarden.Core.Util;

namespace NetWarden.Core.Scanning;

/// <summary>Shared concurrency limit + token-bucket rate limit so the whole scan stays "polite".</summary>
public sealed class Throttle : IDisposable
{
    private readonly SemaphoreSlim _concurrency;
    private readonly TokenBucket _rate;

    public Throttle(int maxConcurrency, int perSecond)
    {
        _concurrency = new SemaphoreSlim(Math.Max(1, maxConcurrency));
        _rate = new TokenBucket(Math.Max(1, perSecond));
    }

    public async Task<IDisposable> AcquireAsync(CancellationToken ct)
    {
        await _concurrency.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await _rate.TakeAsync(ct).ConfigureAwait(false);
        }
        catch
        {
            _concurrency.Release();
            throw;
        }
        return new Releaser(_concurrency);
    }

    private sealed class Releaser : IDisposable
    {
        private SemaphoreSlim? _s;
        public Releaser(SemaphoreSlim s) => _s = s;
        public void Dispose() => Interlocked.Exchange(ref _s, null)?.Release();
    }

    public void Dispose() => _concurrency.Dispose();
}

/// <summary>Simple thread-safe token bucket: refills continuously at the given rate, bursts up to ~1/10 s worth.</summary>
public sealed class TokenBucket
{
    private readonly double _ratePerSecond;
    private readonly double _capacity;
    private double _tokens;
    private long _lastTicks;
    private readonly object _gate = new();
    private readonly System.Diagnostics.Stopwatch _clock = System.Diagnostics.Stopwatch.StartNew();

    public TokenBucket(double ratePerSecond)
    {
        _ratePerSecond = ratePerSecond;
        _capacity = Math.Max(1, ratePerSecond / 10);
        _tokens = _capacity;
        _lastTicks = _clock.ElapsedTicks;
    }

    public async Task TakeAsync(CancellationToken ct)
    {
        while (true)
        {
            TimeSpan wait;
            lock (_gate)
            {
                var now = _clock.ElapsedTicks;
                var elapsed = (now - _lastTicks) / (double)System.Diagnostics.Stopwatch.Frequency;
                _lastTicks = now;
                _tokens = Math.Min(_capacity, _tokens + elapsed * _ratePerSecond);
                if (_tokens >= 1)
                {
                    _tokens -= 1;
                    return;
                }
                wait = TimeSpan.FromSeconds((1 - _tokens) / _ratePerSecond);
            }
            await Task.Delay(wait < TimeSpan.FromMilliseconds(1) ? TimeSpan.FromMilliseconds(1) : wait, ct).ConfigureAwait(false);
        }
    }
}

/// <summary>Full TCP connect scan: opens and immediately closes a normal connection per port.</summary>
public sealed class TcpConnectScanner
{
    private readonly Throttle _throttle;
    private readonly int _timeoutMs;
    private readonly int _retries;

    public TcpConnectScanner(Throttle throttle, int timeoutMs, int retries)
    {
        _throttle = throttle;
        _timeoutMs = timeoutMs;
        _retries = retries;
    }

    public async Task<PortState> ProbeAsync(IPAddress address, int port, CancellationToken ct)
    {
        for (int attempt = 0; attempt <= _retries; attempt++)
        {
            using (await _throttle.AcquireAsync(ct).ConfigureAwait(false))
            {
                var state = await ConnectOnceAsync(address, port, ct).ConfigureAwait(false);
                if (state != PortState.Filtered) return state;
            }
        }
        return PortState.Filtered;
    }

    private async Task<PortState> ConnectOnceAsync(IPAddress address, int port, CancellationToken ct)
    {
        using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        socket.LingerState = new LingerOption(true, 0);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_timeoutMs);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), cts.Token).ConfigureAwait(false);
            return PortState.Open;
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
        {
            return PortState.Closed;
        }
        catch (SocketException)
        {
            return PortState.Filtered;
        }
        catch (OperationCanceledException)
        {
            ct.ThrowIfCancellationRequested();
            return PortState.Filtered;
        }
    }
}

public sealed record UdpProbeResult(int Port, string Service, string Detail, Dictionary<string, string> Facts, byte[] Response);

/// <summary>Sends one harmless, protocol-correct request to common UDP services.</summary>
public sealed class UdpProber
{
    private readonly IProbeClient _probe;
    private readonly TimeSpan _timeout;

    public UdpProber(IProbeClient probe, TimeSpan timeout)
    {
        _probe = probe;
        _timeout = timeout;
    }

    public static readonly int[] Ports = { 53, 123, 137, 161, 623, 1900 };

    public async Task<IReadOnlyList<UdpProbeResult>> ProbeAsync(string host, CancellationToken ct)
    {
        var tasks = new[]
        {
            ProbeDnsAsync(host, ct),
            ProbeNtpAsync(host, ct),
            ProbeNetBiosAsync(host, ct),
            ProbeSnmpAsync(host, ct),
            ProbeIpmiAsync(host, ct),
            ProbeSsdpAsync(host, ct)
        };
        var results = await Task.WhenAll(tasks).ConfigureAwait(false);
        return results.Where(r => r != null).Cast<UdpProbeResult>().ToList();
    }

    private async Task<UdpProbeResult?> ProbeDnsAsync(string host, CancellationToken ct)
    {
        // Non-recursive query for the root NS records: any DNS server answers this without doing lookups for us.
        var resp = await _probe.UdpExchangeAsync(host, 53, DnsPackets.Query(".", 2, recursionDesired: false), _timeout, ct).ConfigureAwait(false);
        var hdr = resp == null ? null : DnsPackets.ParseHeader(resp);
        if (hdr is not { IsResponse: true }) return null;
        return new UdpProbeResult(53, "dns", "DNS server", new Dictionary<string, string>
        {
            ["dns.recursionAvailable"] = hdr.RecursionAvailable ? "yes" : "no"
        }, resp!);
    }

    private async Task<UdpProbeResult?> ProbeNtpAsync(string host, CancellationToken ct)
    {
        var resp = await _probe.UdpExchangeAsync(host, 123, NtpPackets.ClientRequest(), _timeout, ct).ConfigureAwait(false);
        var r = resp == null ? null : NtpPackets.ParseResponse(resp);
        if (r is not { Mode: 4 }) return null;
        return new UdpProbeResult(123, "ntp", $"NTPv{r.Value.Version}, stratum {r.Value.Stratum}",
            new Dictionary<string, string> { ["ntp.stratum"] = r.Value.Stratum.ToString() }, resp!);
    }

    private async Task<UdpProbeResult?> ProbeNetBiosAsync(string host, CancellationToken ct)
    {
        var resp = await _probe.UdpExchangeAsync(host, 137, NetBiosPackets.NodeStatusRequest(), _timeout, ct).ConfigureAwait(false);
        var ns = resp == null ? null : NetBiosPackets.ParseNodeStatus(resp);
        if (ns == null) return null;
        var facts = new Dictionary<string, string>();
        if (ns.ComputerName != null) facts["netbios.name"] = ns.ComputerName;
        if (ns.Workgroup != null) facts["netbios.workgroup"] = ns.Workgroup;
        if (ns.Mac != null) facts["netbios.mac"] = ns.Mac;
        return new UdpProbeResult(137, "netbios-ns", $"NetBIOS name {ns.ComputerName ?? "?"}", facts, resp!);
    }

    private async Task<UdpProbeResult?> ProbeSnmpAsync(string host, CancellationToken ct)
    {
        var resp = await _probe.UdpExchangeAsync(host, 161, SnmpPackets.V3DiscoveryRequest(), _timeout, ct).ConfigureAwait(false);
        if (resp == null) return null;
        var engine = SnmpPackets.ParseEngineId(resp);
        if (engine == null) return null;
        var facts = new Dictionary<string, string> { ["snmp.v3"] = "yes", ["snmp.engineId"] = ByteUtil.ToHex(engine) };
        var detail = "SNMPv3 agent";
        if (SnmpPackets.EnterpriseNumber(engine) is int pen)
        {
            facts["snmp.enterprise"] = pen.ToString();
            if (SnmpPackets.EnterpriseName(pen) is string vendor) { facts["snmp.vendor"] = vendor; detail += $" ({vendor})"; }
        }
        return new UdpProbeResult(161, "snmp", detail, facts, resp);
    }

    private async Task<UdpProbeResult?> ProbeIpmiAsync(string host, CancellationToken ct)
    {
        var resp = await _probe.UdpExchangeAsync(host, 623, IpmiPackets.AsfPresencePing, _timeout, ct).ConfigureAwait(false);
        if (resp == null || !IpmiPackets.IsPresencePong(resp)) return null;
        return new UdpProbeResult(623, "ipmi", "IPMI/BMC management controller (RMCP presence pong)",
            new Dictionary<string, string> { ["ipmi.rmcp"] = "yes" }, resp);
    }

    private async Task<UdpProbeResult?> ProbeSsdpAsync(string host, CancellationToken ct)
    {
        var resp = await _probe.UdpExchangeAsync(host, 1900, SsdpPackets.MSearch(host), _timeout, ct).ConfigureAwait(false);
        var server = resp == null ? null : SsdpPackets.ParseServer(resp);
        if (server == null) return null;
        var facts = new Dictionary<string, string> { ["ssdp.server"] = server };
        if (UpnpDescription.Location(System.Text.Encoding.ASCII.GetString(resp!)) is string loc) facts["ssdp.location"] = loc;
        return new UdpProbeResult(1900, "ssdp", string.IsNullOrEmpty(server) ? "UPnP/SSDP responder" : $"UPnP: {server}", facts, resp!);
    }
}
