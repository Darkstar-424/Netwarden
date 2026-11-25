using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using NetWarden.Core.Protocols;
using NetWarden.Core.Util;

namespace NetWarden.Core.Discovery;

public sealed record PingResult(bool Alive, string Method, int? Ttl, double? RoundTripMs);

public interface IHostPinger
{
    Task<PingResult> PingAsync(IPAddress address, CancellationToken ct);
}

/// <summary>ICMP echo using the OS ping API (no admin rights needed on Windows).</summary>
public sealed class IcmpPinger : IHostPinger
{
    private readonly int _timeoutMs;
    public IcmpPinger(int timeoutMs) => _timeoutMs = timeoutMs;

    public async Task<PingResult> PingAsync(IPAddress address, CancellationToken ct)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(address, TimeSpan.FromMilliseconds(_timeoutMs), new byte[16], new PingOptions(128, true), ct).ConfigureAwait(false);
            if (reply.Status == IPStatus.Success)
                return new PingResult(true, "ICMP echo", reply.Options?.Ttl, reply.RoundtripTime);
        }
        catch (Exception ex) when (ex is PingException or SocketException or InvalidOperationException or PlatformNotSupportedException)
        {
            // fall through
        }
        return new PingResult(false, "ICMP echo", null, null);
    }
}

/// <summary>
/// "Ping" by opening TCP connections to common ports. A refused connection also proves the host is up.
/// </summary>
public sealed class TcpPinger : IHostPinger
{
    private readonly int _timeoutMs;
    private readonly IReadOnlyList<int> _ports;

    public TcpPinger(int timeoutMs, IReadOnlyList<int> ports)
    {
        _timeoutMs = timeoutMs;
        _ports = ports;
    }

    public async Task<PingResult> PingAsync(IPAddress address, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var tasks = _ports.Select(p => TryPortAsync(address, p, cts.Token)).ToList();
        while (tasks.Count > 0)
        {
            var done = await Task.WhenAny(tasks).ConfigureAwait(false);
            tasks.Remove(done);
            var r = await done.ConfigureAwait(false);
            if (r.Alive)
            {
                cts.Cancel();
                return r;
            }
        }
        ct.ThrowIfCancellationRequested();
        return new PingResult(false, "TCP ping", null, null);
    }

    private async Task<PingResult> TryPortAsync(IPAddress address, int port, CancellationToken ct)
    {
        using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_timeoutMs);
        var started = DateTime.UtcNow;
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), cts.Token).ConfigureAwait(false);
            return new PingResult(true, $"TCP ping (port {port} open)", null, (DateTime.UtcNow - started).TotalMilliseconds);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
        {
            return new PingResult(true, $"TCP ping (port {port} refused)", null, (DateTime.UtcNow - started).TotalMilliseconds);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            return new PingResult(false, "TCP ping", null, null);
        }
    }
}

/// <summary>Resolves MAC addresses on the local subnet using the Windows SendARP API (no admin, no Npcap).</summary>
public static class ArpResolver
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref uint physicalAddrLen);

    public static bool IsSupported => OperatingSystem.IsWindows();

    public static Task<string?> ResolveAsync(IPAddress address, CancellationToken ct)
    {
        if (!IsSupported || address.AddressFamily != AddressFamily.InterNetwork || !IsOnLocalSubnet(address))
            return Task.FromResult<string?>(null);
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            var mac = new byte[6];
            uint len = (uint)mac.Length;
            var dest = BitConverter.ToUInt32(address.GetAddressBytes(), 0);
            try
            {
                var rc = SendARP(dest, 0, mac, ref len);
                if (rc != 0 || len < 6) return null;
                return string.Join(":", mac.Take(6).Select(b => b.ToString("X2")));
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
            {
                return null;
            }
        }, ct);
    }

    public static bool IsOnLocalSubnet(IPAddress address)
    {
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                foreach (var ua in nic.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork || ua.IPv4Mask == null) continue;
                    var a = ua.Address.GetAddressBytes();
                    var m = ua.IPv4Mask.GetAddressBytes();
                    var t = address.GetAddressBytes();
                    bool same = true;
                    for (int i = 0; i < 4; i++) if ((a[i] & m[i]) != (t[i] & m[i])) { same = false; break; }
                    if (same) return true;
                }
            }
        }
        catch (NetworkInformationException) { }
        return false;
    }

    /// <summary>Local IPv4 subnets (for the "my local network" suggestion in the first-run wizard).</summary>
    public static IReadOnlyList<(string Cidr, string Interface)> LocalSubnets()
    {
        var list = new List<(string, string)>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var ua in nic.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork || ua.IPv4Mask == null) continue;
                    var prefix = ua.PrefixLength;
                    if (prefix < 16) prefix = 24; // never suggest anything larger than a /16; default to /24
                    var cidr = Targeting.IpMath.SubnetKey(ua.Address.ToString(), prefix);
                    if (!list.Any(x => x.Item1 == cidr)) list.Add((cidr, nic.Name));
                }
            }
        }
        catch (NetworkInformationException) { }
        return list;
    }
}

public sealed record NameInfo(string? DnsName, string? NetBiosName, string? Workgroup, string? NetBiosMac);

public sealed class NameResolver
{
    private readonly IProbeClient _probe;
    private readonly TimeSpan _timeout;

    public NameResolver(IProbeClient probe, TimeSpan timeout)
    {
        _probe = probe;
        _timeout = timeout;
    }

    public async Task<NameInfo> ResolveAsync(IPAddress address, CancellationToken ct)
    {
        var dnsTask = ReverseDnsAsync(address, ct);
        var nbTask = NetBiosAsync(address, ct);
        await Task.WhenAll(dnsTask, nbTask).ConfigureAwait(false);
        var nb = nbTask.Result;
        return new NameInfo(dnsTask.Result, nb?.ComputerName, nb?.Workgroup, nb?.Mac);
    }

    private async Task<string?> ReverseDnsAsync(IPAddress address, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(_timeout + _timeout);
            var entry = await Dns.GetHostEntryAsync(address.ToString(), cts.Token).ConfigureAwait(false);
            var name = entry.HostName;
            return string.IsNullOrWhiteSpace(name) || name == address.ToString() ? null : name;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ArgumentException)
        {
            ct.ThrowIfCancellationRequested();
            return null;
        }
    }

    private async Task<NetBiosPackets.NodeStatus?> NetBiosAsync(IPAddress address, CancellationToken ct)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork) return null;
        var reply = await _probe.UdpExchangeAsync(address.ToString(), 137, NetBiosPackets.NodeStatusRequest(), _timeout, ct).ConfigureAwait(false);
        return reply == null ? null : NetBiosPackets.ParseNodeStatus(reply);
    }
}

/// <summary>
/// MAC vendor lookup. A small built-in table covers common virtualisation and device vendors;
/// drop the full IEEE list (oui.csv from standards-oui.ieee.org) into the data folder for complete coverage.
/// </summary>
public sealed class OuiLookup
{
    private readonly Dictionary<string, string> _map = new(StringComparer.OrdinalIgnoreCase);

    public int Count => _map.Count;

    public OuiLookup(string? ieeeCsvPath = null)
    {
        using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("NetWarden.Core.oui.txt"))
        {
            if (s != null)
            {
                using var r = new StreamReader(s);
                LoadSimple(r);
            }
        }
        if (ieeeCsvPath != null && File.Exists(ieeeCsvPath))
        {
            using var r = new StreamReader(ieeeCsvPath);
            LoadIeeeCsv(r);
        }
    }

    public void LoadSimple(TextReader reader)
    {
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            line = line.Trim();
            if (line.Length < 8 || line.StartsWith('#')) continue;
            var parts = line.Split('\t', 2);
            if (parts.Length == 2) _map[Normalize(parts[0])] = parts[1].Trim();
        }
    }

    /// <summary>IEEE format: Registry,Assignment,Organization Name,Organization Address</summary>
    public void LoadIeeeCsv(TextReader reader)
    {
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            var fields = SplitCsv(line);
            if (fields.Count < 3 || fields[1].Length != 6 || fields[1] == "Assignment") continue;
            _map[fields[1].ToUpperInvariant()] = fields[2].Trim();
        }
    }

    public string? Lookup(string? mac)
    {
        if (string.IsNullOrEmpty(mac)) return null;
        var hex = new string(mac.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
        if (hex.Length < 6) return null;
        if (_map.TryGetValue(hex[..6], out var v)) return v;
        var second = Convert.ToByte(hex.Substring(0, 2), 16);
        if ((second & 0x02) != 0) return "Randomized / private MAC";
        return null;
    }

    private static string Normalize(string prefix) => new string(prefix.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();

    private static List<string> SplitCsv(string line)
    {
        var result = new List<string>();
        var sb = new System.Text.StringBuilder();
        bool quoted = false;
        for (int i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (c == '"')
            {
                if (quoted && i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                else quoted = !quoted;
            }
            else if (c == ',' && !quoted) { result.Add(sb.ToString()); sb.Clear(); }
            else sb.Append(c);
        }
        result.Add(sb.ToString());
        return result;
    }
}
