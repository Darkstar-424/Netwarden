using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace NetWarden.Core.Targeting;

public enum TargetKind { SingleAddress, Cidr, Range, HostName }

/// <summary>One parsed entry of a target list.</summary>
public sealed record TargetSpec(TargetKind Kind, string Original, uint Start = 0, uint End = 0, IPAddress? Address = null, string? HostName = null)
{
    public long Count => Kind switch
    {
        TargetKind.Cidr or TargetKind.Range => (long)End - Start + 1,
        _ => 1
    };

    public bool Contains(IPAddress ip)
    {
        switch (Kind)
        {
            case TargetKind.SingleAddress:
                return Address != null && Address.Equals(ip);
            case TargetKind.Cidr:
            case TargetKind.Range:
                if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
                var v = IpMath.ToUInt32(ip);
                return v >= Start && v <= End;
            default:
                return false;
        }
    }
}

public static class IpMath
{
    public static uint ToUInt32(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        if (b.Length != 4) throw new ArgumentException("IPv4 address expected.", nameof(ip));
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    public static IPAddress FromUInt32(uint v)
        => new(new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });

    public static string SubnetKey(string address, int prefix = 24)
    {
        if (!IPAddress.TryParse(address, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork) return "Other";
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        return $"{FromUInt32(ToUInt32(ip) & mask)}/{prefix}";
    }
}

public static class TargetParser
{
    private static readonly Regex HostNameRegex = new(
        @"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>Hard limit on how many addresses one scope may expand to (a /16).</summary>
    public const long MaxAddresses = 65536;

    /// <summary>Parses a whole target list separated by commas, semicolons, spaces or new lines.</summary>
    public static IReadOnlyList<TargetSpec> ParseList(string? text)
    {
        var result = new List<TargetSpec>();
        if (string.IsNullOrWhiteSpace(text)) return result;
        foreach (var rawLine in text.Split('\n'))
        {
            var hash = rawLine.IndexOf('#');
            var line = hash >= 0 ? rawLine[..hash] : rawLine;   // "# comment" or "10.0.0.5  # printer"
            foreach (var token in line.Split(new[] { ',', ';', ' ', '\r', '\t' }, StringSplitOptions.RemoveEmptyEntries))
                result.Add(Parse(token.Trim()));
        }
        return result;
    }

    public static bool TryParseList(string? text, out IReadOnlyList<TargetSpec> specs, out string? error)
    {
        try
        {
            specs = ParseList(text);
            error = null;
            return true;
        }
        catch (FormatException ex)
        {
            specs = Array.Empty<TargetSpec>();
            error = ex.Message;
            return false;
        }
    }

    public static TargetSpec Parse(string token)
    {
        var t = token.Trim();
        if (t.Length == 0) throw new FormatException("Empty target.");

        // CIDR
        var slash = t.IndexOf('/');
        if (slash > 0)
        {
            if (!IPAddress.TryParse(t[..slash], out var baseIp) || baseIp.AddressFamily != AddressFamily.InterNetwork)
                throw new FormatException($"'{t}': only IPv4 subnets are supported (e.g. 192.168.1.0/24).");
            if (!int.TryParse(t[(slash + 1)..], out var prefix) || prefix < 0 || prefix > 32)
                throw new FormatException($"'{t}': the number after '/' must be between 0 and 32.");
            var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
            var network = IpMath.ToUInt32(baseIp) & mask;
            var broadcast = network | ~mask;
            uint start = network, end = broadcast;
            if (prefix <= 30)
            {
                // Skip network and broadcast addresses for normal subnets.
                start = network + 1;
                end = broadcast - 1;
            }
            return new TargetSpec(TargetKind.Cidr, t, start, end);
        }

        // Range: a.b.c.d-e.f.g.h or a.b.c.d-h
        var dash = t.IndexOf('-');
        if (dash > 0 && IPAddress.TryParse(t[..dash], out var first) && first.AddressFamily == AddressFamily.InterNetwork)
        {
            var rest = t[(dash + 1)..];
            uint s = IpMath.ToUInt32(first);
            uint e;
            if (IPAddress.TryParse(rest, out var last) && last.AddressFamily == AddressFamily.InterNetwork && rest.Contains('.'))
            {
                e = IpMath.ToUInt32(last);
            }
            else if (byte.TryParse(rest, out var lastOctet))
            {
                e = (s & 0xFFFFFF00u) | lastOctet;
            }
            else
            {
                throw new FormatException($"'{t}': ranges look like 10.0.0.1-10.0.0.50 or 10.0.0.1-50.");
            }
            if (e < s) throw new FormatException($"'{t}': the end of the range is before the start.");
            return new TargetSpec(TargetKind.Range, t, s, e);
        }

        if (IPAddress.TryParse(t, out var ip))
        {
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                var v = IpMath.ToUInt32(ip);
                return new TargetSpec(TargetKind.SingleAddress, t, v, v, ip);
            }
            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                return new TargetSpec(TargetKind.SingleAddress, t, 0, 0, ip);
        }

        if (HostNameRegex.IsMatch(t) && !t.All(c => char.IsDigit(c) || c == '.'))
            return new TargetSpec(TargetKind.HostName, t, HostName: t.TrimEnd('.'));

        throw new FormatException($"'{t}' is not an IP address, subnet, range or host name.");
    }

    /// <summary>Expands IP-based specs into addresses (host names are returned separately for later resolution).</summary>
    public static IReadOnlyList<IPAddress> ExpandAddresses(IEnumerable<TargetSpec> specs, long limit = MaxAddresses)
    {
        var seen = new HashSet<IPAddress>();
        var list = new List<IPAddress>();
        foreach (var spec in specs)
        {
            switch (spec.Kind)
            {
                case TargetKind.SingleAddress:
                    if (spec.Address != null && seen.Add(spec.Address)) list.Add(spec.Address);
                    break;
                case TargetKind.Cidr:
                case TargetKind.Range:
                    for (ulong v = spec.Start; v <= spec.End; v++)
                    {
                        var ip = IpMath.FromUInt32((uint)v);
                        if (seen.Add(ip)) list.Add(ip);
                        if (list.Count > limit)
                            throw new InvalidOperationException($"The targets expand to more than {limit:N0} addresses. Split them into smaller scans.");
                    }
                    break;
            }
            if (list.Count > limit)
                throw new InvalidOperationException($"The targets expand to more than {limit:N0} addresses. Split them into smaller scans.");
        }
        return list;
    }

    public static long CountAddresses(IEnumerable<TargetSpec> specs) => specs.Sum(s => s.Count);
}

public static class AddressClassifier
{
    /// <summary>True for RFC1918, loopback, link-local, CGNAT (100.64/10) and IPv6 ULA/link-local/loopback.</summary>
    public static bool IsPrivate(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = ip.GetAddressBytes();
            return (b[0] & 0xFE) == 0xFC || ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal;
        }
        return false;
    }

    /// <summary>True if any part of the spec lies outside private address space.</summary>
    public static bool ContainsPublic(TargetSpec spec)
    {
        switch (spec.Kind)
        {
            case TargetKind.SingleAddress:
                return spec.Address != null && !IsPrivate(spec.Address);
            case TargetKind.Cidr:
            case TargetKind.Range:
                // Check the private blocks fully containing the range.
                foreach (var (s, e) in PrivateBlocksV4)
                    if (spec.Start >= s && spec.End <= e) return false;
                return true;
            default:
                return false; // host names are checked after resolution
        }
    }

    private static readonly (uint, uint)[] PrivateBlocksV4 =
    {
        (0x0A000000, 0x0AFFFFFF), // 10/8
        (0xAC100000, 0xAC1FFFFF), // 172.16/12
        (0xC0A80000, 0xC0A8FFFF), // 192.168/16
        (0xA9FE0000, 0xA9FEFFFF), // 169.254/16
        (0x64400000, 0x647FFFFF), // 100.64/10
        (0x7F000000, 0x7FFFFFFF)  // 127/8
    };
}
