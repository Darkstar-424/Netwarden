using System.Text.Json.Serialization;

namespace NetWarden.Core.Models;

public sealed class ServiceInfo
{
    /// <summary>Short service name, e.g. "http", "ssh", "smb".</summary>
    public string Name { get; set; } = "unknown";
    public string? Product { get; set; }
    public string? Version { get; set; }
    public string? Banner { get; set; }
    /// <summary>Candidate CPE 2.3 names for CVE matching (may be several, e.g. nginx has two vendors in NVD).</summary>
    public List<string> Cpes { get; set; } = new();
    public bool Tls { get; set; }
    /// <summary>Protocol facts gathered during detection (e.g. "smb.signing" = "required").</summary>
    public Dictionary<string, string> Facts { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    [JsonIgnore]
    public string Display => string.Join(' ', new[] { Product, Version }.Where(s => !string.IsNullOrWhiteSpace(s))) is { Length: > 0 } pv
        ? $"{Name} ({pv})"
        : Name;

    public string? Fact(string key) => Facts.TryGetValue(key, out var v) ? v : null;
}

public sealed class CipherInfo
{
    public ushort Id { get; set; }
    public string Name { get; set; } = "";
    public string Protocol { get; set; } = "";
    public bool Weak { get; set; }
    public bool ForwardSecret { get; set; }
}

public sealed class CertificateInfo
{
    public string Subject { get; set; } = "";
    public string Issuer { get; set; } = "";
    public DateTimeOffset NotBefore { get; set; }
    public DateTimeOffset NotAfter { get; set; }
    public bool SelfSigned { get; set; }
    public bool ChainTrusted { get; set; }
    public string KeyAlgorithm { get; set; } = "";
    public int KeySize { get; set; }
    public string SignatureAlgorithm { get; set; } = "";
    public string Thumbprint { get; set; } = "";
    public List<string> SubjectAltNames { get; set; } = new();
}

public sealed class TlsInfo
{
    /// <summary>Supported protocol versions, e.g. "SSLv3", "TLS 1.0", "TLS 1.3".</summary>
    public List<string> Protocols { get; set; } = new();
    public List<CipherInfo> Ciphers { get; set; } = new();
    public CertificateInfo? Certificate { get; set; }
    /// <summary>Size in bits of the Diffie-Hellman prime offered with DHE suites, if seen.</summary>
    public int? DhPrimeBits { get; set; }
}

public sealed class PortResult
{
    public int Port { get; set; }
    public TransportProtocol Protocol { get; set; }
    public PortState State { get; set; }
    public ServiceInfo? Service { get; set; }
    public TlsInfo? Tls { get; set; }

    [JsonIgnore]
    public string Label => $"{Port}/{(Protocol == TransportProtocol.Tcp ? "tcp" : "udp")}";
}

/// <summary>One application or service identified on a device.</summary>
public sealed class AppInfo
{
    public string Name { get; set; } = "";
    /// <summary>Plain-English group, e.g. "Web app", "File sharing", "Media", "Remote access".</summary>
    public string Category { get; set; } = "";
    public string? Version { get; set; }
    /// <summary>Where it was seen, e.g. "443/tcp", "Bonjour", "UPnP".</summary>
    public string Where { get; set; } = "";
    /// <summary>How it was identified, e.g. "page title", "service banner", "Bonjour advertisement".</summary>
    public string Source { get; set; } = "";
    public string? Detail { get; set; }

    [JsonIgnore]
    public string Display => string.IsNullOrEmpty(Version) ? Name : $"{Name} {Version}";
}

public sealed class OsGuess
{
    public string Family { get; set; } = "Unknown";
    public string? Detail { get; set; }
    /// <summary>0-100.</summary>
    public int Confidence { get; set; }
    public string Basis { get; set; } = "";

    [JsonIgnore]
    public string Display => string.IsNullOrEmpty(Detail) ? Family : $"{Family} ({Detail})";
}

public sealed class HostResult
{
    public string Address { get; set; } = "";
    public bool IsUp { get; set; }
    public string? HostName { get; set; }
    public string? NetBiosName { get; set; }
    public string? MacAddress { get; set; }
    public string? Vendor { get; set; }
    public int? Ttl { get; set; }
    public double? LatencyMs { get; set; }
    public string DiscoveryMethod { get; set; } = "";
    public List<PortResult> Ports { get; set; } = new();
    public OsGuess? Os { get; set; }
    /// <summary>Make and model the device reports about itself (UPnP / Bonjour), e.g. "Synology DS920+".</summary>
    public string? DeviceModel { get; set; }
    /// <summary>Kind of device inferred from what it advertises, e.g. "Printer", "NAS", "Media player".</summary>
    public string? DeviceType { get; set; }
    /// <summary>Name the device gives itself on the network (UPnP friendly name or Bonjour name).</summary>
    public string? FriendlyName { get; set; }
    /// <summary>Applications and services identified on the device, in plain words.</summary>
    public List<AppInfo> Apps { get; set; } = new();
    public List<Finding> Findings { get; set; } = new();

    [JsonIgnore]
    public string DisplayName => NetBiosName ?? HostName ?? Address;

    [JsonIgnore]
    public IEnumerable<PortResult> OpenPorts => Ports.Where(p => p.State == PortState.Open);
}

public sealed class Finding
{
    /// <summary>Stable identity across scans: check|host|port|cve. Used to carry status forward.</summary>
    public string Key { get; set; } = "";
    public string CheckId { get; set; } = "";
    public string Title { get; set; } = "";
    public Severity Severity { get; set; }
    public Confidence Confidence { get; set; }
    public string Host { get; set; } = "";
    public string? HostName { get; set; }
    public int? Port { get; set; }
    public TransportProtocol? Protocol { get; set; }
    public string Description { get; set; } = "";
    public string Evidence { get; set; } = "";
    public double? Cvss { get; set; }
    public string? CvssVector { get; set; }
    public List<string> Cves { get; set; } = new();
    /// <summary>Listed in CISA's Known Exploited Vulnerabilities catalog.</summary>
    public bool Kev { get; set; }
    public List<string> References { get; set; } = new();
    public List<string> Remediation { get; set; } = new();
    /// <summary>Plain-English one-line action used to group findings into "fix these first" items.</summary>
    public string FixAction { get; set; } = "";
    public FindingStatus Status { get; set; }
    public string? StatusNote { get; set; }

    [JsonIgnore]
    public string Location => Port is int p ? $"{Host}:{p}/{(Protocol == TransportProtocol.Udp ? "udp" : "tcp")}" : Host;

    public static string MakeKey(string checkId, string host, int? port, string? extra = null)
        => string.Join('|', checkId, host, port?.ToString() ?? "-", extra ?? "-");
}

public sealed class ScanResult
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTimeOffset Started { get; set; }
    public DateTimeOffset? Finished { get; set; }
    public string ProfileName { get; set; } = "";
    public string ScopeName { get; set; } = "";
    public List<string> Targets { get; set; } = new();
    public string StartedBy { get; set; } = "";
    public ScanState State { get; set; }
    public List<HostResult> Hosts { get; set; } = new();
    public List<string> Errors { get; set; } = new();
    public List<string> Warnings { get; set; } = new();

    [JsonIgnore]
    public IEnumerable<HostResult> LiveHosts => Hosts.Where(h => h.IsUp);

    [JsonIgnore]
    public IEnumerable<Finding> AllFindings => Hosts.SelectMany(h => h.Findings);

    [JsonIgnore]
    public int OpenPortCount => Hosts.Sum(h => h.Ports.Count(p => p.State == PortState.Open));

    [JsonIgnore]
    public TimeSpan? Duration => Finished - Started;

    public int CountBySeverity(Severity s, bool openOnly = true)
        => AllFindings.Count(f => f.Severity == s && (!openOnly || f.Status == FindingStatus.Open));
}

public sealed class ScanProgress
{
    public ScanPhase Phase { get; init; }
    public long Completed { get; init; }
    public long Total { get; init; }
    public string Message { get; init; } = "";
    public TimeSpan? Eta { get; init; }
    public int HostsUp { get; init; }
    public int OpenPorts { get; init; }
    public int Findings { get; init; }
    public double Fraction => Total <= 0 ? 0 : Math.Clamp((double)Completed / Total, 0, 1);
}
