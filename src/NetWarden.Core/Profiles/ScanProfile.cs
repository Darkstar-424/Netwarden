using System.Text.Json;
using System.Text.Json.Serialization;
using NetWarden.Core.Models;

namespace NetWarden.Core.Profiles;

public sealed record TimingSettings(int Concurrency, int TimeoutMs, int RatePerSecond, int HostParallelism, int Retries)
{
    public static TimingSettings For(TimingTemplate t) => t switch
    {
        TimingTemplate.Gentle => new TimingSettings(10, 3000, 20, 2, 1),
        TimingTemplate.Polite => new TimingSettings(50, 1500, 100, 4, 1),
        TimingTemplate.Normal => new TimingSettings(150, 1000, 400, 8, 0),
        TimingTemplate.Fast => new TimingSettings(400, 750, 1500, 16, 0),
        _ => new TimingSettings(50, 1500, 100, 4, 1)
    };
}

/// <summary>A saved set of scan options. Built-in presets are read-only; custom ones are stored as JSON.</summary>
public sealed class ScanProfile
{
    public string Name { get; set; } = "Custom";
    /// <summary>Plain-English goal shown in Simple mode.</summary>
    public string Goal { get; set; } = "";
    public string Description { get; set; } = "";
    public bool BuiltIn { get; set; }

    // Discovery
    public bool IcmpPing { get; set; } = true;
    public bool TcpPing { get; set; } = true;
    public bool ArpDiscovery { get; set; } = true;
    public bool TreatAllHostsAsUp { get; set; }
    public bool ResolveNames { get; set; } = true;

    // Ports
    /// <summary>"top100", "top1000", "all", or a list such as "22,80,443,8000-8100". Empty means no port scan.</summary>
    public string TcpPorts { get; set; } = "top1000";
    public bool UdpProbes { get; set; }

    // Detection
    public bool ServiceDetection { get; set; } = true;
    public bool TlsInspection { get; set; } = true;
    public bool OsDetection { get; set; } = true;
    /// <summary>Identify apps and device models: web-app fingerprints, Bonjour/mDNS and UPnP device descriptions.</summary>
    public bool IdentifyApps { get; set; } = true;

    // Vulnerability assessment
    public bool VulnerabilityChecks { get; set; } = true;
    public ProbeLevel MaxProbeLevel { get; set; } = ProbeLevel.SafeProbe;
    /// <summary>Checks that connect anonymously (anonymous FTP, Windows null session). Off by default.</summary>
    public bool AllowAnonymousLoginChecks { get; set; }
    public List<string> DisabledChecks { get; set; } = new();

    // Timing
    public TimingTemplate Timing { get; set; } = TimingTemplate.Polite;
    public int? MaxConcurrency { get; set; }
    public int? TimeoutMs { get; set; }
    public int? MaxRatePerSecond { get; set; }

    [JsonIgnore]
    public TimingSettings EffectiveTiming
    {
        get
        {
            var t = TimingSettings.For(Timing);
            return t with
            {
                Concurrency = Math.Clamp(MaxConcurrency ?? t.Concurrency, 1, 2000),
                TimeoutMs = Math.Clamp(TimeoutMs ?? t.TimeoutMs, 100, 30000),
                RatePerSecond = Math.Clamp(MaxRatePerSecond ?? t.RatePerSecond, 1, 20000)
            };
        }
    }

    public ScanProfile Clone(string? newName = null)
    {
        var json = JsonSerializer.Serialize(this, ProfileJson.Options);
        var copy = JsonSerializer.Deserialize<ScanProfile>(json, ProfileJson.Options)!;
        copy.BuiltIn = false;
        if (newName != null) copy.Name = newName;
        return copy;
    }
}

public static class ProfileJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static string Serialize(ScanProfile p) => JsonSerializer.Serialize(p, Options);

    public static ScanProfile Deserialize(string json)
        => JsonSerializer.Deserialize<ScanProfile>(json, Options) ?? throw new InvalidDataException("Profile file is empty.");
}

public static class BuiltInProfiles
{
    public const string QuickDiscovery = "Quick Discovery";
    public const string Standard = "Standard";
    public const string FullTcp = "Full TCP";
    public const string WebServices = "Web Services";
    public const string WindowsAudit = "Windows Network Audit";
    public const string Custom = "Custom";

    public static IReadOnlyList<ScanProfile> All { get; } = new List<ScanProfile>
    {
        new()
        {
            Name = QuickDiscovery, BuiltIn = true,
            Goal = "Find devices on my network",
            Description = "Lists the devices that answer and their names. No service or vulnerability checks. Takes a minute or two.",
            TcpPorts = "", ServiceDetection = false, TlsInspection = false, VulnerabilityChecks = false, OsDetection = true
        },
        new()
        {
            Name = Standard, BuiltIn = true,
            Goal = "Quick health check",
            Description = "Checks the ~1000 most common ports, identifies services and looks for known weaknesses.",
            TcpPorts = "top1000", UdpProbes = true
        },
        new()
        {
            Name = FullTcp, BuiltIn = true,
            Goal = "Deep check (takes longer)",
            Description = "Checks all 65,535 TCP ports on every device. Thorough but slow on large networks.",
            TcpPorts = "all", UdpProbes = true
        },
        new()
        {
            Name = WebServices, BuiltIn = true,
            Goal = "Check my web servers",
            Description = "Focuses on websites and web admin pages: TLS settings, certificates, exposed files and admin pages.",
            TcpPorts = "80,81,443,591,2375,3000,4443,5000,5601,7001,7443,8000,8008,8080-8090,8443,8888,9000,9090,9200,9443,10000",
            UdpProbes = false
        },
        new()
        {
            Name = WindowsAudit, BuiltIn = true,
            Goal = "Check my Windows network",
            Description = "Looks at file sharing (SMB), Remote Desktop, domain services and SQL Server on Windows machines.",
            TcpPorts = "53,88,135,139,389,445,464,593,636,1433,3268,3269,3389,5985,5986,9389",
            UdpProbes = true
        },
        new()
        {
            Name = Custom, BuiltIn = true,
            Goal = "Custom (advanced)",
            Description = "Start from the Standard settings and change anything.",
            TcpPorts = "top1000", UdpProbes = true
        }
    };

    public static ScanProfile Get(string name)
        => All.FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase))?.Clone(name) is { } c
            ? WithBuiltIn(c)
            : throw new KeyNotFoundException($"No built-in profile named '{name}'.");

    private static ScanProfile WithBuiltIn(ScanProfile p) { p.BuiltIn = true; return p; }
}
