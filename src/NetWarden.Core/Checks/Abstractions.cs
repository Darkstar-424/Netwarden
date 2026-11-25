using NetWarden.Core.Models;
using NetWarden.Core.Profiles;
using NetWarden.Core.Util;

namespace NetWarden.Core.Checks;

public enum CheckScope
{
    /// <summary>Run once per open port.</summary>
    Port,
    /// <summary>Run once per host.</summary>
    Host
}

/// <summary>
/// A pluggable vulnerability check. Add a new class implementing this interface (with a public parameterless
/// constructor) to NetWarden.Checks and it is discovered automatically; the engine never needs changing.
/// </summary>
public interface IVulnerabilityCheck
{
    /// <summary>Stable identifier, e.g. "smb.smbv1". Used in profiles to disable a check.</summary>
    string Id { get; }
    string Name { get; }
    string Category { get; }
    CheckScope Scope { get; }
    /// <summary>The furthest this check goes. SafeProbe checks send extra read-only requests.</summary>
    ProbeLevel Level { get; }
    /// <summary>True for checks that connect anonymously (off unless the profile allows it).</summary>
    bool RequiresAnonymousLogin { get; }
    /// <summary>False if the check works purely from facts already collected (usable on imported Nmap data).</summary>
    bool RequiresNetwork { get; }

    bool AppliesTo(CheckTarget target);
    Task<IReadOnlyList<Finding>> RunAsync(CheckContext context, CancellationToken ct);
}

public sealed record CheckTarget(HostResult Host, PortResult? Port)
{
    public ServiceInfo? Service => Port?.Service;
}

public sealed class CheckContext
{
    public required CheckTarget Target { get; init; }
    public required ScanProfile Profile { get; init; }
    public required IProbeClient Probe { get; init; }
    public ICveRepository? Cves { get; init; }
    public INwLog Log { get; init; } = NullLog.Instance;
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(3);
    public DateTimeOffset Now { get; init; } = DateTimeOffset.UtcNow;

    public HostResult Host => Target.Host;
    public PortResult? Port => Target.Port;
    public ServiceInfo? Service => Target.Port?.Service;

    /// <summary>Creates a finding pre-filled with host/port and a stable key.</summary>
    public Finding NewFinding(IVulnerabilityCheck check, string title, Severity severity, Confidence confidence, string? keyExtra = null)
        => new()
        {
            Key = Finding.MakeKey(check.Id, Host.Address, Port?.Port, keyExtra),
            CheckId = check.Id,
            Title = title,
            Severity = severity,
            Confidence = confidence,
            Host = Host.Address,
            HostName = Host.DisplayName == Host.Address ? null : Host.DisplayName,
            Port = Port?.Port,
            Protocol = Port?.Protocol
        };
}

public sealed record CveMatchRule(
    string CveId, string Vendor, string Product, string Criteria,
    string? VersionStartIncluding, string? VersionStartExcluding,
    string? VersionEndIncluding, string? VersionEndExcluding);

public sealed record CveRecord(
    string Id, string Description, double? Cvss, string? CvssVector, string? Severity,
    DateTimeOffset? Published, IReadOnlyList<string> References, bool Kev, string? KevRequiredAction, DateTimeOffset? KevDateAdded);

/// <summary>Read access to the local CVE database. Implemented by NetWarden.Data.</summary>
public interface ICveRepository
{
    bool IsAvailable { get; }
    IReadOnlyList<CveMatchRule> GetRules(string vendor, string product);
    CveRecord? Get(string cveId);
}

/// <summary>Severity from a CVSS v3.x base score (FIRST rating scale).</summary>
public static class CvssRating
{
    public static Severity FromScore(double? score) => score switch
    {
        null => Severity.Medium,
        >= 9.0 => Severity.Critical,
        >= 7.0 => Severity.High,
        >= 4.0 => Severity.Medium,
        > 0.0 => Severity.Low,
        _ => Severity.Info
    };
}
