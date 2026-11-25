using NetWarden.Core.Models;

namespace NetWarden.Reporting;

public sealed record FixItem(string Action, Severity Severity, bool Kev, int FindingCount, IReadOnlyList<string> Hosts, IReadOnlyList<Finding> Findings, string WhyItMatters, IReadOnlyList<string> Steps);

public sealed class ReportModel
{
    public required ScanResult Scan { get; init; }
    public required string Title { get; init; }
    public DateTimeOffset Generated { get; init; } = DateTimeOffset.Now;
    public required IReadOnlyList<Finding> Findings { get; init; }
    public required IReadOnlyList<FixItem> FixFirst { get; init; }
    public required string RiskRating { get; init; }
    public required string RiskExplanation { get; init; }
    public int Count(Severity s) => Findings.Count(f => f.Severity == s);
    public int KevCount => Findings.Count(f => f.Kev);
}

public static class ReportBuilder
{
    /// <summary>Builds the report from a scan. Accepted-risk and false-positive findings are left out of the counts but listed separately.</summary>
    public static ReportModel Build(ScanResult scan, string? title = null, bool includeClosed = false)
    {
        var findings = scan.AllFindings
            .Where(f => includeClosed || f.Status == FindingStatus.Open)
            .OrderByDescending(f => f.Severity).ThenByDescending(f => f.Kev).ThenByDescending(f => f.Cvss ?? 0).ThenBy(f => f.Host)
            .ToList();
        var (rating, why) = Rate(findings);
        return new ReportModel
        {
            Scan = scan,
            Title = title ?? $"Network security assessment – {scan.ScopeName}",
            Findings = findings,
            FixFirst = GroupFixes(findings),
            RiskRating = rating,
            RiskExplanation = why
        };
    }

    public static (string Rating, string Why) Rate(IReadOnlyCollection<Finding> open)
    {
        if (open.Any(f => f.Kev)) return ("Critical", "At least one weakness is known to be actively exploited by attackers (CISA KEV).");
        if (open.Any(f => f.Severity == Severity.Critical)) return ("Critical", "Critical weaknesses were found that could let an attacker take over a device remotely.");
        if (open.Any(f => f.Severity == Severity.High)) return ("High", "High-severity weaknesses were found. Fix them soon.");
        if (open.Any(f => f.Severity == Severity.Medium)) return ("Medium", "Only medium or lower issues were found. Plan fixes as part of normal maintenance.");
        if (open.Any(f => f.Severity == Severity.Low)) return ("Low", "Only minor issues were found.");
        return ("Minimal", "No open issues were found by this scan.");
    }

    /// <summary>Groups findings that share a fix (e.g. "Turn off SMBv1" on 3 hosts) and ranks them.</summary>
    public static IReadOnlyList<FixItem> GroupFixes(IEnumerable<Finding> findings)
    {
        return findings
            .GroupBy(f => string.IsNullOrEmpty(f.FixAction) ? f.Title : f.FixAction)
            .Select(g =>
            {
                var worst = g.OrderByDescending(f => f.Severity).ThenByDescending(f => f.Kev).First();
                var hosts = g.Select(f => f.HostName != null ? $"{f.HostName} ({f.Host})" : f.Host).Distinct().ToList();
                var action = g.Key;
                if (hosts.Count > 1 && !action.Contains(" on ", StringComparison.Ordinal)) action = $"{action} on {hosts.Count} devices";
                return new FixItem(action, worst.Severity, g.Any(f => f.Kev), g.Count(), hosts, g.ToList(), FirstSentence(worst.Description), worst.Remediation);
            })
            .OrderByDescending(x => x.Kev).ThenByDescending(x => x.Severity).ThenByDescending(x => x.FindingCount)
            .ToList();
    }

    private static string FirstSentence(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var i = s.IndexOf(". ", StringComparison.Ordinal);
        return i < 0 ? s : s[..(i + 1)];
    }
}

public sealed record ScanDiff(
    IReadOnlyList<HostResult> NewHosts,
    IReadOnlyList<HostResult> GoneHosts,
    IReadOnlyList<(string Host, PortResult Port)> NewPorts,
    IReadOnlyList<(string Host, PortResult Port)> ClosedPorts,
    IReadOnlyList<Finding> NewFindings,
    IReadOnlyList<Finding> ResolvedFindings)
{
    public bool IsEmpty => NewHosts.Count + GoneHosts.Count + NewPorts.Count + ClosedPorts.Count + NewFindings.Count + ResolvedFindings.Count == 0;

    /// <summary>Compares an older scan (before) with a newer one (after).</summary>
    public static ScanDiff Compare(ScanResult before, ScanResult after)
    {
        var b = before.LiveHosts.GroupBy(h => h.Address).ToDictionary(g => g.Key, g => g.First());
        var a = after.LiveHosts.GroupBy(h => h.Address).ToDictionary(g => g.Key, g => g.First());
        var newHosts = a.Values.Where(h => !b.ContainsKey(h.Address)).ToList();
        var goneHosts = b.Values.Where(h => !a.ContainsKey(h.Address)).ToList();
        var newPorts = new List<(string, PortResult)>();
        var closedPorts = new List<(string, PortResult)>();
        foreach (var host in a.Values.Where(h => b.ContainsKey(h.Address)))
        {
            var old = b[host.Address].OpenPorts.Select(p => p.Label).ToHashSet();
            var now = host.OpenPorts.Select(p => p.Label).ToHashSet();
            newPorts.AddRange(host.OpenPorts.Where(p => !old.Contains(p.Label)).Select(p => (host.Address, p)));
            closedPorts.AddRange(b[host.Address].OpenPorts.Where(p => !now.Contains(p.Label)).Select(p => (host.Address, p)));
        }
        var beforeKeys = before.AllFindings.Select(f => f.Key).ToHashSet();
        var afterKeys = after.AllFindings.Select(f => f.Key).ToHashSet();
        var newFindings = after.AllFindings.Where(f => !beforeKeys.Contains(f.Key)).OrderByDescending(f => f.Severity).ToList();
        // A finding only counts as resolved if its host was scanned again.
        var resolved = before.AllFindings.Where(f => !afterKeys.Contains(f.Key) && a.ContainsKey(f.Host)).OrderByDescending(f => f.Severity).ToList();
        return new ScanDiff(newHosts, goneHosts, newPorts, closedPorts, newFindings, resolved);
    }
}
