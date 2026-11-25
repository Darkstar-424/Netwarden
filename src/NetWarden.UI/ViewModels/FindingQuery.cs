using NetWarden.Core.Models;

namespace NetWarden.UI.ViewModels;

/// <summary>
/// Advanced-mode filter syntax, e.g. "severity>=high kev:true host:192.168.1.10 port:445 cve:2017 status:open conf:confirmed smb".
/// Words without a prefix search title, host and CVEs.
/// </summary>
public sealed class FindingQuery
{
    public Severity? MinSeverity { get; private set; }
    public Severity? ExactSeverity { get; private set; }
    public bool? Kev { get; private set; }
    public List<string> Hosts { get; } = new();
    public List<int> Ports { get; } = new();
    public List<string> Cves { get; } = new();
    public FindingStatus? Status { get; private set; }
    public Confidence? Confidence { get; private set; }
    public List<string> Words { get; } = new();
    public List<string> Errors { get; } = new();

    public static FindingQuery Parse(string? text)
    {
        var q = new FindingQuery();
        if (string.IsNullOrWhiteSpace(text)) return q;
        foreach (var raw in text.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            var token = raw.Trim();
            var lower = token.ToLowerInvariant();
            if (lower.StartsWith("severity>=", StringComparison.Ordinal) || lower.StartsWith("sev>=", StringComparison.Ordinal))
            {
                if (TrySeverity(lower[(lower.IndexOf(">=", StringComparison.Ordinal) + 2)..], out var s)) q.MinSeverity = s; else q.Errors.Add(token);
            }
            else if (lower.StartsWith("severity:", StringComparison.Ordinal) || lower.StartsWith("sev:", StringComparison.Ordinal))
            {
                if (TrySeverity(lower[(lower.IndexOf(':') + 1)..], out var s)) q.ExactSeverity = s; else q.Errors.Add(token);
            }
            else if (lower.StartsWith("kev:", StringComparison.Ordinal))
            {
                q.Kev = lower[4..] is "true" or "yes" or "1";
            }
            else if (lower.StartsWith("host:", StringComparison.Ordinal)) q.Hosts.Add(lower[5..]);
            else if (lower.StartsWith("port:", StringComparison.Ordinal))
            {
                if (int.TryParse(lower[5..], out var p)) q.Ports.Add(p); else q.Errors.Add(token);
            }
            else if (lower.StartsWith("cve:", StringComparison.Ordinal)) q.Cves.Add(lower[4..]);
            else if (lower.StartsWith("status:", StringComparison.Ordinal))
            {
                q.Status = lower[7..] switch
                {
                    "open" => FindingStatus.Open,
                    "accepted" or "acceptedrisk" or "accepted-risk" => FindingStatus.AcceptedRisk,
                    "fp" or "falsepositive" or "false-positive" => FindingStatus.FalsePositive,
                    "fixed" => FindingStatus.Fixed,
                    _ => null
                };
                if (q.Status == null) q.Errors.Add(token);
            }
            else if (lower.StartsWith("conf:", StringComparison.Ordinal) || lower.StartsWith("confidence:", StringComparison.Ordinal))
            {
                q.Confidence = lower[(lower.IndexOf(':') + 1)..] switch
                {
                    "confirmed" => Core.Models.Confidence.Confirmed,
                    "config" or "configuration" => Core.Models.Confidence.Configuration,
                    "potential" or "version" => Core.Models.Confidence.Potential,
                    _ => null
                };
                if (q.Confidence == null) q.Errors.Add(token);
            }
            else q.Words.Add(lower);
        }
        return q;
    }

    private static bool TrySeverity(string s, out Severity sev)
    {
        switch (s)
        {
            case "crit": case "critical": sev = Severity.Critical; return true;
            case "high": sev = Severity.High; return true;
            case "med": case "medium": sev = Severity.Medium; return true;
            case "low": sev = Severity.Low; return true;
            case "info": sev = Severity.Info; return true;
            default: sev = Severity.Info; return false;
        }
    }

    public bool Matches(Finding f)
    {
        if (MinSeverity is Severity min && f.Severity < min) return false;
        if (ExactSeverity is Severity ex && f.Severity != ex) return false;
        if (Kev is bool k && f.Kev != k) return false;
        if (Hosts.Count > 0 && !Hosts.Any(h => f.Host.Contains(h, StringComparison.OrdinalIgnoreCase) || (f.HostName?.Contains(h, StringComparison.OrdinalIgnoreCase) ?? false))) return false;
        if (Ports.Count > 0 && (f.Port is not int p || !Ports.Contains(p))) return false;
        if (Cves.Count > 0 && !Cves.Any(c => f.Cves.Any(x => x.Contains(c, StringComparison.OrdinalIgnoreCase)))) return false;
        if (Status is FindingStatus st && f.Status != st) return false;
        if (Confidence is Confidence cf && f.Confidence != cf) return false;
        foreach (var w in Words)
        {
            var hay = $"{f.Title} {f.Host} {f.HostName} {string.Join(' ', f.Cves)} {f.CheckId} {f.Description}";
            if (!hay.Contains(w, StringComparison.OrdinalIgnoreCase)) return false;
        }
        return true;
    }
}
