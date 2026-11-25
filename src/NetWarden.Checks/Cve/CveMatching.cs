using NetWarden.Core.Checks;
using NetWarden.Core.Fingerprinting;
using NetWarden.Core.Models;

namespace NetWarden.Checks.Cve;

/// <summary>Compares version strings such as "8.2p1", "2.4.41", "1.0.2k" piece by piece (numbers numerically, letters alphabetically).</summary>
public static class VersionComparer
{
    public static int Compare(string? a, string? b)
    {
        var ta = Tokenize(a ?? "");
        var tb = Tokenize(b ?? "");
        for (int i = 0; i < Math.Max(ta.Count, tb.Count); i++)
        {
            var x = i < ta.Count ? ta[i] : null;
            var y = i < tb.Count ? tb[i] : null;
            // Missing numeric parts count as 0 ("1.0" == "1.0.0"); a missing part before letters sorts first ("1.0.2" < "1.0.2k").
            if (x == null) { if (y is long) x = 0L; else return -1; }
            if (y == null) { if (x is long) y = 0L; else return 1; }
            int c;
            if (x is long lx && y is long ly) c = lx.CompareTo(ly);
            else if (x is long) c = 1;          // numbers sort after letters at the same position: 1.0a < 1.0.1
            else if (y is long) c = -1;
            else c = string.CompareOrdinal((string)x, (string)y);
            if (c != 0) return Math.Sign(c);
        }
        return 0;
    }

    private static List<object> Tokenize(string v)
    {
        var tokens = new List<object>();
        int i = 0;
        v = v.Trim().ToLowerInvariant();
        while (i < v.Length)
        {
            if (char.IsDigit(v[i]))
            {
                int start = i;
                while (i < v.Length && char.IsDigit(v[i])) i++;
                tokens.Add(long.TryParse(v[start..i], out var n) ? n : long.MaxValue);
            }
            else if (char.IsLetter(v[i]))
            {
                int start = i;
                while (i < v.Length && char.IsLetter(v[i])) i++;
                tokens.Add(v[start..i]);
            }
            else i++;
        }
        return tokens;
    }
}

public static class CpeMatcher
{
    /// <summary>Does the detected CPE (with a concrete version) fall inside the NVD rule?</summary>
    public static bool Matches(string detectedCpe, CveMatchRule rule)
    {
        var d = CpeMapper.Parse(detectedCpe);
        var r = CpeMapper.Parse(rule.Criteria);
        if (d == null || r == null) return false;
        if (!string.Equals(d.Vendor, r.Vendor, StringComparison.OrdinalIgnoreCase) || !string.Equals(d.Product, r.Product, StringComparison.OrdinalIgnoreCase))
            return false;
        if (d.Version is "*" or "-" or "") return false;

        var detectedFull = d.Update is "*" or "-" or "" ? d.Version : d.Version + d.Update;

        if (r.Version is not ("*" or "-" or ""))
        {
            // Exact version rule; the update field must agree when the rule specifies one.
            if (VersionComparer.Compare(d.Version, r.Version) != 0) return false;
            if (r.Update is "*" or "-" or "") return true;
            return string.Equals(d.Update, r.Update, StringComparison.OrdinalIgnoreCase);
        }

        bool hasRange = rule.VersionStartIncluding != null || rule.VersionStartExcluding != null || rule.VersionEndIncluding != null || rule.VersionEndExcluding != null;
        if (!hasRange) return false; // "all versions" rules are too broad to report

        if (rule.VersionStartIncluding != null && VersionComparer.Compare(detectedFull, rule.VersionStartIncluding) < 0) return false;
        if (rule.VersionStartExcluding != null && VersionComparer.Compare(detectedFull, rule.VersionStartExcluding) <= 0) return false;
        if (rule.VersionEndIncluding != null && VersionComparer.Compare(detectedFull, rule.VersionEndIncluding) > 0) return false;
        if (rule.VersionEndExcluding != null && VersionComparer.Compare(detectedFull, rule.VersionEndExcluding) >= 0) return false;
        return true;
    }

    public static IReadOnlyList<string> MatchingCves(string detectedCpe, IEnumerable<CveMatchRule> rules)
        => rules.Where(r => Matches(detectedCpe, r)).Select(r => r.CveId).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
}

/// <summary>Matches detected product versions against the local NVD/KEV database. Results are labelled "Potential".</summary>
public sealed class CveVersionCheck : CheckBase
{
    public const int MaxFindingsPerService = 50;

    public override string Id => "cve.version-match";
    public override string Name => "Known vulnerabilities for detected version";
    public override string Category => "Known vulnerabilities (CVE)";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Service?.Cpes.Count > 0;

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        if (ctx.Cves is not { IsAvailable: true } repo) return None();
        var service = ctx.Service!;
        var results = new List<Finding>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var cpe in service.Cpes)
        {
            var parts = CpeMapper.Parse(cpe);
            if (parts == null) continue;
            var rules = repo.GetRules(parts.Vendor, parts.Product);
            foreach (var cveId in CpeMatcher.MatchingCves(cpe, rules))
            {
                if (!seen.Add(cveId)) continue;
                var rec = repo.Get(cveId);
                if (rec == null) continue;
                var productName = !string.IsNullOrEmpty(service.Product) && service.Cpes.Count == 1 ? service.Product : parts.Product.Replace('_', ' ');
                var product = $"{productName} {parts.Version}{(parts.Update is "*" ? "" : parts.Update)}";
                var f = ctx.NewFinding(this, $"{cveId} in {product}", CvssRating.FromScore(rec.Cvss), Confidence.Potential, cveId);
                f.Description = rec.Description;
                f.Evidence = $"Detected: {service.Display}" + (service.Banner != null ? $"\nBanner: {service.Banner}" : "") +
                             $"\nCPE: {cpe}\nVersion-based match: vendors sometimes back-port fixes without changing the version, so confirm against vendor advisories.";
                f.Cves.Add(cveId);
                f.Cvss = rec.Cvss;
                f.CvssVector = rec.CvssVector;
                f.Kev = rec.Kev;
                if (rec.Kev && f.Severity < Severity.High) f.Severity = Severity.High;
                f.FixAction = $"Update {productName} on {ctx.Host.DisplayName}";
                f.Remediation.Add($"Update {productName} to a version that fixes {cveId} (see the vendor advisory in the references).");
                if (rec.Kev && !string.IsNullOrEmpty(rec.KevRequiredAction)) f.Remediation.Add("CISA required action: " + rec.KevRequiredAction);
                f.Remediation.Add("If the vendor back-ported the fix, mark this finding as a false positive with a note.");
                f.References.Add($"https://nvd.nist.gov/vuln/detail/{cveId}");
                f.References.AddRange(rec.References.Where(r => !f.References.Contains(r, StringComparer.OrdinalIgnoreCase)).Take(5));
                results.Add(f);
            }
        }
        var ordered = results.OrderByDescending(f => f.Kev).ThenByDescending(f => f.Cvss ?? 0).ToList();
        if (ordered.Count > MaxFindingsPerService)
        {
            ctx.Log.Info($"{ctx.Host.Address}:{ctx.Port?.Port} matched {ordered.Count} CVEs; reporting the {MaxFindingsPerService} most severe.");
            ordered = ordered.Take(MaxFindingsPerService).ToList();
        }
        return Task.FromResult<IReadOnlyList<Finding>>(ordered);
    }
}
