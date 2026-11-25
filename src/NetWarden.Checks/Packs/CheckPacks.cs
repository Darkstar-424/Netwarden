using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using NetWarden.Core.Checks;
using NetWarden.Core.Models;
using NetWarden.Core.Util;

namespace NetWarden.Checks.Packs;

/// <summary>A JSON check pack: a list of read-only HTTP probe templates.</summary>
public sealed class CheckPack
{
    public string Name { get; set; } = "";
    public string Version { get; set; } = "";
    public List<HttpTemplate> Templates { get; set; } = new();
}

public sealed class HttpTemplate
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public Severity Severity { get; set; } = Severity.Medium;
    /// <summary>GET, HEAD or OPTIONS only. Anything else is rejected when the pack loads.</summary>
    public string Method { get; set; } = "GET";
    public string Path { get; set; } = "/";
    /// <summary>Only run on these ports (empty = any HTTP(S) service).</summary>
    public List<int> Ports { get; set; } = new();
    public List<int> Status { get; set; } = new();
    /// <summary>Regular expressions that must ALL match the body.</summary>
    public List<string> BodyMatches { get; set; } = new();
    /// <summary>Regular expressions that must NOT match the body (filters soft-404 pages).</summary>
    public List<string> BodyNotMatches { get; set; } = new();
    /// <summary>"Header-Name: regex" pairs that must match.</summary>
    public List<string> HeaderMatches { get; set; } = new();
    public string Description { get; set; } = "";
    /// <summary>What to show as evidence. The matched content itself is never stored (it may contain secrets).</summary>
    public string EvidenceNote { get; set; } = "";
    public string FixAction { get; set; } = "";
    public List<string> Remediation { get; set; } = new();
    public List<string> References { get; set; } = new();
    public List<string> Cves { get; set; } = new();
    public double? Cvss { get; set; }
}

public static class CheckPackValidator
{
    private static readonly Regex SafePath = new(@"^/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]{0,200}$", RegexOptions.Compiled);

    public static IReadOnlyList<string> Validate(CheckPack pack)
    {
        var errors = new List<string>();
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var t in pack.Templates)
        {
            var where = $"template '{t.Id}'";
            if (string.IsNullOrWhiteSpace(t.Id) || !Regex.IsMatch(t.Id, @"^[a-z0-9][a-z0-9.\-]{1,60}$")) errors.Add($"{where}: id must be lower-case letters, digits, dots or dashes.");
            if (!ids.Add(t.Id)) errors.Add($"{where}: duplicate id.");
            if (t.Method is not ("GET" or "HEAD" or "OPTIONS")) errors.Add($"{where}: method '{t.Method}' is not allowed (read-only methods only: GET, HEAD, OPTIONS).");
            if (!SafePath.IsMatch(t.Path) || t.Path.Contains("..", StringComparison.Ordinal) || t.Path.Contains("\r") || t.Path.Contains("\n"))
                errors.Add($"{where}: path '{t.Path}' is not allowed.");
            if (t.Status.Count == 0 && t.BodyMatches.Count == 0 && t.HeaderMatches.Count == 0) errors.Add($"{where}: needs at least one matcher.");
            foreach (var r in t.BodyMatches.Concat(t.BodyNotMatches))
                if (!IsValidRegex(r)) errors.Add($"{where}: invalid regex '{r}'.");
            foreach (var h in t.HeaderMatches)
            {
                var c = h.IndexOf(':');
                if (c <= 0 || !IsValidRegex(h[(c + 1)..].Trim())) errors.Add($"{where}: header matcher must be 'Name: regex'.");
            }
            if (string.IsNullOrWhiteSpace(t.Name) || string.IsNullOrWhiteSpace(t.Description)) errors.Add($"{where}: name and description are required.");
        }
        return errors;
    }

    private static bool IsValidRegex(string pattern)
    {
        try { _ = new Regex(pattern, RegexOptions.None, TimeSpan.FromMilliseconds(100)); return true; }
        catch (ArgumentException) { return false; }
    }
}

public static class CheckPackLoader
{
    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>Loads the built-in pack plus any *.json packs in the folder that have a matching .sha256 file.</summary>
    public static IReadOnlyList<IVulnerabilityCheck> LoadAll(string? folder, Action<string>? warn)
    {
        var checks = new List<IVulnerabilityCheck>();
        using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("NetWarden.Checks.http-default.json"))
        {
            if (s != null)
            {
                var pack = JsonSerializer.Deserialize<CheckPack>(s, Json);
                if (pack != null) checks.AddRange(FromPack(pack, warn));
            }
        }
        if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) return checks;
        foreach (var file in Directory.EnumerateFiles(folder, "*.json"))
        {
            try
            {
                var bytes = File.ReadAllBytes(file);
                var hashFile = file + ".sha256";
                if (!File.Exists(hashFile))
                {
                    warn?.Invoke($"Check pack {Path.GetFileName(file)} skipped: no {Path.GetFileName(hashFile)} integrity file.");
                    continue;
                }
                var expected = File.ReadAllText(hashFile).Trim().Split(' ', '\t')[0];
                var actual = Convert.ToHexString(SHA256.HashData(bytes));
                if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
                {
                    warn?.Invoke($"Check pack {Path.GetFileName(file)} skipped: SHA-256 does not match.");
                    continue;
                }
                var pack = JsonSerializer.Deserialize<CheckPack>(bytes, Json);
                if (pack != null) checks.AddRange(FromPack(pack, warn));
            }
            catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
            {
                warn?.Invoke($"Check pack {Path.GetFileName(file)} could not be loaded: {ex.Message}");
            }
        }
        return checks;
    }

    public static IReadOnlyList<IVulnerabilityCheck> FromPack(CheckPack pack, Action<string>? warn)
    {
        var errors = CheckPackValidator.Validate(pack);
        if (errors.Count > 0)
        {
            foreach (var e in errors) warn?.Invoke($"Check pack '{pack.Name}': {e}");
            return Array.Empty<IVulnerabilityCheck>();
        }
        return pack.Templates.Select(t => (IVulnerabilityCheck)new HttpTemplateCheck(t, pack.Name)).ToList();
    }
}

/// <summary>Runs one validated HTTP template against an HTTP(S) service.</summary>
public sealed class HttpTemplateCheck : IVulnerabilityCheck
{
    private readonly HttpTemplate _t;
    private readonly Regex[] _body;
    private readonly Regex[] _bodyNot;
    private readonly (string Header, Regex Pattern)[] _headers;

    public HttpTemplateCheck(HttpTemplate template, string packName)
    {
        _t = template;
        Category = $"Web ({packName})";
        var opts = RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant;
        _body = template.BodyMatches.Select(r => new Regex(r, opts, TimeSpan.FromMilliseconds(250))).ToArray();
        _bodyNot = template.BodyNotMatches.Select(r => new Regex(r, opts, TimeSpan.FromMilliseconds(250))).ToArray();
        _headers = template.HeaderMatches.Select(h =>
        {
            var c = h.IndexOf(':');
            return (h[..c].Trim(), new Regex(h[(c + 1)..].Trim(), opts, TimeSpan.FromMilliseconds(250)));
        }).ToArray();
    }

    public string Id => "web." + _t.Id;
    public string Name => _t.Name;
    public string Category { get; }
    public CheckScope Scope => CheckScope.Port;
    public ProbeLevel Level => ProbeLevel.SafeProbe;
    public bool RequiresAnonymousLogin => false;
    public bool RequiresNetwork => true;

    public bool AppliesTo(CheckTarget target)
    {
        var s = target.Service;
        if (s == null || target.Port?.Protocol != TransportProtocol.Tcp) return false;
        if (_t.Ports.Count > 0 && !_t.Ports.Contains(target.Port.Port)) return false;
        return s.Fact("http.scheme") != null || s.Name is "http" or "https" or "elasticsearch" || (_t.Ports.Count > 0 && _t.Ports.Contains(target.Port.Port));
    }

    public async Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var s = ctx.Service!;
        var tls = s.Fact("http.scheme") == "https" || s.Tls;
        var resp = await ctx.Probe.HttpRequestAsync(ctx.Host.Address, ctx.Port!.Port, tls, _t.Method, _t.Path, ctx.Timeout + ctx.Timeout, ct).ConfigureAwait(false);
        if (resp == null || !Matches(resp)) return Array.Empty<Finding>();
        var f = ctx.NewFinding(this, _t.Name, _t.Severity, Confidence.Confirmed);
        f.Description = _t.Description;
        var url = $"{(tls ? "https" : "http")}://{ctx.Host.Address}:{ctx.Port.Port}{_t.Path}";
        f.Evidence = $"{_t.Method} {url} → HTTP {resp.StatusCode}" + (string.IsNullOrEmpty(_t.EvidenceNote) ? "" : $"\n{_t.EvidenceNote}") +
                     "\n(Response content is not stored.)";
        f.FixAction = string.IsNullOrEmpty(_t.FixAction) ? "Restrict access to " + _t.Path : _t.FixAction;
        f.Remediation.AddRange(_t.Remediation);
        f.References.AddRange(_t.References);
        f.Cves.AddRange(_t.Cves);
        f.Cvss = _t.Cvss;
        return new[] { f };
    }

    public bool Matches(HttpProbeResponse resp)
    {
        if (_t.Status.Count > 0 && !_t.Status.Contains(resp.StatusCode)) return false;
        try
        {
            if (_body.Any(r => !r.IsMatch(resp.Body))) return false;
            if (_bodyNot.Any(r => r.IsMatch(resp.Body))) return false;
            foreach (var (header, pattern) in _headers)
            {
                var v = resp.Header(header);
                if (v == null || !pattern.IsMatch(v)) return false;
            }
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
        return true;
    }
}
