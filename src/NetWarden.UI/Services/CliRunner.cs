using NetWarden.Core;
using NetWarden.Core.Models;
using NetWarden.Core.Profiles;
using NetWarden.Core.Util;
using NetWarden.Data.Feeds;
using NetWarden.Data.Import;
using NetWarden.Reporting;

namespace NetWarden.UI.Services;

/// <summary>
/// Command-line mode of NetWarden.exe (used by scheduled tasks and scripts). Scopes must already exist and be
/// authorized in the GUI: the command line cannot create or authorize scopes.
/// </summary>
public sealed class CliRunner
{
    private readonly AppServices _s;
    private readonly TextWriter _out;

    public CliRunner(AppServices services, TextWriter output)
    {
        _s = services;
        _out = output;
    }

    public static readonly string[] Verbs = { "scan", "import-nmap", "update-cve", "list-scopes", "list-profiles", "report", "help", "--help", "-h", "/?" };

    public static bool IsCliInvocation(string[] args) => args.Length > 0 && Verbs.Contains(args[0], StringComparer.OrdinalIgnoreCase);

    public async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        if (args.Length == 0) { Help(); return 0; }
        var opts = ParseOptions(args.Skip(1).ToArray());
        try
        {
            switch (args[0].ToLowerInvariant())
            {
                case "scan": return await ScanAsync(opts, ct);
                case "import-nmap": return await ImportAsync(opts, ct);
                case "update-cve": return await UpdateCveAsync(opts, ct);
                case "list-scopes":
                    foreach (var s in _s.History.ListScopes())
                        _out.WriteLine($"{s.Name}\t{(s.Authorized ? "authorized" : "NOT authorized")}\t{s.Targets.Replace("\r", "").Replace('\n', ' ')}");
                    return 0;
                case "list-profiles":
                    foreach (var p in _s.Profiles.All()) _out.WriteLine($"{p.Name}\t{(p.BuiltIn ? "built-in" : "custom")}\t{p.TcpPorts}");
                    return 0;
                case "report": return await ReportAsync(opts);
                default: Help(); return 0;
            }
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException or FeedException or InvalidDataException or Core.Targeting.ScopeException)
        {
            _out.WriteLine("Error: " + ex.Message);
            _s.Log.Error("CLI error", ex);
            return 2;
        }
    }

    public static Dictionary<string, string> ParseOptions(string[] args)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal)) continue;
            var key = args[i][2..];
            var value = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal) ? args[++i] : "true";
            d[key] = value;
        }
        return d;
    }

    private async Task<int> ScanAsync(Dictionary<string, string> o, CancellationToken ct)
    {
        if (!o.TryGetValue("scope", out var scopeName)) throw new ArgumentException("--scope is required (see list-scopes).");
        var scope = _s.History.FindScope(scopeName) ?? throw new ArgumentException($"No scope named '{scopeName}'. Create and authorize it in the NetWarden window first.");
        if (!scope.Authorized) throw new InvalidOperationException($"Scope '{scope.Name}' has not been authorized. Open NetWarden and confirm authorization first.");
        var profile = o.TryGetValue("profile", out var pn) ? _s.Profiles.Find(pn) ?? throw new ArgumentException($"No profile named '{pn}'.") : BuiltInProfiles.Get(BuiltInProfiles.Standard);

        _out.WriteLine($"NetWarden scan: {profile.Name} on {scope.Name} ({scope.Targets.Replace("\r", "").Replace('\n', ' ')})");
        var observer = new ConsoleObserver(_out);
        var result = await _s.RunScanAsync(scope, profile, observer, default, ct, sendNotifications: o.ContainsKey("notify") || _s.Settings.Notifications.Enabled);
        _out.WriteLine();
        _out.WriteLine($"Result: {result.State}. {result.LiveHosts.Count()} host(s), {result.OpenPortCount} open port(s), {result.AllFindings.Count(f => f.Status == FindingStatus.Open)} open finding(s).");
        foreach (var sev in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low })
            _out.WriteLine($"  {sev,-8} {result.CountBySeverity(sev)}");
        if (o.TryGetValue("report", out var reportPath))
        {
            await ReportWriter.WriteAsync(result, ReportWriter.FormatFromExtension(reportPath), Path.GetFullPath(reportPath));
            _out.WriteLine($"Report written to {Path.GetFullPath(reportPath)}");
        }
        if (result.State == ScanState.Failed) return 3;
        // Exit code 1 lets scripts react to critical/KEV findings.
        return result.AllFindings.Any(f => f.Status == FindingStatus.Open && (f.Severity == Severity.Critical || f.Kev)) ? 1 : 0;
    }

    private async Task<int> ImportAsync(Dictionary<string, string> o, CancellationToken ct)
    {
        if (!o.TryGetValue("file", out var file)) throw new ArgumentException("--file <nmap.xml> is required.");
        ScanResult result;
        await using (var stream = File.OpenRead(file)) result = NmapXmlImporter.Import(stream, _s.CurrentUser, Path.GetFileName(file));
        await _s.Orchestrator.AnalyzeOfflineAsync(result, BuiltInProfiles.Get(BuiltInProfiles.Standard), ct);
        _s.History.ApplyStatuses(result);
        _s.History.SaveScan(result);
        _s.History.Audit("import-nmap", _s.CurrentUser, result.ScopeName, null, null, file);
        _out.WriteLine($"Imported {result.LiveHosts.Count()} host(s); {result.AllFindings.Count()} finding(s).");
        if (o.TryGetValue("report", out var reportPath))
            await ReportWriter.WriteAsync(result, ReportWriter.FormatFromExtension(reportPath), Path.GetFullPath(reportPath));
        return 0;
    }

    private async Task<int> UpdateCveAsync(Dictionary<string, string> o, CancellationToken ct)
    {
        var progress = new Progress<FeedProgress>(p => _out.WriteLine(p.Message));
        var key = o.TryGetValue("api-key", out var k) ? k : _s.Settings.NvdApiKey;
        await new NvdClient(key).SyncAsync(_s.Cves, progress, ct);
        await new KevClient().SyncAsync(_s.Cves, progress, ct);
        var st = _s.Cves.Stats();
        _out.WriteLine($"CVE database: {st.CveCount:N0} CVEs, {st.KevCount:N0} KEV.");
        _s.History.Audit("cve-update-end", _s.CurrentUser);
        return 0;
    }

    private async Task<int> ReportAsync(Dictionary<string, string> o)
    {
        if (!o.TryGetValue("out", out var path)) throw new ArgumentException("--out <file.pdf|html|csv|json> is required.");
        var summary = o.TryGetValue("scan", out var id) && Guid.TryParse(id, out var g)
            ? _s.History.ListScans().FirstOrDefault(s => s.Id == g)
            : _s.History.ListScans().FirstOrDefault();
        if (summary == null) throw new InvalidOperationException("No scans found.");
        var scan = _s.History.LoadScan(summary.Id)!;
        await ReportWriter.WriteAsync(scan, ReportWriter.FormatFromExtension(path), Path.GetFullPath(path));
        _out.WriteLine($"Report for {summary.Label} written to {Path.GetFullPath(path)}");
        return 0;
    }

    private void Help()
    {
        _out.WriteLine("""
NetWarden – defensive network scanner and vulnerability assessment.
Only scan networks you own or are authorized to assess.

Usage:
  NetWarden.exe                                   Open the GUI
  NetWarden.exe scan --scope <name> [--profile <name>] [--report <file>] [--notify]
  NetWarden.exe import-nmap --file <nmap.xml> [--report <file>]
  NetWarden.exe update-cve [--api-key <NVD key>]
  NetWarden.exe report --out <file.pdf|.html|.csv|.json> [--scan <id>]
  NetWarden.exe list-scopes | list-profiles

Exit codes: 0 ok, 1 critical or actively exploited findings, 2 usage error, 3 scan failed.
Scopes are created and authorized in the GUI.
""");
    }

    private sealed class ConsoleObserver : IScanObserver
    {
        private readonly TextWriter _w;
        private int _lastPercent = -1;
        public ConsoleObserver(TextWriter w) => _w = w;
        public void OnProgress(ScanProgress p)
        {
            var pct = (int)(p.Fraction * 100);
            if (pct / 10 == _lastPercent / 10 && p.Phase != ScanPhase.Finished) return;
            _lastPercent = pct;
            lock (_w) _w.WriteLine($"[{pct,3}%] {p.Phase}: {p.Message}");
        }
        public void OnHostUpdated(HostResult host) { }
        public void OnFinding(Finding f) { lock (_w) _w.WriteLine($"  [{f.Severity}] {f.Title} – {f.Location}"); }
        public void OnMessage(string message) { lock (_w) _w.WriteLine(message); }
    }
}
