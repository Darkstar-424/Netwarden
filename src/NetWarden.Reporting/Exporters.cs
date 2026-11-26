using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetWarden.Core.Models;

namespace NetWarden.Reporting;

public enum ReportFormat { Pdf, Html, Csv, Json }

public static class ReportText
{
    public static string SeverityIcon(Severity s) => s switch
    {
        Severity.Critical => "●",
        Severity.High => "▲",
        Severity.Medium => "■",
        Severity.Low => "◆",
        _ => "○"
    };

    public static string ConfidenceLabel(Confidence c) => c switch
    {
        Confidence.Confirmed => "Confirmed",
        Confidence.Configuration => "Configuration",
        _ => "Potential (version-based)"
    };

    public const string ResponsibleUse =
        "This report was produced by NetWarden, a defensive assessment tool, for assets the operator confirmed they are authorized to assess. " +
        "Checks are non-intrusive: no exploitation, password guessing or payload delivery was performed. Version-based (\"Potential\") findings should be confirmed against vendor advisories.";
}

public static class HtmlReportWriter
{
    public static string Render(ReportModel m)
    {
        var s = m.Scan;
        var sb = new StringBuilder();
        string E(string? v) => WebUtility.HtmlEncode(v ?? "");
        sb.Append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        sb.Append("<title>").Append(E(m.Title)).Append("</title><style>").Append(Css).Append("</style></head><body><main>");
        sb.Append("<header><div class=\"brand\">NetWarden</div><h1>").Append(E(m.Title)).Append("</h1>");
        sb.Append("<p class=\"meta\">Scan started ").Append(E(s.Started.ToLocalTime().ToString("f", CultureInfo.CurrentCulture)))
          .Append(" · profile ").Append(E(s.ProfileName)).Append(" · run by ").Append(E(s.StartedBy))
          .Append(" · report generated ").Append(E(m.Generated.ToLocalTime().ToString("g", CultureInfo.CurrentCulture))).Append("</p></header>");

        // Executive summary
        sb.Append("<section><h2>Executive summary</h2><div class=\"risk risk-").Append(m.RiskRating.ToLowerInvariant()).Append("\"><div class=\"risk-label\">Overall risk</div><div class=\"risk-value\">")
          .Append(E(m.RiskRating)).Append("</div><p>").Append(E(m.RiskExplanation)).Append("</p></div>");
        sb.Append("<div class=\"cards\">");
        Card(sb, "Devices found", s.LiveHosts.Count().ToString(CultureInfo.InvariantCulture));
        Card(sb, "Open services", s.OpenPortCount.ToString(CultureInfo.InvariantCulture));
        Card(sb, "Open findings", m.Findings.Count.ToString(CultureInfo.InvariantCulture));
        Card(sb, "Actively exploited", m.KevCount.ToString(CultureInfo.InvariantCulture));
        sb.Append("</div><table class=\"sev\"><tr>");
        foreach (var sev in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low, Severity.Info })
            sb.Append("<td class=\"s-").Append(sev.ToString().ToLowerInvariant()).Append("\"><b>").Append(m.Count(sev)).Append("</b><br>").Append(ReportText.SeverityIcon(sev)).Append(' ').Append(sev).Append("</td>");
        sb.Append("</tr></table>");

        if (m.FixFirst.Count > 0)
        {
            sb.Append("<h3>Fix these first</h3><ol class=\"fixes\">");
            foreach (var fix in m.FixFirst.Take(10))
            {
                sb.Append("<li><span class=\"badge s-").Append(fix.Severity.ToString().ToLowerInvariant()).Append("\">").Append(ReportText.SeverityIcon(fix.Severity)).Append(' ').Append(fix.Severity).Append("</span>");
                if (fix.Kev) sb.Append(" <span class=\"badge kev\">Actively exploited</span>");
                sb.Append(" <b>").Append(E(fix.Action)).Append("</b><br><span class=\"muted\">").Append(E(fix.WhyItMatters)).Append(" Affects: ")
                  .Append(E(string.Join(", ", fix.Hosts.Take(6)))).Append(fix.Hosts.Count > 6 ? $" and {fix.Hosts.Count - 6} more" : "").Append("</span></li>");
            }
            sb.Append("</ol>");
        }
        sb.Append("</section>");

        // Findings
        sb.Append("<section><h2>Findings</h2>");
        if (m.Findings.Count == 0) sb.Append("<p>No open findings.</p>");
        foreach (var f in m.Findings)
        {
            sb.Append("<article class=\"finding\"><div class=\"fhead\"><span class=\"badge s-").Append(f.Severity.ToString().ToLowerInvariant()).Append("\">")
              .Append(ReportText.SeverityIcon(f.Severity)).Append(' ').Append(f.Severity).Append("</span>");
            if (f.Kev) sb.Append("<span class=\"badge kev\">Actively exploited (KEV)</span>");
            sb.Append("<span class=\"badge conf\">").Append(ReportText.ConfidenceLabel(f.Confidence)).Append("</span>");
            if (f.Cvss is double cv) sb.Append("<span class=\"badge conf\">CVSS ").Append(cv.ToString("0.0", CultureInfo.InvariantCulture)).Append("</span>");
            sb.Append("</div><h3>").Append(E(f.Title)).Append("</h3><p class=\"muted\">").Append(E(f.HostName != null ? $"{f.HostName} · " : "")).Append(E(f.Location)).Append("</p>");
            sb.Append("<p>").Append(E(f.Description)).Append("</p>");
            if (!string.IsNullOrEmpty(f.Evidence)) sb.Append("<h4>Evidence</h4><pre>").Append(E(f.Evidence)).Append("</pre>");
            if (f.Cves.Count > 0 || f.CvssVector != null)
                sb.Append("<p class=\"muted mono\">").Append(E(string.Join(", ", f.Cves))).Append(f.CvssVector != null ? " · " + E(f.CvssVector) : "").Append("</p>");
            if (f.Remediation.Count > 0)
            {
                sb.Append("<h4>How to fix</h4><ol>");
                foreach (var r in f.Remediation) sb.Append("<li>").Append(E(r)).Append("</li>");
                sb.Append("</ol>");
            }
            if (f.References.Count > 0)
            {
                sb.Append("<h4>References</h4><ul class=\"refs\">");
                foreach (var r in f.References.Take(8))
                {
                    var safe = r.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || r.StartsWith("http://", StringComparison.OrdinalIgnoreCase);
                    sb.Append("<li>").Append(safe ? $"<a href=\"{E(r)}\" rel=\"noopener noreferrer\">{E(r)}</a>" : E(r)).Append("</li>");
                }
                sb.Append("</ul>");
            }
            sb.Append("</article>");
        }
        sb.Append("</section>");

        // Hosts
        sb.Append("<section><h2>Devices and services</h2><table class=\"grid\"><thead><tr><th>Address</th><th>Name</th><th>OS guess</th><th>MAC / vendor</th><th>Open services</th><th>Findings</th></tr></thead><tbody>");
        foreach (var h in s.LiveHosts)
        {
            sb.Append("<tr><td class=\"mono\">").Append(E(h.Address)).Append("</td><td>").Append(E(h.NetBiosName ?? h.HostName ?? "")).Append("</td><td>")
              .Append(E(h.Os?.Display ?? "")).Append(h.DeviceType != null || h.DeviceModel != null ? "<br><span class=\"muted\">" + E(string.Join(" · ", new[] { h.DeviceType, h.DeviceModel }.Where(x => x != null))) + "</span>" : "")
              .Append("</td><td class=\"mono\">").Append(E(h.MacAddress ?? "")).Append(h.Vendor != null ? "<br>" + E(h.Vendor) : "").Append("</td><td>");
            var named = h.Apps.Where(a => a.Category is not ("Network service" or "Web server" or "Windows services" or "Device info")).Select(a => a.Display).ToList();
            if (named.Count > 0) sb.Append("<div><b>Apps:</b> ").Append(E(string.Join(", ", named))).Append("</div>");
            foreach (var p in h.OpenPorts) sb.Append("<div><span class=\"mono\">").Append(E(p.Label)).Append("</span> ").Append(E(p.Service?.Display ?? "")).Append("</div>");
            sb.Append("</td><td>").Append(h.Findings.Count(f => f.Status == FindingStatus.Open)).Append("</td></tr>");
        }
        sb.Append("</tbody></table></section>");

        var closed = s.AllFindings.Where(f => f.Status != FindingStatus.Open).ToList();
        if (closed.Count > 0)
        {
            sb.Append("<section><h2>Accepted risks, false positives and fixed items</h2><table class=\"grid\"><thead><tr><th>Status</th><th>Finding</th><th>Location</th><th>Note</th></tr></thead><tbody>");
            foreach (var f in closed)
                sb.Append("<tr><td>").Append(E(f.Status.ToString())).Append("</td><td>").Append(E(f.Title)).Append("</td><td class=\"mono\">").Append(E(f.Location)).Append("</td><td>").Append(E(f.StatusNote)).Append("</td></tr>");
            sb.Append("</tbody></table></section>");
        }

        if (s.Warnings.Count > 0 || s.Errors.Count > 0)
        {
            sb.Append("<section><h2>Scan notes</h2><ul>");
            foreach (var w in s.Warnings.Concat(s.Errors)) sb.Append("<li>").Append(E(w)).Append("</li>");
            sb.Append("</ul></section>");
        }
        sb.Append("<footer><p>").Append(E(ReportText.ResponsibleUse)).Append("</p><p>Targets: <span class=\"mono\">").Append(E(string.Join(", ", s.Targets))).Append("</span></p></footer>");
        sb.Append("</main></body></html>");
        return sb.ToString();
    }

    private static void Card(StringBuilder sb, string label, string value)
        => sb.Append("<div class=\"card\"><div class=\"muted\">").Append(WebUtility.HtmlEncode(label)).Append("</div><div class=\"big\">").Append(WebUtility.HtmlEncode(value)).Append("</div></div>");

    private const string Css = @"
body{margin:0;background:#f3f3f3;color:#1b1b1b;font:15px/1.5 'Segoe UI',system-ui,sans-serif}
main{max-width:1040px;margin:0 auto;padding:32px 24px}
header{border-bottom:3px solid #005fb8;margin-bottom:24px}.brand{color:#005fb8;font-weight:700;letter-spacing:.04em}
h1{margin:4px 0;font-size:28px}h2{font-size:21px;margin:32px 0 12px}h3{font-size:16px;margin:8px 0 4px}h4{font-size:13px;margin:12px 0 4px;color:#5c5c5c;text-transform:uppercase;letter-spacing:.04em}
.meta,.muted{color:#5c5c5c}.mono{font-family:Consolas,'Cascadia Mono',monospace;font-size:13px}
section{background:#fff;border:1px solid #e0e0e0;border-radius:10px;padding:20px 24px;margin-bottom:20px}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:16px 0}.card{border:1px solid #e0e0e0;border-radius:8px;padding:12px 16px}.big{font-size:28px;font-weight:600}
.risk{border-radius:8px;padding:14px 18px;border:1px solid #e0e0e0}.risk-label{font-size:12px;text-transform:uppercase;color:#5c5c5c}.risk-value{font-size:26px;font-weight:700}
.risk-critical{background:#fde7e9}.risk-high{background:#fff1e5}.risk-medium{background:#fff4ce}.risk-low,.risk-minimal{background:#e8f1fb}
table.sev{width:100%;border-collapse:separate;border-spacing:8px 0;text-align:center}table.sev td{border-radius:8px;padding:8px}
.s-critical{background:#fde7e9;color:#a4262c}.s-high{background:#fff1e5;color:#b3420b}.s-medium{background:#fff4ce;color:#7a4f00}.s-low{background:#e8f1fb;color:#0f5ba7}.s-info{background:#f0f0f0;color:#505050}
.badge{display:inline-block;padding:1px 9px;border-radius:10px;font-size:12px;font-weight:600;margin-right:6px}.kev{background:#1b1b1b;color:#fff}.conf{border:1px solid #c8ccd2;font-weight:400}
.fixes li{margin-bottom:10px}.finding{border-top:1px solid #ededed;padding:16px 0}.finding:first-of-type{border-top:0}
pre{background:#f4f5f7;border-radius:6px;padding:10px 12px;white-space:pre-wrap;font-size:12.5px}
table.grid{width:100%;border-collapse:collapse;font-size:13.5px}table.grid th{text-align:left;background:#f7f8fa;color:#5c5c5c;padding:8px}table.grid td{border-top:1px solid #ededed;padding:8px;vertical-align:top}
.refs{font-size:13px;word-break:break-all}footer{color:#5c5c5c;font-size:12.5px;margin-top:24px}
@media print{body{background:#fff}section{border:0;padding:0}}";
}

public static class CsvExporter
{
    public static string Findings(IEnumerable<Finding> findings)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Severity,Title,Host,HostName,Port,Protocol,Confidence,CVSS,CVSSVector,CVEs,KEV,Status,StatusNote,FixAction,Description,Evidence,Remediation,References");
        foreach (var f in findings)
        {
            sb.AppendJoin(',', new[]
            {
                f.Severity.ToString(), f.Title, f.Host, f.HostName ?? "", f.Port?.ToString(CultureInfo.InvariantCulture) ?? "",
                f.Protocol?.ToString().ToLowerInvariant() ?? "", f.Confidence.ToString(), f.Cvss?.ToString("0.0", CultureInfo.InvariantCulture) ?? "",
                f.CvssVector ?? "", string.Join(' ', f.Cves), f.Kev ? "yes" : "no", f.Status.ToString(), f.StatusNote ?? "", f.FixAction,
                f.Description, f.Evidence, string.Join(" | ", f.Remediation), string.Join(' ', f.References)
            }.Select(Escape));
            sb.AppendLine();
        }
        return sb.ToString();
    }

    public static string Hosts(ScanResult scan)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Address,HostName,NetBIOS,MAC,Vendor,OS,OSConfidence,Port,Protocol,Service,Product,Version,TLS,OpenFindings,DeviceType,DeviceModel,Apps");
        foreach (var h in scan.LiveHosts)
        {
            var ports = h.OpenPorts.ToList();
            if (ports.Count == 0) ports.Add(null!);
            foreach (var p in ports)
            {
                sb.AppendJoin(',', new[]
                {
                    h.Address, h.HostName ?? "", h.NetBiosName ?? "", h.MacAddress ?? "", h.Vendor ?? "", h.Os?.Display ?? "", h.Os?.Confidence.ToString(CultureInfo.InvariantCulture) ?? "",
                    p?.Port.ToString(CultureInfo.InvariantCulture) ?? "", p == null ? "" : p.Protocol.ToString().ToLowerInvariant(), p?.Service?.Name ?? "",
                    p?.Service?.Product ?? "", p?.Service?.Version ?? "", p?.Tls != null ? string.Join(' ', p.Tls.Protocols) : "",
                    h.Findings.Count(f => f.Status == FindingStatus.Open).ToString(CultureInfo.InvariantCulture),
                    h.DeviceType ?? "", h.DeviceModel ?? "", string.Join("; ", h.Apps.Select(a => a.Display))
                }.Select(Escape));
                sb.AppendLine();
            }
        }
        return sb.ToString();
    }

    /// <summary>RFC 4180 quoting, plus a leading apostrophe for cells that spreadsheet apps would treat as formulas.</summary>
    public static string Escape(string v)
    {
        if (v.Length > 0 && "=+-@\t\r".Contains(v[0])) v = "'" + v;
        return v.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0 ? "\"" + v.Replace("\"", "\"\"") + "\"" : v;
    }
}

public static class JsonExporter
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static string Export(ScanResult scan) => JsonSerializer.Serialize(scan, Options);
}

/// <summary>Writes any report format to disk. PDF is handled by the PDF writer (QuestPDF).</summary>
public static class ReportWriter
{
    public static Func<ReportModel, string, Task>? PdfWriter { get; set; }

    public static async Task WriteAsync(ScanResult scan, ReportFormat format, string path, string? title = null)
    {
        var model = ReportBuilder.Build(scan, title);
        switch (format)
        {
            case ReportFormat.Html:
                await File.WriteAllTextAsync(path, HtmlReportWriter.Render(model), new UTF8Encoding(false)).ConfigureAwait(false);
                break;
            case ReportFormat.Csv:
                await File.WriteAllTextAsync(path, CsvExporter.Findings(scan.AllFindings), new UTF8Encoding(true)).ConfigureAwait(false);
                var hostsPath = Path.Combine(Path.GetDirectoryName(path) ?? ".", Path.GetFileNameWithoutExtension(path) + "-hosts.csv");
                await File.WriteAllTextAsync(hostsPath, CsvExporter.Hosts(scan), new UTF8Encoding(true)).ConfigureAwait(false);
                break;
            case ReportFormat.Json:
                await File.WriteAllTextAsync(path, JsonExporter.Export(scan), new UTF8Encoding(false)).ConfigureAwait(false);
                break;
            case ReportFormat.Pdf:
                if (PdfWriter == null) throw new InvalidOperationException("PDF output is not available in this build.");
                await PdfWriter(model, path).ConfigureAwait(false);
                break;
        }
    }

    public static ReportFormat FormatFromExtension(string path) => Path.GetExtension(path).ToLowerInvariant() switch
    {
        ".pdf" => ReportFormat.Pdf,
        ".csv" => ReportFormat.Csv,
        ".json" => ReportFormat.Json,
        _ => ReportFormat.Html
    };
}
