using NetWarden.Checks;
using NetWarden.Core;
using NetWarden.Core.Checks;
using NetWarden.Core.Models;
using NetWarden.Core.Profiles;
using NetWarden.Data.Import;
using NetWarden.Reporting;

// Usage: SampleReport <nmap.xml> <output folder> [--pdf]
var input = args.Length > 0 ? args[0] : "../../tests/NetWarden.Tests/TestData/sample-nmap.xml";
var output = args.Length > 1 ? args[1] : "../../samples";
Directory.CreateDirectory(output);

ScanResult scan;
await using (var s = File.OpenRead(input)) scan = NmapXmlImporter.Import(s, "CORP\\it-admin", "Fictional lab network (sample data)");
scan.ScopeName = "Fictional lab network";

// A tiny CVE set with real NVD/KEV data for the products in the sample, so the demo needs no download.
var cves = new SampleCves()
    .Add("CVE-2023-48795", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", "The SSH transport protocol with certain OpenSSH extensions allows a man-in-the-middle to bypass integrity checks (Terrapin attack).", "openbsd", "openssh", null, "9.6")
    .Add("CVE-2023-38408", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution if an agent is forwarded to an attacker-controlled system.", "openbsd", "openssh", null, "9.3p2")
    .Add("CVE-2021-41617", 7.0, "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", "sshd in OpenSSH 6.2 through 8.x before 8.8, when certain non-default configurations are used, allows privilege escalation.", "openbsd", "openssh", "6.2", "8.8")
    .Add("CVE-2021-23017", 7.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:H", "A security issue in nginx resolver was identified, which might allow an attacker who is able to forge UDP packets from the DNS server to cause 1-byte memory overwrite.", "f5", "nginx", "0.6.18", "1.20.1");

var orchestrator = new ScanOrchestrator(CheckRegistry.CreateAll(), cves);
await orchestrator.AnalyzeOfflineAsync(scan, BuiltInProfiles.Get(BuiltInProfiles.Standard), CancellationToken.None);

// Demonstrate the status workflow: one finding accepted as a documented risk.
var cert = scan.AllFindings.FirstOrDefault(f => f.CheckId == "svc.ftp-cleartext") ?? scan.AllFindings.OrderBy(f => f.Severity).First();
cert.Status = FindingStatus.AcceptedRisk;
cert.StatusNote = "Sample: accepted until the device is replaced in Q1.";

var title = "Sample report – fictional lab network";
await ReportWriter.WriteAsync(scan, ReportFormat.Html, Path.Combine(output, "sample-report.html"), title);
await ReportWriter.WriteAsync(scan, ReportFormat.Json, Path.Combine(output, "sample-report.json"), title);
await ReportWriter.WriteAsync(scan, ReportFormat.Csv, Path.Combine(output, "sample-report.csv"), title);
#if !NW_OFFLINE
if (args.Contains("--pdf"))
{
    NetWarden.Reporting.Pdf.PdfReportWriter.Register();
    await ReportWriter.WriteAsync(scan, ReportFormat.Pdf, Path.Combine(output, "sample-report.pdf"), title);
}
#endif
Console.WriteLine($"{scan.AllFindings.Count()} findings written to {Path.GetFullPath(output)}");

sealed class SampleCves : ICveRepository
{
    private readonly List<CveMatchRule> _rules = new();
    private readonly Dictionary<string, CveRecord> _records = new();
    public bool IsAvailable => true;
    public IReadOnlyList<CveMatchRule> GetRules(string vendor, string product) => _rules.Where(r => r.Vendor == vendor && r.Product == product).ToList();
    public CveRecord? Get(string id) => _records.GetValueOrDefault(id);
    public SampleCves Add(string id, double cvss, string vector, string description, string vendor, string product, string? startIncl, string endExcl)
    {
        _records[id] = new CveRecord(id, description, cvss, vector, null, null, new[] { $"https://nvd.nist.gov/vuln/detail/{id}" }, false, null, null);
        _rules.Add(new CveMatchRule(id, vendor, product, $"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*", startIncl, null, null, endExcl));
        return this;
    }
}
