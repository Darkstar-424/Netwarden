using System.IO.Compression;
using System.Text;
using System.Text.Json;
using NetWarden.Core.Models;
using NetWarden.Data.Feeds;
using NetWarden.Data.Import;
using NetWarden.Reporting;
using NetWarden.UI.Services;
using NetWarden.UI.ViewModels;
using Xunit;

namespace NetWarden.Tests;

public class DataAndReportTests
{
    [Fact]
    public void Nmap_xml_import_maps_hosts_ports_and_scripts()
    {
        var scan = NmapXmlImporter.Import(TestData.Resource("sample-nmap.xml"), "tester", "sample-nmap.xml");
        Assert.Equal(ScanState.Imported, scan.State);
        Assert.Equal(2, scan.LiveHosts.Count());
        var win = scan.Hosts.Single(h => h.Address == "192.168.1.10");
        Assert.Equal("filesrv01.corp.example", win.HostName);
        Assert.Equal("Windows", win.Os!.Family);
        Assert.Equal(2, win.Ports.Count); // closed 3389 skipped
        var smb = win.Ports.Single(p => p.Port == 445).Service!;
        Assert.Equal("enabled", smb.Fact("smb1"));
        Assert.Equal("enabled", smb.Fact("smb.signing"));
        var linux = scan.Hosts.Single(h => h.Address == "192.168.1.20");
        var ssh = linux.Ports.Single(p => p.Port == 22).Service!;
        Assert.Equal("8.2p1", ssh.Version);
        Assert.Contains("cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*", ssh.Cpes);
        var tls = linux.Ports.Single(p => p.Port == 443).Tls!;
        Assert.Contains("TLS 1.0", tls.Protocols);
        Assert.Contains(tls.Ciphers, c => c.Weak && c.Name.Contains("3DES"));
    }

    [Fact]
    public void Nmap_import_rejects_other_xml()
        => Assert.Throws<InvalidDataException>(() => NmapXmlImporter.Import(new MemoryStream(Encoding.UTF8.GetBytes("<root/>")), "t", "x.xml"));

    [Fact]
    public async Task Nvd_page_parsing_and_validation()
    {
        var page = await NvdClient.ParsePageAsync(TestData.Resource("nvd-page.json"), CancellationToken.None);
        Assert.Equal(2L, page.TotalResults);
        var cve = Assert.Single(page.Items);                 // rejected CVE skipped
        Assert.Equal("CVE-2023-48795", cve.Id);
        Assert.StartsWith("The SSH transport protocol", cve.Description);
        Assert.Equal(5.9, cve.Cvss!.Value, 1);
        var rule = Assert.Single(cve.Rules);                 // non-vulnerable platform entry skipped
        Assert.Equal("openssh", rule.Product);
        Assert.Equal("9.6", rule.VersionEndExcluding);

        await Assert.ThrowsAsync<FeedException>(() => NvdClient.ParsePageAsync(new MemoryStream(Encoding.UTF8.GetBytes("{\"format\":\"OTHER\"}")), CancellationToken.None));
    }

    [Fact]
    public async Task Kev_parsing_requires_plausible_catalog()
    {
        static string Catalog(int n) => JsonSerializer.Serialize(new
        {
            catalogVersion = "2026.11.25",
            vulnerabilities = Enumerable.Range(1, n).Select(i => new { cveID = $"CVE-2020-{i:D5}", vulnerabilityName = "x", dateAdded = "2026-01-01", dueDate = "2026-02-01", requiredAction = "Patch", knownRansomwareCampaignUse = "Unknown" })
        });
        var ok = await KevClient.ParseAsync(new MemoryStream(Encoding.UTF8.GetBytes(Catalog(150))), CancellationToken.None);
        Assert.Equal(150, ok.Count);
        await Assert.ThrowsAsync<FeedException>(() => KevClient.ParseAsync(new MemoryStream(Encoding.UTF8.GetBytes(Catalog(5))), CancellationToken.None));
    }

    [Fact]
    public void Offline_bundle_detects_tampering()
    {
        var dir = Path.Combine(Path.GetTempPath(), "nw-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var db = Path.Combine(dir, "cve.db");
            File.WriteAllBytes(db, Encoding.ASCII.GetBytes("pretend database contents"));
            var zip = Path.Combine(dir, "bundle.zip");
            OfflineBundle.Export(db, zip, 1);
            var extracted = OfflineBundle.VerifyAndExtract(zip);
            Assert.Equal("pretend database contents", File.ReadAllText(extracted));
            File.Delete(extracted);

            using (var archive = ZipFile.Open(zip, ZipArchiveMode.Update))
            {
                archive.GetEntry("cve.db")!.Delete();
                using var w = new StreamWriter(archive.CreateEntry("cve.db").Open());
                w.Write("tampered");
            }
            Assert.Throws<FeedException>(() => OfflineBundle.VerifyAndExtract(zip));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    private static ScanResult SampleScan(params (string Host, int Port, string Check, Severity Sev, bool Kev)[] findings)
    {
        var scan = new ScanResult { ScopeName = "Office", ProfileName = "Standard", StartedBy = "tester", State = ScanState.Completed, Started = DateTimeOffset.Now.AddMinutes(-5), Finished = DateTimeOffset.Now, Targets = { "192.168.1.0/24" } };
        foreach (var g in findings.GroupBy(f => f.Host))
        {
            var host = new HostResult { Address = g.Key, IsUp = true };
            foreach (var f in g)
            {
                if (host.Ports.All(p => p.Port != f.Port)) host.Ports.Add(new PortResult { Port = f.Port, State = PortState.Open, Service = new ServiceInfo { Name = "svc" } });
                host.Findings.Add(new Finding
                {
                    Key = Finding.MakeKey(f.Check, g.Key, f.Port), CheckId = f.Check, Title = f.Check + " title", Severity = f.Sev, Kev = f.Kev,
                    Host = g.Key, Port = f.Port, FixAction = "Fix " + f.Check, Description = "Why it matters. More detail.", Remediation = { "Step one", "Step two" }
                });
            }
            scan.Hosts.Add(host);
        }
        return scan;
    }

    [Fact]
    public void Report_groups_fixes_and_rates_risk()
    {
        var scan = SampleScan(("10.0.0.1", 445, "smb.smbv1", Severity.High, false), ("10.0.0.2", 445, "smb.smbv1", Severity.High, false),
                              ("10.0.0.3", 22, "cve.version-match", Severity.Medium, true), ("10.0.0.3", 443, "tls.cert-untrusted", Severity.Low, false));
        var report = ReportBuilder.Build(scan);
        Assert.Equal("Critical", report.RiskRating); // KEV present
        Assert.Equal(3, report.FixFirst.Count);
        Assert.True(report.FixFirst[0].Kev);
        Assert.Equal("Fix smb.smbv1 on 2 devices", report.FixFirst[1].Action);
        Assert.Equal("Why it matters.", report.FixFirst[1].WhyItMatters);
    }

    [Fact]
    public void Accepted_and_false_positive_findings_leave_the_counts()
    {
        var scan = SampleScan(("10.0.0.1", 445, "a", Severity.High, false), ("10.0.0.1", 80, "b", Severity.Low, false));
        scan.AllFindings.First().Status = FindingStatus.AcceptedRisk;
        var report = ReportBuilder.Build(scan);
        Assert.Single(report.Findings);
        Assert.Equal("Low", report.RiskRating);
    }

    [Fact]
    public void Scan_diff_finds_changes()
    {
        var before = SampleScan(("10.0.0.1", 445, "a", Severity.High, false), ("10.0.0.2", 22, "b", Severity.Low, false));
        var after = SampleScan(("10.0.0.1", 3389, "c", Severity.Medium, false), ("10.0.0.3", 80, "d", Severity.Low, false));
        var diff = ScanDiff.Compare(before, after);
        Assert.Equal("10.0.0.3", Assert.Single(diff.NewHosts).Address);
        Assert.Equal("10.0.0.2", Assert.Single(diff.GoneHosts).Address);
        Assert.Equal(3389, Assert.Single(diff.NewPorts).Port.Port);
        Assert.Equal(445, Assert.Single(diff.ClosedPorts).Port.Port);
        Assert.Equal(2, diff.NewFindings.Count);
        Assert.Equal("a", Assert.Single(diff.ResolvedFindings).CheckId); // b's host was not rescanned, so not "resolved"
    }

    [Fact]
    public void Csv_escaping_blocks_formula_injection()
    {
        Assert.Equal("'=cmd|' /C calc'!A0", CsvExporter.Escape("=cmd|' /C calc'!A0"));
        Assert.Equal("\"a,b\"", CsvExporter.Escape("a,b"));
        Assert.Equal("\"say \"\"hi\"\"\"", CsvExporter.Escape("say \"hi\""));
        var csv = CsvExporter.Findings(SampleScan(("10.0.0.1", 445, "a", Severity.High, false)).AllFindings);
        Assert.Equal(2, csv.Trim().Split('\n').Length);
    }

    [Fact]
    public void Html_report_is_encoded_and_complete()
    {
        var scan = SampleScan(("10.0.0.1", 445, "a", Severity.High, false));
        scan.AllFindings.First().Title = "<script>alert(1)</script>";
        scan.AllFindings.First().References.Add("javascript:alert(1)");
        var html = HtmlReportWriter.Render(ReportBuilder.Build(scan));
        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;", html);
        Assert.DoesNotContain("href=\"javascript:", html);
        Assert.Contains("Executive summary", html);
        Assert.Contains("Fix these first", html);
    }

    [Fact]
    public void Json_export_roundtrips()
    {
        var scan = SampleScan(("10.0.0.1", 445, "a", Severity.High, true));
        var json = JsonExporter.Export(scan);
        Assert.Contains("\"severity\": \"High\"", json);
        var back = JsonSerializer.Deserialize<ScanResult>(json, JsonExporter.Options)!;
        Assert.True(back.AllFindings.Single().Kev);
    }

    [Theory]
    [InlineData("severity>=high", 2)]
    [InlineData("kev:true", 1)]
    [InlineData("host:10.0.0.2", 2)]
    [InlineData("port:445", 2)]
    [InlineData("severity:low", 1)]
    [InlineData("title smb", 1)]
    [InlineData("", 3)]
    public void Finding_query_language(string query, int expected)
    {
        var scan = SampleScan(("10.0.0.1", 445, "smb", Severity.Critical, true), ("10.0.0.2", 445, "x", Severity.High, false), ("10.0.0.2", 80, "y", Severity.Low, false));
        var q = FindingQuery.Parse(query);
        Assert.Empty(q.Errors);
        Assert.Equal(expected, scan.AllFindings.Count(q.Matches));
    }

    [Fact]
    public void Finding_query_reports_errors()
        => Assert.NotEmpty(FindingQuery.Parse("severity>=urgent port:abc").Errors);

    [Fact]
    public void Map_layout_places_every_host()
    {
        var hosts = Enumerable.Range(1, 30).Select(i => new HostRow(new HostResult { Address = $"10.0.0.{i}", IsUp = true })).ToList();
        var subnet = NetworkMapViewModel.Layout("10.0.0.0/24", hosts);
        Assert.Equal(30, subnet.Nodes.Count);
        Assert.Equal(30, subnet.Edges.Count);
        Assert.All(subnet.Nodes, n => Assert.InRange(n.X, 0.0, subnet.Width));
        Assert.Equal(30, subnet.Nodes.Select(n => (Math.Round(n.X), Math.Round(n.Y))).Distinct().Count());
    }

    [Fact]
    public void Cli_argument_parsing()
    {
        Assert.True(CliRunner.IsCliInvocation(new[] { "scan", "--scope", "x" }));
        Assert.False(CliRunner.IsCliInvocation(Array.Empty<string>()));
        Assert.False(CliRunner.IsCliInvocation(new[] { "C:\\some\\file.txt" }));
        var o = CliRunner.ParseOptions(new[] { "--scope", "Head office", "--notify", "--profile", "Standard" });
        Assert.Equal("Head office", o["scope"]);
        Assert.Equal("true", o["notify"]);
        Assert.Equal("Standard", o["profile"]);
    }

    [Fact]
    public void Glossary_explains_key_terms()
    {
        foreach (var term in new[] { "cve", "cvss", "kev", "nla", "smb", "tls", "port", "confidence" })
            Assert.NotEqual(term, Glossary.Instance[term]);
    }

    [Fact]
    public void Profiles_roundtrip_as_json()
    {
        var p = NetWarden.Core.Profiles.BuiltInProfiles.Get("Web Services").Clone("Mine");
        p.Timing = TimingTemplate.Gentle;
        var back = NetWarden.Core.Profiles.ProfileJson.Deserialize(NetWarden.Core.Profiles.ProfileJson.Serialize(p));
        Assert.Equal("Mine", back.Name);
        Assert.Equal(TimingTemplate.Gentle, back.Timing);
        Assert.False(back.BuiltIn);
        Assert.Equal(10, back.EffectiveTiming.Concurrency);
    }
}

#if !NW_OFFLINE
public class SqliteStoreTests
{
    private static string TempDb() => Path.Combine(Path.GetTempPath(), $"nw-{Guid.NewGuid():N}.db");

    [Fact]
    public void History_saves_scans_statuses_and_append_only_audit()
    {
        var path = TempDb();
        var store = new NetWarden.Data.History.HistoryStore(NetWarden.Data.Sqlite.SqliteConnectionFactory.Instance, path);
        var scan = new ScanResult { ScopeName = "S", ProfileName = "P", Started = DateTimeOffset.Now, Finished = DateTimeOffset.Now, State = ScanState.Completed };
        var host = new HostResult { Address = "10.0.0.1", IsUp = true };
        host.Findings.Add(new Finding { Key = "k1", Title = "t", Severity = Severity.High, Host = "10.0.0.1" });
        scan.Hosts.Add(host);
        store.SaveScan(scan);
        store.SetStatus("k1", FindingStatus.AcceptedRisk, "documented", "tester");
        var loaded = store.LoadScan(scan.Id)!;
        Assert.Equal(FindingStatus.AcceptedRisk, loaded.AllFindings.Single().Status);
        Assert.Single(store.ListScans());
        store.Audit("scan-start", "tester", "S", "10.0.0.1", "P");
        Assert.Single(store.ReadAudit());
        Assert.ThrowsAny<Exception>(() =>
        {
            using var c = NetWarden.Data.Sqlite.SqliteConnectionFactory.Instance.Open(path);
            NetWarden.Data.Storage.Db.Execute(c, "DELETE FROM audit_log");
        });
    }

    [Fact]
    public void Cve_database_upsert_rules_and_kev()
    {
        var db = new NetWarden.Data.CveStore.CveDatabase(NetWarden.Data.Sqlite.SqliteConnectionFactory.Instance, TempDb());
        Assert.False(db.IsAvailable);
        db.Upsert(new[]
        {
            new NetWarden.Data.CveStore.CveImportRecord
            {
                Id = "CVE-2023-48795", Description = "Terrapin", Cvss = 5.9,
                Rules = { new NetWarden.Core.Checks.CveMatchRule("CVE-2023-48795", "openbsd", "openssh", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", null, null, null, "9.6") }
            }
        });
        db.ApplyKev(new[] { new NetWarden.Data.CveStore.KevImportRecord("CVE-2023-48795", "Terrapin", DateTimeOffset.Now, null, "Patch", "Unknown") });
        Assert.True(db.IsAvailable);
        Assert.Single(db.GetRules("openbsd", "openssh"));
        Assert.True(db.Get("CVE-2023-48795")!.Kev);
        Assert.Equal(1L, db.Stats().KevCount);
    }
}
#endif
