using System.Text;
using NetWarden.Checks;
using NetWarden.Checks.Config;
using NetWarden.Checks.Cve;
using NetWarden.Checks.Packs;
using NetWarden.Checks.Probes;
using NetWarden.Core.Checks;
using NetWarden.Core.Models;
using NetWarden.Core.Protocols;
using NetWarden.Core.Util;
using Xunit;

namespace NetWarden.Tests;

public class CheckTests
{
    private static async Task<IReadOnlyList<Finding>> Run(IVulnerabilityCheck check, CheckContext ctx)
    {
        Assert.True(check.AppliesTo(ctx.Target), $"{check.Id} should apply");
        return await check.RunAsync(ctx, CancellationToken.None);
    }

    [Fact]
    public async Task Smbv1_finding_from_negotiation_fact()
    {
        var ctx = TestData.Context(TestData.Host(), TestData.Port(445, "smb", ("smb1", "enabled")));
        var f = Assert.Single(await Run(new Smb1EnabledCheck(), ctx));
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(Confidence.Confirmed, f.Confidence);
        Assert.NotEmpty(f.Remediation);
        Assert.Equal("smb.smbv1|192.168.1.10|445|-", f.Key);
    }

    [Fact]
    public void Smbv1_check_ignores_disabled()
        => Assert.False(new Smb1EnabledCheck().AppliesTo(new CheckTarget(TestData.Host(), TestData.Port(445, "smb", ("smb1", "disabled")))));

    [Theory]
    [InlineData("required", false)]
    [InlineData("enabled", true)]
    [InlineData("disabled", true)]
    public void Smb_signing_check_applies_when_not_required(string state, bool applies)
        => Assert.Equal(applies, new SmbSigningCheck().AppliesTo(new CheckTarget(TestData.Host(), TestData.Port(445, "smb", ("smb.signing", state)))));

    [Fact]
    public async Task Rdp_without_nla_is_high()
    {
        var ctx = TestData.Context(TestData.Host(), TestData.Port(3389, "rdp", ("rdp.nla", "not-required"), ("rdp.sslOnly", "selected protocol 0x1")));
        var f = Assert.Single(await Run(new RdpNlaCheck(), ctx));
        Assert.Equal(Severity.High, f.Severity);
        Assert.False(new RdpNlaCheck().AppliesTo(new CheckTarget(TestData.Host(), TestData.Port(3389, "rdp", ("rdp.nla", "required")))));
    }

    [Fact]
    public async Task Terrapin_detected_without_strict_kex()
    {
        var port = TestData.Port(22, "ssh", ("ssh.kex", "curve25519-sha256,ext-info-s"), ("ssh.ciphers", "chacha20-poly1305@openssh.com,aes128-ctr"), ("ssh.macs", "hmac-sha2-256"));
        var f = Assert.Single(await Run(new SshTerrapinCheck(), TestData.Context(TestData.Host(), port)));
        Assert.Contains("CVE-2023-48795", f.Cves);
    }

    [Fact]
    public async Task Terrapin_not_reported_with_strict_kex()
    {
        var port = TestData.Port(22, "ssh", ("ssh.kex", "curve25519-sha256,kex-strict-s-v00@openssh.com"), ("ssh.ciphers", "chacha20-poly1305@openssh.com"), ("ssh.macs", "hmac-sha2-256"));
        Assert.Empty(await Run(new SshTerrapinCheck(), TestData.Context(TestData.Host(), port)));
    }

    [Theory]
    [InlineData("aes128-cbc", "hmac-sha2-256-etm@openssh.com", true)]
    [InlineData("aes128-cbc", "hmac-sha2-256", false)]
    [InlineData("aes256-gcm@openssh.com", "hmac-sha2-256-etm@openssh.com", false)]
    public void Terrapin_logic(string cipher, string mac, bool vulnerable)
        => Assert.Equal(vulnerable, SshTerrapinCheck.IsVulnerable(new[] { "curve25519-sha256" }, new[] { cipher }, new[] { mac }));

    [Fact]
    public async Task Weak_ssh_algorithms_listed()
    {
        var port = TestData.Port(22, "ssh", ("ssh.kex", "diffie-hellman-group1-sha1,curve25519-sha256"), ("ssh.ciphers", "3des-cbc,aes128-ctr"), ("ssh.macs", "hmac-md5,hmac-sha2-256"));
        var f = Assert.Single(await Run(new SshWeakAlgorithmsCheck(), TestData.Context(TestData.Host(), port)));
        Assert.Contains("diffie-hellman-group1-sha1", f.Evidence);
        Assert.Contains("3des-cbc", f.Evidence);
        Assert.Contains("hmac-md5", f.Evidence);
    }

    [Fact]
    public async Task Legacy_tls_produces_separate_ssl_and_tls1x_findings()
    {
        var port = TestData.Port(443, "https");
        port.Tls = new TlsInfo { Protocols = { "SSLv3", "TLS 1.0", "TLS 1.2" } };
        var findings = await Run(new LegacyTlsCheck(), TestData.Context(TestData.Host(), port));
        Assert.Equal(2, findings.Count);
        Assert.Contains(findings, f => f.Severity == Severity.High && f.Cves.Contains("CVE-2014-3566"));
        Assert.Contains(findings, f => f.Severity == Severity.Medium && f.Title.Contains("TLS 1.0"));
    }

    [Fact]
    public async Task Weak_and_broken_ciphers()
    {
        var port = TestData.Port(443, "https");
        port.Tls = new TlsInfo { Protocols = { "TLS 1.2" }, Ciphers = { new CipherInfo { Name = "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Weak = true, Protocol = "TLS 1.2" } } };
        var f = Assert.Single(await Run(new WeakCipherCheck(), TestData.Context(TestData.Host(), port)));
        Assert.Equal(Severity.Medium, f.Severity);
        Assert.Contains("CVE-2016-2183", f.Cves);
        port.Tls.Ciphers.Add(new CipherInfo { Name = "TLS_RSA_EXPORT_WITH_RC4_40_MD5", Weak = true, Protocol = "TLS 1.2" });
        Assert.Equal(Severity.High, Assert.Single(await Run(new WeakCipherCheck(), TestData.Context(TestData.Host(), port))).Severity);
    }

    [Fact]
    public async Task Certificate_expiry_states()
    {
        var now = new DateTimeOffset(2026, 11, 25, 0, 0, 0, TimeSpan.Zero);
        var port = TestData.Port(443, "https");
        port.Tls = new TlsInfo { Certificate = new CertificateInfo { Subject = "CN=printer", Issuer = "CN=printer", NotBefore = now.AddYears(-2), NotAfter = now.AddDays(-41) } };
        var expired = Assert.Single(await Run(new CertificateExpiryCheck(), TestData.Context(TestData.Host(), port, now: now)));
        Assert.Contains("41 days ago", expired.Title);
        port.Tls.Certificate.NotAfter = now.AddDays(10);
        Assert.Equal(Severity.Low, Assert.Single(await Run(new CertificateExpiryCheck(), TestData.Context(TestData.Host(), port, now: now))).Severity);
        port.Tls.Certificate.NotAfter = now.AddDays(200);
        Assert.Empty(await Run(new CertificateExpiryCheck(), TestData.Context(TestData.Host(), port, now: now)));
    }

    [Fact]
    public void Dh_and_key_checks_thresholds()
    {
        var port = TestData.Port(443, "https");
        port.Tls = new TlsInfo { DhPrimeBits = 1024, Certificate = new CertificateInfo { KeyAlgorithm = "RSA", KeySize = 1024, SignatureAlgorithm = "sha256RSA" } };
        var target = new CheckTarget(TestData.Host(), port);
        Assert.True(new WeakDhCheck().AppliesTo(target));
        Assert.True(new WeakCertificateKeyCheck().AppliesTo(target));
        port.Tls.DhPrimeBits = 2048;
        port.Tls.Certificate.KeySize = 2048;
        Assert.False(new WeakDhCheck().AppliesTo(target));
        Assert.False(new WeakCertificateKeyCheck().AppliesTo(target));
    }

    [Fact]
    public async Task Telnet_and_vnc_noauth()
    {
        Assert.Equal(Severity.High, Assert.Single(await Run(new TelnetOpenCheck(), TestData.Context(TestData.Host(), TestData.Port(23, "telnet")))).Severity);
        var vnc = TestData.Port(5900, "vnc", ("vnc.noAuth", "yes"), ("vnc.securityTypes", "None"));
        Assert.Equal(Severity.Critical, Assert.Single(await Run(new VncNoAuthCheck(), TestData.Context(TestData.Host(), vnc))).Severity);
    }

    [Fact]
    public async Task Exposed_database_severity_depends_on_address()
    {
        var internalDb = Assert.Single(await Run(new ExposedDatabaseCheck(), TestData.Context(TestData.Host("10.0.0.5"), TestData.Port(3306, "mysql"))));
        Assert.Equal(Severity.Low, internalDb.Severity);
        var publicDb = Assert.Single(await Run(new ExposedDatabaseCheck(), TestData.Context(TestData.Host("203.0.113.5"), TestData.Port(3306, "mysql"))));
        Assert.Equal(Severity.High, publicDb.Severity);
    }

    [Fact]
    public async Task Http_security_headers()
    {
        var port = TestData.Port(443, "https", ("http.status", "200"), ("http.scheme", "https"), ("http.header.x-content-type-options", "nosniff"));
        var f = Assert.Single(await Run(new HttpSecurityHeadersCheck(), TestData.Context(TestData.Host(), port)));
        Assert.Contains("Strict-Transport-Security", f.Evidence);
        Assert.DoesNotContain("nosniff", f.Evidence);
    }

    [Fact]
    public async Task Cve_matching_uses_version_ranges_and_kev()
    {
        var repo = new FakeCveRepository()
            .Add("CVE-2023-0001", 9.8, kev: false, "openbsd", "openssh", endExcl: "9.3")
            .Add("CVE-2023-0002", 5.3, kev: true, "openbsd", "openssh", endExcl: "8.9")
            .Add("CVE-2023-0003", 7.5, kev: false, "openbsd", "openssh", endExcl: "8.0");
        var port = TestData.Port(22, "ssh");
        port.Service!.Product = "OpenSSH";
        port.Service.Version = "8.2p1";
        port.Service.Cpes.Add("cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*");
        var findings = await Run(new CveVersionCheck(), TestData.Context(TestData.Host(), port, cves: repo));
        Assert.Equal(2, findings.Count);
        Assert.Equal("CVE-2023-0002", findings[0].Cves[0]);          // KEV first
        Assert.True(findings[0].Kev);
        Assert.Equal(Severity.High, findings[0].Severity);            // KEV raises medium to high
        Assert.Equal(Severity.Critical, findings[1].Severity);
        Assert.All(findings, f => Assert.Equal(Confidence.Potential, f.Confidence));
    }

    [Theory]
    [InlineData("8.2p1", "8.9", -1)]
    [InlineData("2.4.41", "2.4.41", 0)]
    [InlineData("1.0.2k", "1.0.2l", -1)]
    [InlineData("1.0.2", "1.0.2k", -1)]
    [InlineData("10.0", "9.9", 1)]
    [InlineData("1.0", "1.0.0", 0)]
    [InlineData("1.0", "1.0.0.1", -1)]
    public void Version_comparison(string a, string b, int expected)
        => Assert.Equal(expected, VersionComparer.Compare(a, b));

    [Fact]
    public void Cpe_matcher_rules()
    {
        var detected = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*";
        Assert.True(CpeMatcher.Matches(detected, new CveMatchRule("C1", "apache", "http_server", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "2.4.0", null, "2.4.49", null)));
        Assert.False(CpeMatcher.Matches(detected, new CveMatchRule("C2", "apache", "http_server", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", null, null, null, "2.4.41")));
        Assert.True(CpeMatcher.Matches(detected, new CveMatchRule("C3", "apache", "http_server", "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*", null, null, null, null)));
        Assert.False(CpeMatcher.Matches(detected, new CveMatchRule("C4", "apache", "http_server", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", null, null, null, null)));
        Assert.False(CpeMatcher.Matches(detected, new CveMatchRule("C5", "apache", "tomcat", "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*", null, null, null, "99")));
        var ssh = "cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*";
        Assert.True(CpeMatcher.Matches(ssh, new CveMatchRule("C6", "openbsd", "openssh", "cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*", null, null, null, null)));
        Assert.False(CpeMatcher.Matches(ssh, new CveMatchRule("C7", "openbsd", "openssh", "cpe:2.3:a:openbsd:openssh:8.2:p2:*:*:*:*:*:*", null, null, null, null)));
    }

    [Fact]
    public void Cpe_mapper_builds_nvd_names()
    {
        Assert.Contains("cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*", NetWarden.Core.Fingerprinting.CpeMapper.Map("OpenSSH", "8.2p1"));
        Assert.Equal(2, NetWarden.Core.Fingerprinting.CpeMapper.Map("nginx", "1.18.0").Count);
        Assert.Empty(NetWarden.Core.Fingerprinting.CpeMapper.Map("nginx", null));
        Assert.Equal("cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*", NetWarden.Core.Fingerprinting.CpeMapper.FromCpe22("cpe:/a:openbsd:openssh:8.2p1"));
    }

    [Fact]
    public void Builtin_pack_loads_and_is_valid()
    {
        var checks = CheckPackLoader.LoadAll(null, w => throw new Exception(w));
        Assert.Contains(checks, c => c.Id == "web.git-exposed");
        Assert.All(checks, c => Assert.Equal(ProbeLevel.SafeProbe, c.Level));
    }

    [Fact]
    public void Pack_validator_rejects_unsafe_templates()
    {
        var pack = new CheckPack
        {
            Name = "bad",
            Templates =
            {
                new HttpTemplate { Id = "post-thing", Name = "x", Description = "x", Method = "POST", Path = "/login", Status = { 200 } },
                new HttpTemplate { Id = "traversal", Name = "x", Description = "x", Method = "GET", Path = "/../../etc/passwd", Status = { 200 } },
                new HttpTemplate { Id = "nomatch", Name = "x", Description = "x", Method = "GET", Path = "/" }
            }
        };
        var errors = CheckPackValidator.Validate(pack);
        Assert.Contains(errors, e => e.Contains("POST"));
        Assert.Contains(errors, e => e.Contains("traversal"));
        Assert.Contains(errors, e => e.Contains("matcher"));
        Assert.Empty(CheckPackLoader.FromPack(pack, null));
    }

    [Fact]
    public async Task Http_template_matches_git_head()
    {
        var git = CheckPackLoader.LoadAll(null, null).Single(c => c.Id == "web.git-exposed");
        var probe = new ScriptedProbe().Http("GET", "/.git/HEAD", 200, "ref: refs/heads/main\n");
        var port = TestData.Port(80, "http", ("http.scheme", "http"));
        var f = Assert.Single(await Run(git, TestData.Context(TestData.Host(), port, probe)));
        Assert.Equal(Severity.High, f.Severity);
        Assert.DoesNotContain("refs/heads/main", f.Evidence); // content is never stored

        var soft404 = new ScriptedProbe().Http("GET", "/.git/HEAD", 200, "<html>Not found</html>");
        Assert.Empty(await git.RunAsync(TestData.Context(TestData.Host(), TestData.Port(80, "http", ("http.scheme", "http")), soft404), CancellationToken.None));
    }

    [Fact]
    public async Task Trace_template_uses_options_only()
    {
        var trace = CheckPackLoader.LoadAll(null, null).Single(c => c.Id == "web.trace-method");
        var probe = new ScriptedProbe().Http("OPTIONS", "/", 200, "", ("Allow", "GET, HEAD, OPTIONS, TRACE"));
        Assert.Single(await Run(trace, TestData.Context(TestData.Host(), TestData.Port(80, "http", ("http.scheme", "http")), probe)));
        Assert.DoesNotContain(probe.HttpRequests, r => r.StartsWith("TRACE", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Redis_unauthenticated_probe()
    {
        var probe = new ScriptedProbe().Tcp(6379, Encoding.ASCII.GetBytes("$120\r\n# Server\r\nredis_version:6.0.16\r\nredis_mode:standalone\r\n"));
        var port = TestData.Port(6379, "redis");
        var f = Assert.Single(await Run(new RedisUnauthenticatedCheck(), TestData.Context(TestData.Host(), port, probe)));
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal("6.0.16", port.Service!.Version);
        Assert.Contains("INFO", Encoding.ASCII.GetString(probe.Sent.Single().Data));

        var protectedRedis = new ScriptedProbe().Tcp(6379, Encoding.ASCII.GetBytes("-NOAUTH Authentication required.\r\n"));
        Assert.Empty(await new RedisUnauthenticatedCheck().RunAsync(TestData.Context(TestData.Host(), TestData.Port(6379, "redis"), protectedRedis), CancellationToken.None));
    }

    [Fact]
    public async Task Anonymous_ftp_only_tries_anonymous()
    {
        var probe = new ScriptedProbe().Tcp(21,
            Encoding.ASCII.GetBytes("220 (vsFTPd 3.0.3)\r\n"),
            Encoding.ASCII.GetBytes("331 Please specify the password.\r\n"),
            Encoding.ASCII.GetBytes("230 Login successful.\r\n"));
        var check = new AnonymousFtpCheck();
        Assert.True(check.RequiresAnonymousLogin);
        var f = Assert.Single(await Run(check, TestData.Context(TestData.Host(), TestData.Port(21, "ftp"), probe)));
        Assert.Equal(Severity.Medium, f.Severity);
        var sent = string.Concat(probe.Sent.Select(s => Encoding.ASCII.GetString(s.Data)));
        Assert.Contains("USER anonymous", sent);
        Assert.Contains("QUIT", sent);
        Assert.DoesNotContain("LIST", sent);
        Assert.DoesNotContain("RETR", sent);
    }

    [Fact]
    public async Task Ms17010_reports_only_on_insufficient_resources_status()
    {
        static byte[] Status(uint status, ushort uid = 0x0800, ushort tid = 0x0001)
        {
            var smb = new PacketWriter().Bytes(new byte[] { 0xFF, (byte)'S', (byte)'M', (byte)'B' }).U8(0x25).U32LE(status).U8(0x98).U16LE(0xC001)
                .U16LE(0).Zeros(8).U16LE(0).U16LE(tid).U16LE(0xFEFF).U16LE(uid).U16LE(1).U8(0).U16LE(0).ToArray();
            return new PacketWriter().U8(0).U24BE(smb.Length).Bytes(smb).ToArray();
        }
        IProbeClient Script(uint peekStatus) => new ScriptedProbe().Tcp(445,
            ProtocolTests.Smb1NegotiateResponse(true), Status(0), Status(0), Status(peekStatus));

        var port = TestData.Port(445, "smb", ("smb1", "enabled"));
        var f = Assert.Single(await Run(new Ms17010Check(), TestData.Context(TestData.Host(), port, Script(SmbPackets.StatusInsuffServerResources))));
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.True(f.Kev);
        Assert.Empty(await new Ms17010Check().RunAsync(TestData.Context(TestData.Host(), TestData.Port(445, "smb", ("smb1", "enabled")), Script(SmbPackets.StatusInvalidHandle)), CancellationToken.None));
    }

    [Fact]
    public void Registry_discovers_all_checks_with_unique_ids()
    {
        var checks = CheckRegistry.CreateAll();
        Assert.True(checks.Count >= 30, $"only {checks.Count} checks");
        Assert.Equal(checks.Count, checks.Select(c => c.Id).Distinct().Count());
        Assert.Contains(checks, c => c is Smb1EnabledCheck);
        Assert.All(checks.Where(c => c.RequiresAnonymousLogin), c => Assert.Equal(ProbeLevel.SafeProbe, c.Level));
    }
}
