using System.Text;
using NetWarden.Core;
using NetWarden.Core.Fingerprinting;
using NetWarden.Core.Models;
using NetWarden.Core.Profiles;
using NetWarden.Checks;
using Xunit;

namespace NetWarden.Tests;

public class DetectionTests
{
    private static ServiceDetector Detector(ScriptedProbe probe) => new(probe, TimeSpan.FromMilliseconds(200));

    [Fact]
    public async Task Ssh_detection_collects_version_and_algorithms()
    {
        var probe = new ScriptedProbe().Tcp(22,
            Encoding.ASCII.GetBytes("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"),
            ProtocolTests.KexInitPacket("curve25519-sha256", "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com", "hmac-sha2-256-etm@openssh.com"));
        var s = await Detector(probe).DetectAsync("10.0.0.5", 22, CancellationToken.None);
        Assert.Equal("ssh", s.Name);
        Assert.Equal("OpenSSH", s.Product);
        Assert.Equal("8.2p1", s.Version);
        Assert.Equal("Ubuntu-4ubuntu0.5", s.Fact("ssh.comment"));
        Assert.Contains("chacha20-poly1305@openssh.com", s.Fact("ssh.ciphers"));
        Assert.Contains("cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*", s.Cpes);
    }

    [Fact]
    public async Task Rdp_detection_reads_nla_requirement()
    {
        var probe = new ScriptedProbe()
            .Tcp(3389, ProtocolTests.RdpConfirm(0x03, 5))      // TLS-only offer refused: NLA required
            .Tcp(3389, ProtocolTests.RdpConfirm(0x03, 5));     // classic RDP refused too
        var s = await Detector(probe).DetectAsync("10.0.0.5", 3389, CancellationToken.None);
        Assert.Equal("rdp", s.Name);
        Assert.Equal("required", s.Fact("rdp.nla"));
        Assert.Equal("refused", s.Fact("rdp.standardSecurity"));

        var weak = new ScriptedProbe()
            .Tcp(3389, ProtocolTests.RdpConfirm(0x02, 1))
            .Tcp(3389, ProtocolTests.RdpConfirm(0x02, 0));
        var w = await Detector(weak).DetectAsync("10.0.0.6", 3389, CancellationToken.None);
        Assert.Equal("not-required", w.Fact("rdp.nla"));
        Assert.Equal("allowed", w.Fact("rdp.standardSecurity"));
    }

    [Fact]
    public async Task Smb_detection_reads_dialect_signing_and_smb1()
    {
        var probe = new ScriptedProbe()
            .Tcp(445, ProtocolTests.Smb2NegotiateResponse(0x0302, 0x01))
            .Tcp(445, ProtocolTests.Smb1NegotiateResponse(true));
        var s = await Detector(probe).DetectAsync("10.0.0.5", 445, CancellationToken.None);
        Assert.Equal("3.0.2", s.Fact("smb.dialect"));
        Assert.Equal("enabled", s.Fact("smb.signing"));
        Assert.Equal("enabled", s.Fact("smb1"));
    }

    [Fact]
    public async Task Ftp_and_mysql_banners()
    {
        var ftp = await Detector(new ScriptedProbe().Tcp(21, Encoding.ASCII.GetBytes("220 ProFTPD 1.3.5a Server (Debian)\r\n"))).DetectAsync("h", 21, CancellationToken.None);
        Assert.Equal("ProFTPD", ftp.Product);
        Assert.Equal("1.3.5a", ftp.Version);
        Assert.Contains("cpe:2.3:a:proftpd:proftpd:1.3.5:a:*:*:*:*:*:*", ftp.Cpes);

        var payload = new NetWarden.Core.Util.PacketWriter().U8(10).Ascii("10.6.12-MariaDB-0ubuntu0.22.04.1").U8(0).Zeros(10).ToArray();
        var packet = new byte[] { (byte)payload.Length, 0, 0, 0 }.Concat(payload).ToArray();
        var db = await Detector(new ScriptedProbe().Tcp(3306, packet)).DetectAsync("h", 3306, CancellationToken.None);
        Assert.Equal("MariaDB", db.Product);
        Assert.Equal("10.6.12", db.Version);
    }

    [Fact]
    public async Task Http_detection_extracts_server_title_and_components()
    {
        var probe = new ScriptedProbe().Http("GET", "/", 200, "<html><head><title>Welcome to nginx!</title></head></html>",
            ("Server", "nginx/1.18.0 (Ubuntu)"), ("X-Powered-By", "PHP/7.4.3"));
        var s = await Detector(probe).DetectAsync("h", 8080, CancellationToken.None);
        Assert.Equal("nginx", s.Product);
        Assert.Equal("1.18.0", s.Version);
        Assert.Equal("Welcome to nginx!", s.Fact("http.title"));
        Assert.Contains("cpe:2.3:a:php:php:7.4.3:*:*:*:*:*:*:*", s.Cpes);
    }

    [Fact]
    public void Os_guess_from_ports_and_ttl()
    {
        var host = new HostResult { Address = "10.0.0.5", IsUp = true, Ttl = 128 };
        foreach (var p in new[] { 135, 445, 3389 }) host.Ports.Add(new PortResult { Port = p, State = PortState.Open, Service = new ServiceInfo() });
        var os = OsFingerprinter.Guess(host);
        Assert.Equal("Windows", os.Family);
        Assert.InRange(os.Confidence, 50, 95);

        var linux = new HostResult { Address = "10.0.0.6", IsUp = true, Ttl = 64 };
        linux.Ports.Add(new PortResult { Port = 22, State = PortState.Open, Service = new ServiceInfo { Name = "ssh", Banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" } });
        var g = OsFingerprinter.Guess(linux);
        Assert.Equal("Linux/Unix", g.Family);
        Assert.Equal("Ubuntu", g.Detail);
    }

    [Fact]
    public void Os_guess_handles_same_port_on_tcp_and_udp()
    {
        var host = new HostResult { Address = "10.0.0.7", IsUp = true, Ttl = 64 };
        host.Ports.Add(new PortResult { Port = 1900, Protocol = TransportProtocol.Tcp, State = PortState.Open, Service = new ServiceInfo() });
        host.Ports.Add(new PortResult { Port = 1900, Protocol = TransportProtocol.Udp, State = PortState.Open, Service = new ServiceInfo { Name = "ssdp" } });
        Assert.Equal("Linux/Unix", OsFingerprinter.Guess(host).Family);
    }

    [Fact]
    public async Task Offline_analysis_runs_fact_based_checks_only()
    {
        var scan = new ScanResult { State = ScanState.Imported };
        var host = new HostResult { Address = "10.0.0.9", IsUp = true };
        host.Ports.Add(new PortResult { Port = 23, State = PortState.Open, Service = new ServiceInfo { Name = "telnet" } });
        host.Ports.Add(new PortResult { Port = 6379, State = PortState.Open, Service = new ServiceInfo { Name = "redis" } });
        scan.Hosts.Add(host);
        var probe = new ScriptedProbe(); // any network use would find nothing scripted
        var orchestrator = new ScanOrchestrator(CheckRegistry.CreateAll(), null, probe: probe);
        await orchestrator.AnalyzeOfflineAsync(scan, BuiltInProfiles.Get(BuiltInProfiles.Standard), CancellationToken.None);
        Assert.Contains(host.Findings, f => f.CheckId == "svc.telnet");
        Assert.DoesNotContain(host.Findings, f => f.CheckId == "db.redis-noauth");   // safe probe: needs network
        Assert.Empty(probe.Sent);
        Assert.Empty(probe.HttpRequests);
    }

    [Fact]
    public async Task Anonymous_checks_are_skipped_unless_enabled()
    {
        var host = new HostResult { Address = "10.0.0.9", IsUp = true };
        host.Ports.Add(new PortResult { Port = 21, State = PortState.Open, Service = new ServiceInfo { Name = "ftp" } });
        var probe = new ScriptedProbe().Tcp(21, Encoding.ASCII.GetBytes("220 hi\r\n"), Encoding.ASCII.GetBytes("230 ok\r\n"));
        var orchestrator = new ScanOrchestrator(CheckRegistry.CreateAll(), null, probe: probe);
        var profile = BuiltInProfiles.Get(BuiltInProfiles.Standard);
        await orchestrator.RunChecksAsync(host, profile, TimeSpan.FromMilliseconds(100), networkAllowed: true, CancellationToken.None);
        Assert.DoesNotContain(host.Findings, f => f.CheckId == "svc.ftp-anonymous");
        profile.AllowAnonymousLoginChecks = true;
        await orchestrator.RunChecksAsync(host, profile, TimeSpan.FromMilliseconds(100), networkAllowed: true, CancellationToken.None);
        Assert.Contains(host.Findings, f => f.CheckId == "svc.ftp-anonymous");
    }

    [Fact]
    public async Task Orchestrator_refuses_unauthorized_scope()
    {
        var orchestrator = new ScanOrchestrator(Array.Empty<NetWarden.Core.Checks.IVulnerabilityCheck>(), null, probe: new ScriptedProbe());
        var request = new ScanRequest
        {
            Scope = new NetWarden.Core.Targeting.ScanScope { Targets = "127.0.0.1", Authorized = false },
            Profile = BuiltInProfiles.Get(BuiltInProfiles.QuickDiscovery),
            StartedBy = "test"
        };
        await Assert.ThrowsAsync<NetWarden.Core.Targeting.ScopeException>(() => orchestrator.RunAsync(request, null, default, CancellationToken.None));
    }

    [Fact]
    public async Task Orchestrator_scans_loopback_end_to_end()
    {
        // A real (tiny) scan of a listener on 127.0.0.1 proves the pipeline works and honours scope + exclusions.
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            try
            {
                while (true)
                {
                    using var c = await listener.AcceptTcpClientAsync();
                    var s = c.GetStream();
                    await s.WriteAsync(Encoding.ASCII.GetBytes("220 test FTP ready\r\n"));
                    await Task.Delay(50);
                }
            }
            catch (Exception) { }
        });
        try
        {
            var profile = BuiltInProfiles.Get(BuiltInProfiles.Standard);
            profile.TcpPorts = port.ToString();
            profile.UdpProbes = false;
            profile.TreatAllHostsAsUp = true;
            profile.ResolveNames = false;
            profile.TimeoutMs = 500;
            var orchestrator = new ScanOrchestrator(CheckRegistry.CreateAll(), null);
            var result = await orchestrator.RunAsync(new ScanRequest
            {
                Scope = new NetWarden.Core.Targeting.ScanScope { Targets = "127.0.0.1-2", Exclusions = "127.0.0.2", Authorized = true },
                Profile = profile,
                StartedBy = "test"
            }, null, default, CancellationToken.None);
            Assert.Equal(ScanState.Completed, result.State);
            var host = Assert.Single(result.Hosts);
            Assert.Equal("127.0.0.1", host.Address);
            var open = Assert.Single(host.OpenPorts);
            Assert.Equal(port, open.Port);
            Assert.Equal("ftp", open.Service!.Name);
            Assert.Contains(host.Findings, f => f.CheckId == "svc.ftp-cleartext");
        }
        finally
        {
            listener.Stop();
        }
    }
}
