using System.Text;
using NetWarden.Core.Fingerprinting;
using NetWarden.Core.Models;
using NetWarden.Core.Protocols;
using NetWarden.Core.Scanning;
using NetWarden.Core.Util;
using Xunit;

namespace NetWarden.Tests;

public class AppIdentificationTests
{
    /// <summary>Builds a DNS response the way a Chromecast-like device answers a Bonjour query (with a name pointer).</summary>
    private static byte[] BonjourResponse()
    {
        var w = new List<byte>();
        void U16(int v) { w.Add((byte)(v >> 8)); w.Add((byte)v); }
        void Name(string n) { foreach (var l in n.Split('.')) { var b = Encoding.UTF8.GetBytes(l); w.Add((byte)b.Length); w.AddRange(b); } w.Add(0); }
        U16(0x4E57); U16(0x8400); U16(0); U16(4); U16(0); U16(0);
        // 1) _services._dns-sd._udp.local PTR _googlecast._tcp.local
        Name("_services._dns-sd._udp.local"); U16(12); U16(1); U16(0); U16(10);
        var rdStart = w.Count; U16(0);
        int typeNameOffset = w.Count;
        Name("_googlecast._tcp.local");
        var len = w.Count - rdStart - 2; w[rdStart] = (byte)(len >> 8); w[rdStart + 1] = (byte)len;
        // 2) _googlecast._tcp.local PTR Living Room._googlecast._tcp.local (compressed with a pointer)
        w.Add((byte)(0xC0 | (typeNameOffset >> 8))); w.Add((byte)typeNameOffset); U16(12); U16(1); U16(0); U16(10);
        rdStart = w.Count; U16(0);
        int instanceOffset = w.Count;
        var label = Encoding.UTF8.GetBytes("Living Room"); w.Add((byte)label.Length); w.AddRange(label);
        w.Add((byte)(0xC0 | (typeNameOffset >> 8))); w.Add((byte)typeNameOffset);
        len = w.Count - rdStart - 2; w[rdStart] = (byte)(len >> 8); w[rdStart + 1] = (byte)len;
        // 3) SRV
        w.Add((byte)(0xC0 | (instanceOffset >> 8))); w.Add((byte)instanceOffset); U16(33); U16(1); U16(0); U16(10);
        rdStart = w.Count; U16(0);
        U16(0); U16(0); U16(8009); Name("chromecast-abc.local");
        len = w.Count - rdStart - 2; w[rdStart] = (byte)(len >> 8); w[rdStart + 1] = (byte)len;
        // 4) TXT
        w.Add((byte)(0xC0 | (instanceOffset >> 8))); w.Add((byte)instanceOffset); U16(16); U16(1); U16(0); U16(10);
        rdStart = w.Count; U16(0);
        foreach (var kv in new[] { "md=Chromecast Ultra", "fn=Living Room TV", "ve=05" }) { var b = Encoding.UTF8.GetBytes(kv); w.Add((byte)b.Length); w.AddRange(b); }
        len = w.Count - rdStart - 2; w[rdStart] = (byte)(len >> 8); w[rdStart + 1] = (byte)len;
        return w.ToArray();
    }

    [Fact]
    public void Mdns_parser_reads_ptr_srv_and_txt_with_name_compression()
    {
        var records = MdnsPackets.Parse(BonjourResponse());
        Assert.NotNull(records);
        Assert.Contains(records!, r => r.Type == MdnsPackets.TypePtr && r.Target == "_googlecast._tcp.local");
        Assert.Contains(records!, r => r.Type == MdnsPackets.TypePtr && r.Target == "Living Room._googlecast._tcp.local");
        var srv = Assert.Single(records!, r => r.Type == MdnsPackets.TypeSrv);
        Assert.Equal(8009, srv.Port);
        Assert.Equal("chromecast-abc.local", srv.Target);
        var txt = Assert.Single(records!, r => r.Type == MdnsPackets.TypeTxt);
        Assert.Equal("Chromecast Ultra", txt.Txt!["md"]);
    }

    [Fact]
    public void Mdns_parser_rejects_queries_and_survives_garbage()
    {
        Assert.Null(MdnsPackets.Parse(MdnsPackets.Query(new[] { (MdnsPackets.ServicesMetaQuery, MdnsPackets.TypePtr) })));
        var bad = BonjourResponse()[..40];
        Assert.NotNull(MdnsPackets.Parse(bad));
        var loop = new byte[] { 0x4E, 0x57, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0, 0xC0, 12, 0, 12, 0, 1, 0, 0, 0, 10, 0, 0 };
        Assert.Empty(MdnsPackets.Parse(loop)!);
    }

    [Fact]
    public async Task Bonjour_identifies_cast_device_model_and_name()
    {
        var probe = new ScriptedProbe().Udp(5353, BonjourResponse());
        var bonjour = await new DeviceIdentifier(probe, TimeSpan.FromMilliseconds(200)).BonjourAsync("10.0.0.20", CancellationToken.None);
        Assert.NotNull(bonjour);
        var svc = Assert.Single(bonjour!.Services);
        Assert.Equal("_googlecast._tcp", svc.ServiceType);
        Assert.Equal("Living Room", svc.Instance);

        var host = new HostResult { Address = "10.0.0.20", IsUp = true };
        AppInventory.Build(host, bonjour, null);
        Assert.Equal("Chromecast Ultra", host.DeviceModel);
        Assert.Equal("Living Room TV", host.FriendlyName);
        Assert.Equal("Media player", host.DeviceType);
        Assert.Equal("chromecast-abc.local", host.HostName);
        var app = Assert.Single(host.Apps);
        Assert.Equal("Google Cast (Chromecast)", app.Name);
        Assert.Equal("Bonjour, port 8009", app.Where);
    }

    [Fact]
    public void Web_signatures_find_jenkins_with_version_and_cpe()
    {
        var resp = new HttpProbeResponse(200, "OK",
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["X-Jenkins"] = "2.414.1" },
            "<html><head><title>Dashboard [Jenkins]</title></head></html>", false);
        var info = new ServiceInfo { Name = "http" };
        ServiceDetector.ApplyHttp(resp, info);
        Assert.Equal("Jenkins", info.Fact("app.name"));
        Assert.Equal("2.414.1", info.Fact("app.version"));
        Assert.Contains("cpe:2.3:a:jenkins:jenkins:2.414.1:*:*:*:*:*:*:*", info.Cpes);
    }

    [Theory]
    [InlineData("Grafana", "<title>Grafana</title><script>window.grafanaBootData = {\"settings\":{\"buildInfo\":{\"commit\":\"abc\",\"version\":\"10.2.3\",\"edition\":\"OSS\"}}}</script>", null, "10.2.3")]
    [InlineData("Synology DiskStation Manager", "<title>Synology DiskStation - nas01</title>", null, null)]
    [InlineData("Proxmox Virtual Environment", "<title>pve1 - Proxmox Virtual Environment</title>", null, null)]
    [InlineData("Pi-hole", "<title>Pi-hole - raspberrypi</title>", null, null)]
    [InlineData("HP printer web page", "<title>HP Color LaserJet MFP M477fdw</title>", null, null)]
    [InlineData("Webmin", "<title>Login to Webmin</title>", "MiniServ/2.105", "2.105")]
    public void Web_signatures_recognise_common_admin_pages(string expected, string body, string? server, string? version)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (server != null) headers["Server"] = server;
        var hits = WebAppSignatures.Match(new HttpProbeResponse(200, "OK", headers, body, false));
        Assert.NotEmpty(hits);
        Assert.Equal(expected, hits[0].Name);
        Assert.Equal(version, hits[0].Version);
    }

    [Fact]
    public void Plain_pages_are_not_misidentified()
    {
        var hits = WebAppSignatures.Match(new HttpProbeResponse(200, "OK",
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Server"] = "nginx/1.24.0" },
            "<html><head><title>Welcome to my site</title></head><body>Hello taxis</body></html>", false));
        Assert.Empty(hits);
    }

    [Fact]
    public async Task Redirect_to_login_page_on_same_device_is_followed_once()
    {
        var probe = new ScriptedProbe()
            .Http("GET", "/", 302, "", ("Location", "/ui/login"))
            .Http("GET", "/ui/login", 200, "<title>Portainer</title>");
        var info = await new ServiceDetector(probe, TimeSpan.FromMilliseconds(200)).DetectAsync("10.0.0.5", 9000, CancellationToken.None);
        Assert.Equal("Portainer", info.Fact("app.name"));
        Assert.Equal(new[] { "GET /", "GET /ui/login" }, probe.HttpRequests.Take(2));
    }

    [Theory]
    [InlineData("/login", "10.0.0.5", 80, "/login")]
    [InlineData("http://10.0.0.5:8080/admin", "10.0.0.5", 8080, "/admin")]
    [InlineData("http://10.0.0.6/admin", "10.0.0.5", 80, null)]
    [InlineData("//evil.example/x", "10.0.0.5", 80, null)]
    [InlineData("https://10.0.0.5/admin", "10.0.0.5", 80, null)]
    public void Redirects_are_only_followed_on_the_same_device(string location, string host, int port, string? expected)
        => Assert.Equal(expected, ServiceDetector.SameOriginPath(location, host, port));

    private const string UpnpXml = @"<?xml version=""1.0""?>
<root xmlns=""urn:schemas-upnp-org:device-1-0"">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Home Router</friendlyName>
    <manufacturer>NETGEAR</manufacturer>
    <modelName>Nighthawk R7000</modelName>
    <modelNumber>R7000</modelNumber>
    <serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType></service></serviceList>
    <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
      <serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType></service></serviceList>
    </device></deviceList>
  </device>
</root>";

    [Fact]
    public void Upnp_description_gives_model_and_gateway_role()
    {
        var info = UpnpDescription.Parse(UpnpXml);
        Assert.NotNull(info);
        Assert.Equal("Home Router", info!.FriendlyName);
        Assert.Equal("Nighthawk R7000", info.ModelName);
        var host = new HostResult { Address = "10.0.0.1", IsUp = true };
        AppInventory.Build(host, null, info);
        Assert.Equal("NETGEAR Nighthawk R7000 R7000", host.DeviceModel);
        Assert.Equal("Router", host.DeviceType);
        Assert.Equal("NETGEAR", host.Vendor);
        Assert.Contains(host.Apps, a => a.Name.StartsWith("UPnP port forwarding", StringComparison.Ordinal));
    }

    [Fact]
    public void Upnp_parser_refuses_dtds()
    {
        const string xxe = @"<?xml version=""1.0""?><!DOCTYPE r [<!ENTITY x SYSTEM ""file:///c:/windows/win.ini"">]><root><device><friendlyName>&x;</friendlyName></device></root>";
        Assert.Null(UpnpDescription.Parse(xxe));
    }

    [Fact]
    public async Task Upnp_location_on_another_host_is_ignored()
    {
        var probe = new ScriptedProbe().Http("GET", "/desc.xml", 200, UpnpXml);
        var id = new DeviceIdentifier(probe, TimeSpan.FromMilliseconds(200));
        Assert.Null(await id.UpnpAsync("10.0.0.1", "http://10.0.0.99:5000/desc.xml", CancellationToken.None));
        Assert.Empty(probe.HttpRequests);
        Assert.NotNull(await id.UpnpAsync("10.0.0.1", "http://10.0.0.1:5000/desc.xml", CancellationToken.None));
    }

    [Fact]
    public void Inventory_turns_ports_into_readable_apps_and_guesses_device_type()
    {
        var host = new HostResult { Address = "10.0.0.30", IsUp = true };
        host.Ports.Add(new PortResult { Port = 22, Protocol = TransportProtocol.Tcp, State = PortState.Open, Service = new ServiceInfo { Name = "ssh", Product = "OpenSSH", Version = "9.6p1" } });
        host.Ports.Add(new PortResult { Port = 445, Protocol = TransportProtocol.Tcp, State = PortState.Open, Service = new ServiceInfo { Name = "smb", Product = "SMB", Version = "3.1.1" } });
        var web = new ServiceInfo { Name = "https" };
        web.Facts["app.name"] = "Synology DiskStation Manager";
        web.Facts["app.category"] = "NAS / storage";
        web.Facts["app.device"] = "NAS";
        web.Facts["app.source"] = "page title";
        host.Ports.Add(new PortResult { Port = 5001, Protocol = TransportProtocol.Tcp, State = PortState.Open, Service = web });
        host.Ports.Add(new PortResult { Port = 5000, Protocol = TransportProtocol.Tcp, State = PortState.Open, Service = new ServiceInfo { Name = "http", Facts = { ["app.name"] = "Synology DiskStation Manager" } } });

        AppInventory.Build(host, null, null);
        Assert.Equal("NAS", host.DeviceType);
        Assert.Contains(host.Apps, a => a.Name == "SSH remote login: OpenSSH" && a.Version == "9.6p1");
        Assert.Contains(host.Apps, a => a.Name == "Windows file sharing (SMB)" && a.Version == null);
        var dsm = Assert.Single(host.Apps, a => a.Name == "Synology DiskStation Manager");
        Assert.Equal("5000/tcp, 5001/tcp", dsm.Where);
    }
}
