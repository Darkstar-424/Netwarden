using System.Text;
using System.Text.RegularExpressions;
using NetWarden.Core.Models;
using NetWarden.Core.Protocols;
using NetWarden.Core.Tls;
using NetWarden.Core.Util;

namespace NetWarden.Core.Fingerprinting;

public static class WellKnownPorts
{
    private static readonly Dictionary<int, string> Names = new()
    {
        [21] = "ftp", [22] = "ssh", [23] = "telnet", [25] = "smtp", [53] = "dns", [80] = "http", [81] = "http",
        [88] = "kerberos", [110] = "pop3", [111] = "rpcbind", [135] = "msrpc", [139] = "netbios-ssn", [143] = "imap",
        [389] = "ldap", [443] = "https", [445] = "smb", [464] = "kpasswd", [465] = "smtps", [515] = "printer",
        [548] = "afp", [554] = "rtsp", [587] = "submission", [593] = "http-rpc-epmap", [631] = "ipp", [636] = "ldaps",
        [873] = "rsync", [990] = "ftps", [993] = "imaps", [995] = "pop3s", [1433] = "mssql", [1521] = "oracle",
        [1723] = "pptp", [1883] = "mqtt", [2049] = "nfs", [2375] = "docker", [2376] = "docker-tls", [3000] = "http",
        [3268] = "ldap-gc", [3269] = "ldaps-gc", [3306] = "mysql", [3389] = "rdp", [5000] = "http", [5432] = "postgresql",
        [5601] = "kibana", [5900] = "vnc", [5901] = "vnc", [5902] = "vnc", [5903] = "vnc", [5985] = "winrm",
        [5986] = "winrm-https", [6379] = "redis", [8000] = "http", [8008] = "http", [8080] = "http-proxy",
        [8081] = "http", [8443] = "https-alt", [8888] = "http", [9000] = "http", [9090] = "http", [9100] = "jetdirect",
        [9200] = "elasticsearch", [9389] = "adws", [9443] = "https-alt", [10000] = "webmin", [11211] = "memcached",
        [27017] = "mongodb", [62078] = "iphone-sync"
    };

    private static readonly HashSet<int> TlsPorts = new() { 443, 465, 636, 990, 993, 995, 2376, 3269, 5986, 8443, 9443, 4443, 7443, 10443 };
    private static readonly HashSet<int> HttpPorts = new() { 80, 81, 591, 593, 2375, 3000, 5000, 5601, 5985, 7001, 8000, 8008, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8888, 9000, 9090, 9200, 10000 };

    public static string NameFor(int port) => Names.TryGetValue(port, out var n) ? n : "unknown";
    public static bool LikelyTls(int port) => TlsPorts.Contains(port);
    public static bool LikelyHttp(int port) => HttpPorts.Contains(port) || TlsPorts.Contains(port) && port is not (465 or 636 or 990 or 993 or 995 or 3269);
}

/// <summary>Identifies the service on an open TCP port by reading banners and sending harmless protocol greetings.</summary>
public sealed class ServiceDetector
{
    private readonly IProbeClient _probe;
    private readonly TimeSpan _timeout;
    private readonly INwLog _log;

    public ServiceDetector(IProbeClient probe, TimeSpan timeout, INwLog? log = null)
    {
        _probe = probe;
        _timeout = timeout;
        _log = log ?? NullLog.Instance;
    }

    public async Task<ServiceInfo> DetectAsync(string host, int port, CancellationToken ct)
    {
        var info = new ServiceInfo { Name = WellKnownPorts.NameFor(port) };
        try
        {
            switch (port)
            {
                case 21: await FtpAsync(host, port, info, ct).ConfigureAwait(false); break;
                case 22: await SshAsync(host, port, info, ct).ConfigureAwait(false); break;
                case 23: await TelnetAsync(host, port, info, ct).ConfigureAwait(false); break;
                case 25: case 587: await SmtpAsync(host, port, info, ct).ConfigureAwait(false); break;
                case 139: case 445: await SmbAsync(host, port, info, ct).ConfigureAwait(false); break;
                case 1433: await MssqlAsync(host, port, info, ct).ConfigureAwait(false); break;
                case 3306: await MySqlAsync(host, port, info, ct).ConfigureAwait(false); break;
                case 3389: await RdpAsync(host, port, info, ct).ConfigureAwait(false); break;
                case 5432: await PostgresAsync(host, port, info, ct).ConfigureAwait(false); break;
                case 6379: info.Name = "redis"; break;
                case >= 5900 and <= 5910: await VncAsync(host, port, info, ct).ConfigureAwait(false); break;
                default:
                    if (WellKnownPorts.LikelyHttp(port))
                        await HttpAsync(host, port, WellKnownPorts.LikelyTls(port), info, ct).ConfigureAwait(false);
                    else
                        await GenericAsync(host, port, info, ct).ConfigureAwait(false);
                    break;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Debug($"Service detection {host}:{port} failed: {ex.Message}");
        }
        foreach (var cpe in CpeMapper.Map(info.Product, info.Version))
            if (!info.Cpes.Contains(cpe)) info.Cpes.Add(cpe);
        return info;
    }

    private async Task<string?> ReadBannerAsync(string host, int port, CancellationToken ct, byte[]? send = null)
    {
        await using var s = await _probe.ConnectAsync(host, port, _timeout, ct).ConfigureAwait(false);
        if (s == null) return null;
        if (send != null) await s.SendAsync(send, ct).ConfigureAwait(false);
        var data = await s.ReceiveAsync(4096, _timeout, ct).ConfigureAwait(false);
        return data.Length == 0 ? null : Encoding.Latin1.GetString(data);
    }

    private async Task FtpAsync(string host, int port, ServiceInfo info, CancellationToken ct)
    {
        var banner = await ReadBannerAsync(host, port, ct).ConfigureAwait(false);
        if (banner == null) return;
        info.Banner = TextUtil.FirstLine(banner);
        info.Name = banner.StartsWith("220", StringComparison.Ordinal) ? "ftp" : info.Name;
        if (BannerParser.FtpBanner(banner) is { } pv) { info.Product = pv.Product; info.Version = pv.Version; }
    }

    private async Task SshAsync(string host, int port, ServiceInfo info, CancellationToken ct)
    {
        await using var s = await _probe.ConnectAsync(host, port, _timeout, ct).ConfigureAwait(false);
        if (s == null) return;
        var bannerLine = await s.ReceiveLineAsync(_timeout, ct).ConfigureAwait(false);
        // Servers may send other lines before the identification string.
        for (int i = 0; i < 5 && bannerLine != null && !bannerLine.StartsWith("SSH-", StringComparison.Ordinal); i++)
            bannerLine = await s.ReceiveLineAsync(_timeout, ct).ConfigureAwait(false);
        if (bannerLine == null) return;
        info.Name = "ssh";
        info.Banner = bannerLine;
        info.Facts["ssh.banner"] = bannerLine;
        var (software, comment) = SshPackets.ParseBanner(bannerLine);
        if (BannerParser.Ssh(software) is { } pv) { info.Product = pv.Product; info.Version = pv.Version; }
        if (comment != null) info.Facts["ssh.comment"] = comment;
        await s.SendAsync(Encoding.ASCII.GetBytes(SshPackets.ClientBanner + "\r\n"), ct).ConfigureAwait(false);
        var header = await s.ReceiveExactAsync(5, _timeout, ct).ConfigureAwait(false);
        if (header.Length < 5) return;
        var len = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
        if (len <= 0 || len > 35000) return;
        var rest = await s.ReceiveExactAsync(len - 1, _timeout, ct).ConfigureAwait(false);
        var packet = header.Concat(rest).ToArray();
        var kex = SshPackets.ParseKexInit(packet);
        if (kex == null) return;
        info.Facts["ssh.kex"] = string.Join(",", kex.Kex);
        info.Facts["ssh.hostkey"] = string.Join(",", kex.HostKey);
        info.Facts["ssh.ciphers"] = string.Join(",", kex.CiphersS2C.Union(kex.CiphersC2S));
        info.Facts["ssh.macs"] = string.Join(",", kex.MacsS2C.Union(kex.MacsC2S));
    }

    private async Task TelnetAsync(string host, int port, ServiceInfo info, CancellationToken ct)
    {
        await using var s = await _probe.ConnectAsync(host, port, _timeout, ct).ConfigureAwait(false);
        if (s == null) return;
        info.Name = "telnet";
        var data = await s.ReceiveAsync(2048, _timeout, ct).ConfigureAwait(false);
        if (data.Length > 0)
        {
            var text = ByteUtil.PrintableAscii(data.Where(b => b < 0xF0).ToArray());
            info.Banner = TextUtil.Truncate(text.Replace("..", " ").Trim('.', ' '), 200);
            info.Facts["telnet.iac"] = data.Contains((byte)0xFF) ? "yes" : "no";
        }
    }

    private async Task SmtpAsync(string host, int port, ServiceInfo info, CancellationToken ct)
    {
        await using var s = await _probe.ConnectAsync(host, port, _timeout, ct).ConfigureAwait(false);
        if (s == null) return;
        var banner = await s.ReceiveLineAsync(_timeout, ct).ConfigureAwait(false);
        if (banner == null || !banner.StartsWith("220", StringComparison.Ordinal)) return;
        info.Name = port == 587 ? "submission" : "smtp";
        info.Banner = banner;
        if (BannerParser.SmtpBanner(banner) is { } pv) { info.Product = pv.Product; info.Version = pv.Version; }
        await s.SendAsync(Encoding.ASCII.GetBytes("EHLO netwarden.local\r\n"), ct).ConfigureAwait(false);
        var caps = new List<string>();
        for (int i = 0; i < 30; i++)
        {
            var line = await s.ReceiveLineAsync(_timeout, ct).ConfigureAwait(false);
            if (line == null || line.Length < 4) break;
            caps.Add(line[4..]);
            if (line[3] == ' ') break;
        }
        info.Facts["smtp.starttls"] = caps.Any(c => c.StartsWith("STARTTLS", StringComparison.OrdinalIgnoreCase)) ? "yes" : "no";
        var auth = caps.FirstOrDefault(c => c.StartsWith("AUTH", StringComparison.OrdinalIgnoreCase));
        if (auth != null) info.Facts["smtp.auth"] = auth[4..].Trim();
        await s.SendAsync(Encoding.ASCII.GetBytes("QUIT\r\n"), ct).ConfigureAwait(false);
    }

    private async Task SmbAsync(string host, int port, ServiceInfo info, CancellationToken ct)
    {
        info.Name = "smb";
        await using (var s = await _probe.ConnectAsync(host, port, _timeout, ct).ConfigureAwait(false))
        {
            if (s != null)
            {
                if (port == 139)
                {
                    // NetBIOS session service needs a session request first; port 445 carries the same data directly.
                    info.Name = "netbios-ssn";
                }
                else
                {
                    await s.SendAsync(SmbPackets.Smb2Negotiate(), ct).ConfigureAwait(false);
                    var resp = await SmbPackets.ReadMessageAsync(s, _timeout, ct).ConfigureAwait(false);
                    var n = SmbPackets.ParseSmb2NegotiateResponse(resp);
                    if (n != null)
                    {
                        info.Facts["smb.dialect"] = n.DialectName;
                        info.Facts["smb.signing"] = n.SigningRequired ? "required" : n.SigningEnabled ? "enabled" : "disabled";
                        info.Product = "SMB";
                        info.Version = n.DialectName;
                        if (n.BootTime is DateTime boot) info.Facts["smb.boot"] = boot.ToString("u");
                    }
                }
            }
        }
        if (port != 445) return;
        await using var s1 = await _probe.ConnectAsync(host, port, _timeout, ct).ConfigureAwait(false);
        if (s1 == null) { info.Facts["smb1"] = "unknown"; return; }
        await s1.SendAsync(SmbPackets.Smb1Negotiate(), ct).ConfigureAwait(false);
        var r1 = await SmbPackets.ReadMessageAsync(s1, _timeout, ct).ConfigureAwait(false);
        var smb1 = SmbPackets.ParseSmb1NegotiateResponse(r1);
        info.Facts["smb1"] = smb1.Accepted ? "enabled" : "disabled";
        if (smb1.Accepted)
        {
            info.Facts["smb1.signing"] = smb1.SigningRequired ? "required" : smb1.SigningEnabled ? "enabled" : "disabled";
            if (!info.Facts.ContainsKey("smb.signing")) info.Facts["smb.signing"] = info.Facts["smb1.signing"];
        }
    }

    private async Task MssqlAsync(string host, int port, ServiceInfo info, CancellationToken ct)
    {
        await using var s = await _probe.ConnectAsync(host, port, _timeout, ct).ConfigureAwait(false);
        if (s == null) return;
        await s.SendAsync(TdsPackets.PreLogin(), ct).ConfigureAwait(false);
        var resp = await s.ReceiveAsync(4096, _timeout, ct).ConfigureAwait(false);
        var p = TdsPackets.ParsePreLoginResponse(resp);
        if (p == null) return;
        info.Name = "mssql";
        info.Product = p.ProductName;
        info.Version = p.Version;
        info.Facts["mssql.encryption"] = p.EncryptionName;
    }

    private async Task MySqlAsync(string host, int port, ServiceInfo info, CancellationToken ct)
    {
        await using var s = await _probe.ConnectAsync(host, port, _timeout, ct).ConfigureAwait(false);
        if (s == null) return;
        var data = await s.ReceiveAsync(4096, _timeout, ct).ConfigureAwait(false);
        var g = MySqlPackets.ParseGreeting(data);
        if (g == null) return;
        info.Name = "mysql";
        if (g.IsError)
        {
            info.Banner = g.ErrorMessage;
            info.Facts["mysql.hostBlocked"] = "yes";
            return;
        }
        info.Banner = g.ServerVersion;
        if (BannerParser.MySql(g.ServerVersion) is { } pv) { info.Product = pv.Product; info.Version = pv.Version; }
    }

    private async Task PostgresAsync(string host, int port, ServiceInfo info, CancellationToken ct)
    {
        await using var s = await _probe.ConnectAsync(host, port, _timeout, ct).ConfigureAwait(false);
        if (s == null) return;
        await s.SendAsync(PostgresPackets.SslRequest, ct).ConfigureAwait(false);
        var r = await s.ReceiveAsync(1, _timeout, ct).ConfigureAwait(false);
        if (r.Length == 1 && (r[0] == (byte)'S' || r[0] == (byte)'N'))
        {
            info.Name = "postgresql";
            info.Product = "PostgreSQL";
            info.Facts["postgres.ssl"] = r[0] == (byte)'S' ? "supported" : "not offered";
        }
    }

    private async Task RdpAsync(string host, int port, ServiceInfo info, CancellationToken ct)
    {
        // 1) Offer TLS only. NLA-enforcing servers refuse with HYBRID_REQUIRED_BY_SERVER.
        var sslOnly = await RdpNegotiateAsync(host, port, RdpPackets.ProtocolSsl, ct).ConfigureAwait(false);
        if (sslOnly.Outcome is RdpPackets.NegotiationOutcome.NoResponse or RdpPackets.NegotiationOutcome.NotRdp) return;
        info.Name = "rdp";
        info.Product = "Microsoft Terminal Services";
        info.Facts["rdp.sslOnly"] = sslOnly.Describe();
        if (sslOnly.Outcome == RdpPackets.NegotiationOutcome.Failure && sslOnly.Value is 5 or 6)
            info.Facts["rdp.nla"] = "required";
        else if (sslOnly.Outcome == RdpPackets.NegotiationOutcome.Selected)
            info.Facts["rdp.nla"] = "not-required";
        else if (sslOnly.Outcome == RdpPackets.NegotiationOutcome.LegacyNoNegotiation)
            info.Facts["rdp.nla"] = "not-supported";
        // 2) Offer classic RDP security only. Accepting it means weak "standard RDP security" is allowed.
        var classic = await RdpNegotiateAsync(host, port, RdpPackets.ProtocolRdp, ct).ConfigureAwait(false);
        info.Facts["rdp.classic"] = classic.Describe();
        info.Facts["rdp.standardSecurity"] =
            classic.Outcome is RdpPackets.NegotiationOutcome.LegacyNoNegotiation ||
            (classic.Outcome == RdpPackets.NegotiationOutcome.Selected && classic.Value == RdpPackets.ProtocolRdp)
                ? "allowed" : "refused";
    }

    private async Task<RdpPackets.NegotiationResult> RdpNegotiateAsync(string host, int port, uint protocols, CancellationToken ct)
    {
        await using var s = await _probe.ConnectAsync(host, port, _timeout, ct).ConfigureAwait(false);
        if (s == null) return new RdpPackets.NegotiationResult(RdpPackets.NegotiationOutcome.NoResponse, 0);
        await s.SendAsync(RdpPackets.ConnectionRequest(protocols), ct).ConfigureAwait(false);
        var resp = await s.ReceiveAsync(256, _timeout, ct).ConfigureAwait(false);
        return RdpPackets.ParseConfirm(resp);
    }

    private async Task VncAsync(string host, int port, ServiceInfo info, CancellationToken ct)
    {
        await using var s = await _probe.ConnectAsync(host, port, _timeout, ct).ConfigureAwait(false);
        if (s == null) return;
        var version = await s.ReceiveExactAsync(12, _timeout, ct).ConfigureAwait(false);
        var text = Encoding.ASCII.GetString(version);
        if (!text.StartsWith("RFB ", StringComparison.Ordinal)) return;
        info.Name = "vnc";
        info.Product = "VNC";
        info.Version = text.Trim();
        info.Banner = text.Trim();
        if (string.CompareOrdinal(text, "RFB 003.007") < 0)
        {
            info.Facts["vnc.securityTypes"] = "legacy (3.3)";
            return;
        }
        await s.SendAsync(Encoding.ASCII.GetBytes("RFB 003.008\n"), ct).ConfigureAwait(false);
        var types = await s.ReceiveAsync(64, _timeout, ct).ConfigureAwait(false);
        var list = VncPackets.ParseSecurityTypes(types);
        if (list != null)
        {
            info.Facts["vnc.securityTypes"] = string.Join(",", list.Select(VncPackets.SecurityTypeName));
            info.Facts["vnc.noAuth"] = list.Contains((byte)1) ? "yes" : "no";
        }
    }

    private async Task HttpAsync(string host, int port, bool tlsFirst, ServiceInfo info, CancellationToken ct)
    {
        var resp = await _probe.HttpRequestAsync(host, port, tlsFirst, "GET", "/", _timeout + _timeout, ct).ConfigureAwait(false);
        if (resp == null)
            resp = await _probe.HttpRequestAsync(host, port, !tlsFirst, "GET", "/", _timeout + _timeout, ct).ConfigureAwait(false);
        if (resp == null)
        {
            await GenericAsync(host, port, info, ct).ConfigureAwait(false);
            return;
        }
        ApplyHttp(resp, info);
    }

    public static void ApplyHttp(HttpProbeResponse resp, ServiceInfo info)
    {
        info.Name = resp.Tls ? "https" : "http";
        info.Tls = resp.Tls;
        info.Facts["http.scheme"] = resp.Tls ? "https" : "http";
        info.Facts["http.status"] = resp.StatusCode.ToString();
        var server = resp.Header("Server");
        if (server != null) { info.Facts["http.server"] = server; info.Banner = server; }
        var powered = resp.Header("X-Powered-By");
        if (powered != null) info.Facts["http.poweredBy"] = powered;
        if (BannerParser.Title(resp.Body) is string title) info.Facts["http.title"] = title;
        if (resp.Header("WWW-Authenticate") is string auth) info.Facts["http.wwwAuthenticate"] = auth;
        foreach (var h in new[] { "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Location" })
            if (resp.Header(h) is string v) info.Facts["http.header." + h.ToLowerInvariant()] = v;
        if (resp.Header("Set-Cookie") is string cookie) info.Facts["http.setCookie"] = cookie;

        if (BannerParser.HttpServer(server) is { } pv) { info.Product = pv.Product; info.Version = pv.Version; }
        foreach (var c in BannerParser.HttpComponents(server, powered, resp.Body))
        {
            info.Facts["http.component." + c.Product.ToLowerInvariant().Replace(' ', '_')] = c.Version ?? "";
            foreach (var cpe in CpeMapper.Map(c.Product, c.Version))
                if (!info.Cpes.Contains(cpe)) info.Cpes.Add(cpe);
        }
        if (resp.Body.Contains("\"cluster_name\"", StringComparison.Ordinal) && resp.Body.Contains("\"tagline\"", StringComparison.Ordinal))
        {
            info.Name = "elasticsearch";
            info.Product = "Elasticsearch";
            var m = Regex.Match(resp.Body, "\"number\"\\s*:\\s*\"(?<v>[\\d.]+)\"");
            if (m.Success) info.Version = m.Groups["v"].Value;
        }
    }

    private async Task GenericAsync(string host, int port, ServiceInfo info, CancellationToken ct)
    {
        var banner = await ReadBannerAsync(host, port, ct).ConfigureAwait(false);
        if (banner != null)
        {
            info.Banner = TextUtil.Truncate(ByteUtil.PrintableAscii(Encoding.Latin1.GetBytes(banner)), 200);
            if (banner.StartsWith("SSH-", StringComparison.Ordinal))
            {
                await SshAsync(host, port, info, ct).ConfigureAwait(false);
                return;
            }
            if (banner.StartsWith("220", StringComparison.Ordinal))
            {
                info.Name = banner.Contains("SMTP", StringComparison.OrdinalIgnoreCase) || banner.Contains("ESMTP", StringComparison.OrdinalIgnoreCase) ? "smtp" : "ftp";
                if (BannerParser.FtpBanner(banner) is { } f) { info.Product = f.Product; info.Version = f.Version; }
                else if (BannerParser.SmtpBanner(banner) is { } m) { info.Product = m.Product; info.Version = m.Version; }
            }
            else if (banner.StartsWith("+OK", StringComparison.Ordinal)) info.Name = "pop3";
            else if (banner.StartsWith("* OK", StringComparison.Ordinal)) info.Name = "imap";
            else if (banner.StartsWith("RFB ", StringComparison.Ordinal)) info.Name = "vnc";
            return;
        }
        // Silent service: try HTTP, then TLS.
        var http = await _probe.HttpRequestAsync(host, port, false, "GET", "/", _timeout, ct).ConfigureAwait(false);
        if (http != null) { ApplyHttp(http, info); return; }
        var inspector = new TlsInspector(_probe, _log);
        if (await inspector.SpeaksTlsAsync(host, port, _timeout, ct).ConfigureAwait(false))
        {
            info.Tls = true;
            var https = await _probe.HttpRequestAsync(host, port, true, "GET", "/", _timeout, ct).ConfigureAwait(false);
            if (https != null) ApplyHttp(https, info);
            else if (info.Name == "unknown") info.Name = "ssl/unknown";
        }
    }
}
