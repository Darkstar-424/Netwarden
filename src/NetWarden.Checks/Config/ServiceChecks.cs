using NetWarden.Core.Checks;
using NetWarden.Core.Models;
using NetWarden.Core.Targeting;

namespace NetWarden.Checks.Config;

public sealed class TelnetOpenCheck : CheckBase
{
    public override string Id => "svc.telnet";
    public override string Name => "Telnet service open";
    public override string Category => "Remote access";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Port is { Protocol: TransportProtocol.Tcp } p && (p.Service?.Name == "telnet" || p.Port == 23);

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var f = ctx.NewFinding(this, "Telnet is open", Severity.High, Confidence.Configuration);
        f.Description = "Telnet sends usernames, passwords and everything typed in plain text. Anyone on the network path can read them. " +
                        "Telnet on routers, switches and IoT devices is also a common target for botnets.";
        f.Evidence = $"TCP {ctx.Port!.Port} accepted a connection" + (string.IsNullOrEmpty(ctx.Service?.Banner) ? "." : $"; banner: {ctx.Service!.Banner}");
        f.Cvss = 7.5;
        f.FixAction = "Turn off Telnet (use SSH)";
        f.Remediation.AddRange(new[]
        {
            "Disable the Telnet service on the device and use SSH instead.",
            "Windows: Disable-WindowsOptionalFeature -Online -FeatureName TelnetServer (older systems).",
            "Network gear (e.g. Cisco): 'line vty 0 15' → 'transport input ssh'.",
            "If Telnet can't be disabled, restrict it to a management VLAN with firewall rules."
        });
        return One(f);
    }
}

public sealed class FtpCleartextCheck : CheckBase
{
    public override string Id => "svc.ftp-cleartext";
    public override string Name => "Unencrypted FTP";
    public override string Category => "File transfer";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Service?.Name == "ftp" && t.Port?.Tls == null;

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var f = ctx.NewFinding(this, "FTP without encryption", Severity.Low, Confidence.Configuration);
        f.Description = "Plain FTP sends passwords and files unencrypted.";
        f.Evidence = ctx.Service?.Banner ?? $"FTP service on TCP {ctx.Port!.Port}";
        f.FixAction = "Replace FTP with SFTP or FTPS";
        f.Remediation.Add("Use SFTP (over SSH) or FTPS with TLS required, or disable the FTP service if unused.");
        return One(f);
    }
}

/// <summary>Opt-in: logs in as "anonymous" exactly once, then disconnects. Never tries any other credentials.</summary>
public sealed class AnonymousFtpCheck : CheckBase
{
    public override string Id => "svc.ftp-anonymous";
    public override string Name => "Anonymous FTP login allowed";
    public override string Category => "File transfer";
    public override ProbeLevel Level => ProbeLevel.SafeProbe;
    public override bool RequiresAnonymousLogin => true;

    public override bool AppliesTo(CheckTarget t) => t.Service?.Name == "ftp";

    public override async Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        await using var s = await ctx.Probe.ConnectAsync(ctx.Host.Address, ctx.Port!.Port, ctx.Timeout, ct).ConfigureAwait(false);
        if (s == null) return Array.Empty<Finding>();
        var banner = await s.ReceiveLineAsync(ctx.Timeout, ct).ConfigureAwait(false);
        if (banner == null || !banner.StartsWith("220", StringComparison.Ordinal)) return Array.Empty<Finding>();
        // Drain multi-line banners.
        while (banner != null && banner.Length > 3 && banner[3] == '-')
            banner = await s.ReceiveLineAsync(ctx.Timeout, ct).ConfigureAwait(false);
        await s.SendAsync("USER anonymous\r\n"u8.ToArray(), ct).ConfigureAwait(false);
        var user = await s.ReceiveLineAsync(ctx.Timeout, ct).ConfigureAwait(false);
        string? pass = null;
        if (user != null && user.StartsWith("331", StringComparison.Ordinal))
        {
            await s.SendAsync("PASS netwarden@example.invalid\r\n"u8.ToArray(), ct).ConfigureAwait(false);
            pass = await s.ReceiveLineAsync(ctx.Timeout, ct).ConfigureAwait(false);
        }
        await s.SendAsync("QUIT\r\n"u8.ToArray(), ct).ConfigureAwait(false);
        var ok = (user?.StartsWith("230", StringComparison.Ordinal) ?? false) || (pass?.StartsWith("230", StringComparison.Ordinal) ?? false);
        if (!ok) return Array.Empty<Finding>();
        var f = ctx.NewFinding(this, "Anonymous FTP login allowed", Severity.Medium, Confidence.Confirmed);
        f.Description = "Anyone can log in to this FTP server without a password. Check that nothing sensitive is readable and that uploads are not allowed.";
        f.Evidence = $"USER anonymous → {user}" + (pass != null ? $"\nPASS → {pass}" : "") + "\n(No files were listed or downloaded.)";
        f.Cvss = 5.3;
        f.FixAction = "Disable anonymous FTP";
        f.Remediation.Add("vsftpd: anonymous_enable=NO; ProFTPD: remove the <Anonymous> block; IIS: FTP Authentication › disable Anonymous.");
        f.Remediation.Add("If anonymous access is intentional (public downloads), make it read-only and keep it on an isolated server.");
        return List(f);
    }
}

public sealed class RdpNlaCheck : CheckBase
{
    public override string Id => "rdp.no-nla";
    public override string Name => "RDP without Network Level Authentication";
    public override string Category => "Remote access";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Service?.Name == "rdp" && t.Service.Fact("rdp.nla") is "not-required" or "not-supported";

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var f = ctx.NewFinding(this, "Remote Desktop doesn't require Network Level Authentication", Severity.High, Confidence.Configuration);
        f.Description = "Without NLA, Remote Desktop shows a full login session before checking who is connecting. That exposes more code to " +
                        "unauthenticated attackers (BlueKeep-style bugs) and makes denial-of-service and credential attacks easier.";
        f.Evidence = $"Offered TLS only → {ctx.Service!.Fact("rdp.sslOnly")}";
        f.Cvss = 7.5;
        f.FixAction = "Require NLA for Remote Desktop";
        f.Remediation.AddRange(new[]
        {
            "System Properties › Remote › tick \"Allow connections only from computers running Remote Desktop with Network Level Authentication\".",
            "Group Policy: Computer Configuration › Administrative Templates › Windows Components › Remote Desktop Services › Remote Desktop Session Host › Security › \"Require user authentication for remote connections by using NLA\" = Enabled.",
            "Don't expose RDP directly to the internet; use a VPN or RD Gateway."
        });
        f.References.Add("https://learn.microsoft.com/troubleshoot/windows-server/remote/remote-desktop-services-network-level-authentication");
        return One(f);
    }
}

public sealed class RdpStandardSecurityCheck : CheckBase
{
    public override string Id => "rdp.standard-security";
    public override string Name => "RDP accepts legacy 'standard RDP security'";
    public override string Category => "Remote access";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Service?.Name == "rdp" && t.Service.Fact("rdp.standardSecurity") == "allowed";

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var f = ctx.NewFinding(this, "Remote Desktop accepts legacy RDP encryption", Severity.Medium, Confidence.Configuration);
        f.Description = "The server agreed to the old RDP security layer instead of TLS. It uses RC4 and doesn't authenticate the server, so it can be intercepted.";
        f.Evidence = $"Offered PROTOCOL_RDP only → {ctx.Service!.Fact("rdp.classic")}";
        f.FixAction = "Require TLS for Remote Desktop";
        f.Remediation.Add("Group Policy: Remote Desktop Session Host › Security › \"Require use of specific security layer for remote (RDP) connections\" = SSL.");
        f.Remediation.Add("Also set \"Set client connection encryption level\" = High Level.");
        return One(f);
    }
}

public sealed class ExposedDatabaseCheck : CheckBase
{
    private static readonly Dictionary<string, string> Databases = new()
    {
        ["mysql"] = "MySQL/MariaDB", ["mssql"] = "Microsoft SQL Server", ["postgresql"] = "PostgreSQL", ["mongodb"] = "MongoDB",
        ["redis"] = "Redis", ["elasticsearch"] = "Elasticsearch", ["oracle"] = "Oracle Database", ["memcached"] = "Memcached"
    };

    public override string Id => "db.exposed";
    public override string Name => "Database reachable over the network";
    public override string Category => "Databases";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Service != null && Databases.ContainsKey(t.Service.Name) && t.Service.Fact("mysql.hostBlocked") != "yes";

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var name = Databases[ctx.Service!.Name];
        var isPublic = System.Net.IPAddress.TryParse(ctx.Host.Address, out var ip) && !AddressClassifier.IsPrivate(ip);
        var f = ctx.NewFinding(this, $"{name} port reachable on the network", isPublic ? Severity.High : Severity.Low, Confidence.Configuration);
        f.Description = isPublic
            ? $"{name} is reachable from a public internet address. Databases should never face the internet directly."
            : $"{name} accepts connections from this scanning PC. Databases should normally only be reachable from the application servers that use them.";
        f.Evidence = $"TCP {ctx.Port!.Port}: {ctx.Service.Display}" + (ctx.Service.Fact("mssql.encryption") is string enc ? $"; encryption: {enc}" : "");
        f.FixAction = "Restrict database access with a firewall";
        f.Remediation.AddRange(new[]
        {
            "Allow the database port only from the application servers and admin hosts that need it (Windows Defender Firewall / network ACLs).",
            "Bind the service to localhost or an internal interface if remote access isn't needed (e.g. MySQL bind-address, Redis bind).",
            "Require authentication and TLS for all remote connections."
        });
        return One(f);
    }
}

public sealed class VncNoAuthCheck : CheckBase
{
    public override string Id => "vnc.no-auth";
    public override string Name => "VNC without password";
    public override string Category => "Remote access";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Service?.Name == "vnc" && t.Service.Fact("vnc.noAuth") == "yes";

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var f = ctx.NewFinding(this, "VNC remote control without a password", Severity.Critical, Confidence.Confirmed);
        f.Description = "The VNC server offers the \"None\" security type: anyone who can reach it can see and control the screen.";
        f.Evidence = $"{ctx.Service!.Version}; security types offered before login: {ctx.Service.Fact("vnc.securityTypes")}. (NetWarden did not connect further.)";
        f.Cvss = 9.8;
        f.FixAction = "Set a VNC password or disable VNC";
        f.Remediation.Add("Enable password (or Windows/system) authentication in the VNC server settings.");
        f.Remediation.Add("Limit VNC to a management network or tunnel it over SSH/VPN.");
        return One(f);
    }
}

public sealed class SshWeakAlgorithmsCheck : CheckBase
{
    private static readonly string[] WeakKex = { "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1", "gss-group1-sha1-" };
    private static readonly string[] WeakCiphers = { "arcfour", "arcfour128", "arcfour256", "3des-cbc", "blowfish-cbc", "cast128-cbc", "des-cbc", "none" };
    private static readonly string[] WeakMacs = { "hmac-md5", "hmac-md5-96", "hmac-sha1-96", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com", "none" };

    public override string Id => "ssh.weak-algorithms";
    public override string Name => "Weak SSH algorithms";
    public override string Category => "Remote access";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Service?.Name == "ssh" && t.Service.Fact("ssh.kex") != null;

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var s = ctx.Service!;
        var kex = Split(s.Fact("ssh.kex")).Where(k => WeakKex.Any(w => k.StartsWith(w, StringComparison.Ordinal))).ToList();
        var ciphers = Split(s.Fact("ssh.ciphers")).Where(c => WeakCiphers.Contains(c)).ToList();
        var macs = Split(s.Fact("ssh.macs")).Where(m => WeakMacs.Contains(m)).ToList();
        if (kex.Count + ciphers.Count + macs.Count == 0) return None();
        var severity = ciphers.Any(c => c is "none" or "des-cbc" or "arcfour" or "arcfour128" or "arcfour256") || macs.Contains("none") ? Severity.Medium : Severity.Low;
        var f = ctx.NewFinding(this, "SSH server offers weak algorithms", severity, Confidence.Configuration);
        f.Description = "The SSH server still offers outdated key exchange, ciphers or integrity algorithms. Modern clients won't pick them, but old or misconfigured clients could be downgraded.";
        var parts = new List<string>();
        if (kex.Count > 0) parts.Add("Key exchange: " + string.Join(", ", kex));
        if (ciphers.Count > 0) parts.Add("Ciphers: " + string.Join(", ", ciphers));
        if (macs.Count > 0) parts.Add("MACs: " + string.Join(", ", macs));
        f.Evidence = string.Join("\n", parts);
        f.FixAction = "Remove weak SSH algorithms";
        f.Remediation.Add("OpenSSH: set KexAlgorithms, Ciphers and MACs in /etc/ssh/sshd_config to modern values (e.g. curve25519-sha256, chacha20-poly1305@openssh.com, aes256-gcm@openssh.com, hmac-sha2-256-etm@openssh.com) and restart sshd.");
        f.Remediation.Add("Appliances: update firmware; many vendors removed these algorithms in newer releases.");
        f.References.Add("https://www.ssh-audit.com/hardening_guides.html");
        return One(f);
    }

    internal static IEnumerable<string> Split(string? list) => string.IsNullOrEmpty(list) ? Array.Empty<string>() : list.Split(',', StringSplitOptions.RemoveEmptyEntries);
}

/// <summary>Terrapin (CVE-2023-48795): detected from the algorithms the server advertises in KEXINIT.</summary>
public sealed class SshTerrapinCheck : CheckBase
{
    public override string Id => "ssh.terrapin";
    public override string Name => "SSH Terrapin prefix truncation";
    public override string Category => "Remote access";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Service?.Name == "ssh" && t.Service.Fact("ssh.kex") != null;

    public static bool IsVulnerable(IEnumerable<string> kex, IEnumerable<string> ciphers, IEnumerable<string> macs)
    {
        var k = kex.ToList();
        if (k.Contains("kex-strict-s-v00@openssh.com")) return false;
        var c = ciphers.ToList();
        var m = macs.ToList();
        var chacha = c.Contains("chacha20-poly1305@openssh.com");
        var cbcEtm = c.Any(x => x.EndsWith("-cbc", StringComparison.Ordinal)) && m.Any(x => x.EndsWith("-etm@openssh.com", StringComparison.Ordinal));
        return chacha || cbcEtm;
    }

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var s = ctx.Service!;
        var kex = SshWeakAlgorithmsCheck.Split(s.Fact("ssh.kex")).ToList();
        var ciphers = SshWeakAlgorithmsCheck.Split(s.Fact("ssh.ciphers")).ToList();
        var macs = SshWeakAlgorithmsCheck.Split(s.Fact("ssh.macs")).ToList();
        if (!IsVulnerable(kex, ciphers, macs)) return None();
        var f = ctx.NewFinding(this, "SSH vulnerable to Terrapin attack", Severity.Medium, Confidence.Confirmed, "CVE-2023-48795");
        f.Description = "The server offers ChaCha20-Poly1305 or CBC with Encrypt-then-MAC without 'strict key exchange'. A man-in-the-middle can silently drop " +
                        "messages at the start of the session and weaken its security (Terrapin).";
        var evidence = new List<string> { "kex-strict-s-v00@openssh.com: not offered" };
        if (ciphers.Contains("chacha20-poly1305@openssh.com")) evidence.Add("chacha20-poly1305@openssh.com offered");
        var etm = macs.Where(m => m.EndsWith("-etm@openssh.com", StringComparison.Ordinal)).ToList();
        if (etm.Count > 0) evidence.Add("EtM MACs: " + string.Join(", ", etm));
        f.Evidence = string.Join("\n", evidence);
        f.Cves.Add("CVE-2023-48795");
        f.Cvss = 5.9;
        f.CvssVector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N";
        f.FixAction = "Update the SSH server";
        f.Remediation.Add("Update OpenSSH to 9.6 or later (or your vendor's patched build), which adds strict key exchange.");
        f.Remediation.Add("Workaround: disable chacha20-poly1305@openssh.com and all *-etm@openssh.com MACs in sshd_config.");
        f.References.Add("https://terrapin-attack.com/");
        f.References.Add("https://nvd.nist.gov/vuln/detail/CVE-2023-48795");
        return One(f);
    }
}

public sealed class HttpSecurityHeadersCheck : CheckBase
{
    public override string Id => "http.security-headers";
    public override string Name => "Missing HTTP security headers";
    public override string Category => "Web";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Service?.Fact("http.status") is string st && st.StartsWith('2');

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var s = ctx.Service!;
        var missing = new List<string>();
        var https = s.Fact("http.scheme") == "https";
        if (https && s.Fact("http.header.strict-transport-security") == null) missing.Add("Strict-Transport-Security (HSTS)");
        var csp = s.Fact("http.header.content-security-policy");
        if (s.Fact("http.header.x-frame-options") == null && (csp == null || !csp.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase)))
            missing.Add("X-Frame-Options or CSP frame-ancestors (clickjacking)");
        if (s.Fact("http.header.x-content-type-options") == null) missing.Add("X-Content-Type-Options: nosniff");
        if (missing.Count == 0) return None();
        var f = ctx.NewFinding(this, "Web server is missing security headers", Severity.Low, Confidence.Configuration);
        f.Description = "Browser security headers add protection against clickjacking, content sniffing and protocol downgrade. Most important for admin pages and sites users log in to.";
        f.Evidence = "Missing on GET /: " + string.Join("; ", missing) + (s.Fact("http.title") is string title ? $"\nPage title: {title}" : "");
        f.FixAction = "Add HTTP security headers";
        f.Remediation.Add("IIS: add custom response headers (web.config <customHeaders>). Apache: Header always set …. nginx: add_header ….");
        f.Remediation.Add("Recommended: Strict-Transport-Security: max-age=31536000; X-Frame-Options: DENY; X-Content-Type-Options: nosniff.");
        f.References.Add("https://owasp.org/www-project-secure-headers/");
        return One(f);
    }
}

public sealed class SnmpExposedCheck : CheckBase
{
    public override string Id => "udp.snmp";
    public override string Name => "SNMP agent reachable";
    public override string Category => "Network services";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Port is { Protocol: TransportProtocol.Udp, Port: 161 };

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var f = ctx.NewFinding(this, "SNMP management agent reachable", Severity.Info, Confidence.Configuration);
        f.Description = "SNMP lets management tools read (and sometimes change) device settings. Check that SNMPv1/v2c is disabled or uses a non-default community string, and that SNMP is limited to your monitoring servers. " +
                        "NetWarden only performed an unauthenticated SNMPv3 discovery; it did not try any community strings.";
        f.Evidence = ctx.Service?.Banner ?? "SNMPv3 engine discovery answered";
        f.FixAction = "Restrict SNMP to monitoring hosts";
        f.Remediation.Add("Use SNMPv3 with authentication and privacy; disable v1/v2c or change default 'public'/'private' communities.");
        f.Remediation.Add("Restrict UDP 161 to the monitoring server with ACLs.");
        return One(f);
    }
}

public sealed class UpnpExposedCheck : CheckBase
{
    public override string Id => "udp.upnp";
    public override string Name => "UPnP/SSDP responder";
    public override string Category => "Network services";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Port is { Protocol: TransportProtocol.Udp, Port: 1900 };

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var isPublic = System.Net.IPAddress.TryParse(ctx.Host.Address, out var ip) && !AddressClassifier.IsPrivate(ip);
        var f = ctx.NewFinding(this, "UPnP discovery service answers", isPublic ? Severity.High : Severity.Low, Confidence.Configuration);
        f.Description = isPublic
            ? "UPnP/SSDP answers on a public address. It can be abused for DDoS amplification and exposes device details."
            : "UPnP lets devices and apps open ports on your router automatically. On routers it is often better turned off.";
        f.Evidence = ctx.Service?.Banner ?? "M-SEARCH answered";
        f.FixAction = "Disable UPnP where not needed";
        f.Remediation.Add("Disable UPnP on routers and devices that don't need it; never allow SSDP from the internet.");
        return One(f);
    }
}

public sealed class IpmiExposedCheck : CheckBase
{
    public override string Id => "udp.ipmi";
    public override string Name => "IPMI/BMC management interface";
    public override string Category => "Network services";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Port is { Protocol: TransportProtocol.Udp, Port: 623 };

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var f = ctx.NewFinding(this, "Server management controller (IPMI/BMC) reachable", Severity.Medium, Confidence.Configuration);
        f.Description = "Baseboard management controllers (iLO, iDRAC, IPMI) have full control of the server, even when it's switched off. IPMI 2.0 has design weaknesses that can leak password hashes. " +
                        "BMCs belong on a separate management network.";
        f.Evidence = "RMCP/ASF presence ping answered on UDP 623.";
        f.FixAction = "Move BMCs to a management network";
        f.Remediation.Add("Put iLO/iDRAC/IPMI interfaces on an isolated management VLAN reachable only by administrators.");
        f.Remediation.Add("Disable IPMI-over-LAN if you only use the web/Redfish interface; keep BMC firmware updated; change default passwords.");
        f.References.Add("https://www.cisa.gov/news-events/alerts/2013/07/26/risks-using-intelligent-platform-management-interface-ipmi");
        return One(f);
    }
}
