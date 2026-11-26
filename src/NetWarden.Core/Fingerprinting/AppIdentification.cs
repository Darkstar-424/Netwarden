using System.Text.RegularExpressions;
using System.Xml.Linq;
using NetWarden.Core.Models;
using NetWarden.Core.Util;

namespace NetWarden.Core.Fingerprinting;

/// <summary>An identified application, before it is attached to a host.</summary>
public sealed record AppHit(string Name, string Category, string? Version = null, string? DeviceHint = null,
    string? CpeVendor = null, string? CpeProduct = null, string Source = "");

/// <summary>
/// Recognises web applications and device admin pages from the response NetWarden already fetched for "/"
/// (page title, response headers, cookies and page markers). Nothing extra is requested.
/// </summary>
public static class WebAppSignatures
{
    private sealed record Sig(string Name, string Category, string? Title = null, string? Server = null, string? Body = null,
        string? Header = null, string? HeaderValue = null, string? Cookie = null, string? Realm = null,
        string? VersionFrom = null, string? VersionRegex = null, string? Device = null, string? CpeVendor = null, string? CpeProduct = null);

    private const RegexOptions Opt = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    // Patterns are matched case-insensitively. A signature matches when ANY of its title/server/body/header/cookie/realm
    // patterns matches. VersionFrom is "header:<name>", "server", "title" or "body"; VersionRegex must have a group "v".
    private static readonly Sig[] Sigs =
    {
        // NAS and storage
        new("Synology DiskStation Manager", "NAS / storage", Title: @"Synology|DiskStation", Body: @"SYNO\.SDS|webman/modules", Device: "NAS", CpeVendor: "synology", CpeProduct: "diskstation_manager"),
        new("QNAP QTS", "NAS / storage", Title: @"\bQNAP\b|\bQTS\b", Body: @"qnap\.com|QTS_", Device: "NAS"),
        new("TrueNAS", "NAS / storage", Title: @"TrueNAS|FreeNAS", Device: "NAS"),
        new("Unraid", "NAS / storage", Title: @"Unraid", Body: @"unraid\.net", Device: "NAS"),
        new("ASUSTOR ADM", "NAS / storage", Title: @"ASUSTOR", Device: "NAS"),
        new("WD My Cloud", "NAS / storage", Title: @"My ?Cloud", Body: @"wdmycloud", Device: "NAS"),
        new("MinIO", "NAS / storage", Title: @"MinIO", Server: @"^MinIO", CpeVendor: "minio", CpeProduct: "minio"),
        new("Nextcloud", "File sharing", Title: @"Nextcloud", Cookie: @"nc_sameSiteCookie", CpeVendor: "nextcloud", CpeProduct: "nextcloud_server"),
        new("ownCloud", "File sharing", Title: @"ownCloud"),
        new("Immich", "Media", Title: @"^Immich"),

        // Virtualisation and servers
        new("Proxmox Virtual Environment", "Virtualisation", Title: @"Proxmox Virtual Environment", Server: @"pve-api-daemon", Device: "Hypervisor", CpeVendor: "proxmox", CpeProduct: "virtual_environment"),
        new("Proxmox Backup Server", "Backup", Title: @"Proxmox Backup Server", Server: @"proxmox-backup"),
        new("VMware ESXi", "Virtualisation", Title: @"VMware ESXi", Body: @"ID_EESX_Welcome", Device: "Hypervisor"),
        new("VMware vCenter", "Virtualisation", Title: @"vSphere|vCenter", Body: @"ID_VC_Welcome"),
        new("Portainer", "Containers", Title: @"Portainer", CpeVendor: "portainer", CpeProduct: "portainer"),
        new("Docker Registry", "Containers", Header: "Docker-Distribution-Api-Version"),
        new("Cockpit", "Server admin", Title: @"Cockpit", Body: @"cockpit/static"),
        new("Webmin", "Server admin", Title: @"Webmin", Server: @"MiniServ", VersionFrom: "server", VersionRegex: @"MiniServ/(?<v>[\d.]+)", CpeVendor: "webmin", CpeProduct: "webmin"),
        new("Windows Admin Center", "Server admin", Title: @"Windows Admin Center"),
        new("HPE iLO", "Server management (BMC)", Title: @"\biLO\b|Integrated Lights-Out", Device: "Server"),
        new("Dell iDRAC", "Server management (BMC)", Title: @"iDRAC", Device: "Server"),
        new("Supermicro IPMI", "Server management (BMC)", Title: @"Supermicro", Body: @"ATEN International", Device: "Server"),
        new("Apache Tomcat", "Web server", Title: @"Apache Tomcat", VersionFrom: "title", VersionRegex: @"Tomcat/(?<v>\d+\.\d+\.\d+)", CpeVendor: "apache", CpeProduct: "tomcat"),
        new("IIS default page", "Web server", Title: @"^IIS Windows|^IIS\d|Internet Information Services"),

        // Developer and IT tools
        new("Jenkins", "Developer tools", Title: @"\[Jenkins\]", Header: "X-Jenkins", VersionFrom: "header:X-Jenkins", VersionRegex: @"(?<v>[\d.]+)", CpeVendor: "jenkins", CpeProduct: "jenkins"),
        new("GitLab", "Developer tools", Title: @"GitLab", Cookie: @"_gitlab_session", CpeVendor: "gitlab", CpeProduct: "gitlab"),
        new("Gitea", "Developer tools", Title: @"\bGitea\b", Cookie: @"i_like_gitea", CpeVendor: "gitea", CpeProduct: "gitea"),
        new("Grafana", "Monitoring", Title: @"^Grafana", Body: @"grafana-app|""appSubUrl""", VersionFrom: "body", VersionRegex: @"""buildInfo"":\{[^}]*?""version"":""(?<v>\d+\.\d+\.\d+)", CpeVendor: "grafana", CpeProduct: "grafana"),
        new("Kibana", "Monitoring", Header: "kbn-name", Title: @"^Kibana|^Elastic$", VersionFrom: "header:kbn-version", VersionRegex: @"(?<v>[\d.]+)", CpeVendor: "elastic", CpeProduct: "kibana"),
        new("Prometheus", "Monitoring", Title: @"Prometheus Time Series"),
        new("Zabbix", "Monitoring", Title: @"Zabbix", CpeVendor: "zabbix", CpeProduct: "zabbix"),
        new("Nagios", "Monitoring", Realm: @"Nagios", Title: @"^Nagios"),
        new("Uptime Kuma", "Monitoring", Title: @"Uptime Kuma"),
        new("phpMyAdmin", "Database admin", Title: @"phpMyAdmin", CpeVendor: "phpmyadmin", CpeProduct: "phpmyadmin"),
        new("Jupyter", "Developer tools", Title: @"^Jupyter|JupyterLab|JupyterHub"),
        new("code-server", "Developer tools", Title: @"code-server"),
        new("Apache Guacamole", "Remote access", Title: @"Guacamole"),
        new("Ollama", "AI service", Body: @"^Ollama is running"),
        new("Vaultwarden / Bitwarden", "Password manager", Title: @"Vaultwarden|Bitwarden Web vault"),
        new("Nginx Proxy Manager", "Reverse proxy", Title: @"Nginx Proxy Manager"),
        new("Traefik", "Reverse proxy", Title: @"^Traefik", Body: @"traefik-dashboard"),
        new("Node-RED", "Smart home / IoT", Title: @"Node-RED"),
        new("Paperless-ngx", "Documents", Title: @"Paperless"),
        new("WordPress", "Website / CMS", Body: @"/wp-content/|/wp-includes/", VersionFrom: "body", VersionRegex: @"<meta name=""generator"" content=""WordPress (?<v>[\d.]+)", CpeVendor: "wordpress", CpeProduct: "wordpress"),
        new("Roundcube Webmail", "Mail", Title: @"Roundcube"),
        new("Outlook Web Access (Exchange)", "Mail", Header: "X-OWA-Version", Title: @"Outlook Web App|Outlook$", VersionFrom: "header:X-OWA-Version", VersionRegex: @"(?<v>[\d.]+)"),
        new("SharePoint", "Collaboration", Header: "MicrosoftSharePointTeamServices", VersionFrom: "header:MicrosoftSharePointTeamServices", VersionRegex: @"(?<v>[\d.]+)"),

        // Media and downloads
        new("Plex Media Server", "Media", Header: "X-Plex-Protocol", Title: @"^Plex$", Device: "Media server"),
        new("Jellyfin", "Media", Title: @"Jellyfin", Device: "Media server"),
        new("Emby", "Media", Title: @"^Emby", Device: "Media server"),
        new("Sonarr / Radarr / Lidarr", "Media", Title: @"^(Sonarr|Radarr|Lidarr|Prowlarr|Readarr|Bazarr)\b"),
        new("Transmission", "Downloads", Realm: @"Transmission", Title: @"Transmission Web"),
        new("qBittorrent", "Downloads", Title: @"qBittorrent"),
        new("Deluge", "Downloads", Title: @"Deluge"),
        new("SABnzbd", "Downloads", Title: @"SABnzbd"),
        new("AirPlay receiver", "Media", Server: @"AirTunes", VersionFrom: "server", VersionRegex: @"AirTunes/(?<v>[\d.]+)", Device: "Apple device"),
        new("Roku", "Media", Server: @"Roku", Device: "Media player"),

        // Smart home / IoT
        new("Home Assistant", "Smart home / IoT", Title: @"Home Assistant", Device: "Smart home hub"),
        new("Philips Hue Bridge", "Smart home / IoT", Title: @"hue personal wireless lighting", Body: @"Philips hue", Device: "Smart home hub"),
        new("Shelly", "Smart home / IoT", Title: @"^Shelly", Device: "Smart home device"),
        new("Tasmota", "Smart home / IoT", Title: @"Tasmota", Body: @"Tasmota", Device: "Smart home device"),
        new("ESPHome", "Smart home / IoT", Body: @"ESPHome", Device: "Smart home device"),
        new("OctoPrint", "3D printing", Title: @"OctoPrint", Device: "3D printer"),

        // Network gear
        new("UniFi Network", "Network gear", Title: @"UniFi", Device: "Network controller"),
        new("pfSense", "Firewall", Title: @"pfSense", Device: "Firewall"),
        new("OPNsense", "Firewall", Title: @"OPNsense", Device: "Firewall"),
        new("OpenWrt (LuCI)", "Network gear", Title: @"LuCI|OpenWrt", Body: @"luci-static", Device: "Router"),
        new("DD-WRT", "Network gear", Title: @"DD-WRT", Device: "Router"),
        new("MikroTik RouterOS", "Network gear", Title: @"RouterOS|MikroTik", Device: "Router"),
        new("Ubiquiti EdgeOS", "Network gear", Title: @"EdgeOS", Device: "Router"),
        new("FortiGate", "Firewall", Title: @"FortiGate", Body: @"ftnt-fortinet", Device: "Firewall"),
        new("SonicWall", "Firewall", Title: @"SonicWall|SonicWALL", Device: "Firewall"),
        new("Pi-hole", "Network service", Title: @"Pi-hole", Header: "X-Pi-hole", CpeVendor: "pi-hole", CpeProduct: "pi-hole"),
        new("AdGuard Home", "Network service", Title: @"AdGuard Home"),
        new("NETGEAR router", "Network gear", Title: @"NETGEAR", Realm: @"NETGEAR", Device: "Router"),
        new("TP-Link device", "Network gear", Title: @"TP-?LINK|Archer|Deco", Body: @"tplinkwifi", Device: "Router"),
        new("ASUS router", "Network gear", Title: @"ASUS (Wireless )?Router", Body: @"ASUSWRT", Device: "Router"),
        new("Linksys router", "Network gear", Title: @"Linksys", Device: "Router"),
        new("Cisco device", "Network gear", Title: @"^Cisco", Realm: @"level_15_access|Cisco", Device: "Network device"),

        // Printers and cameras
        new("HP printer web page", "Printing", Server: @"HP HTTP Server|HP-ChaiSOE", Title: @"LaserJet|OfficeJet|DeskJet|HP ENVY|PageWide|DesignJet", Device: "Printer"),
        new("Brother printer web page", "Printing", Server: @"^debut", Title: @"^Brother", Device: "Printer"),
        new("Canon printer web page", "Printing", Server: @"Canon HTTP Server|CANON HTTP", Title: @"^Canon", Device: "Printer"),
        new("Epson printer web page", "Printing", Server: @"EPSON", Title: @"^EPSON", Device: "Printer"),
        new("Xerox printer web page", "Printing", Title: @"Xerox", Device: "Printer"),
        new("Hikvision camera/NVR", "Camera", Server: @"App-webs|DNVRS-Webs|Hikvision", Body: @"doc/page/login\.asp", Device: "Camera"),
        new("Dahua camera/NVR", "Camera", Body: @"/RPC2_Login|dahua", Device: "Camera"),
        new("Axis camera", "Camera", Title: @"^AXIS\b", Device: "Camera"),
    };

    private static readonly Dictionary<string, Regex> Cache = new();

    private static Regex R(string pattern)
    {
        lock (Cache)
        {
            if (!Cache.TryGetValue(pattern, out var r)) Cache[pattern] = r = new Regex(pattern, Opt, TimeSpan.FromMilliseconds(200));
            return r;
        }
    }

    private static bool Is(string? pattern, string? text) => pattern != null && !string.IsNullOrEmpty(text) && R(pattern).IsMatch(text);

    public static IReadOnlyList<AppHit> Match(HttpProbeResponse resp)
    {
        var title = BannerParser.Title(resp.Body);
        var server = resp.Header("Server");
        var cookie = resp.Header("Set-Cookie");
        var realm = resp.Header("WWW-Authenticate");
        var hits = new List<AppHit>();
        foreach (var s in Sigs)
        {
            bool headerHit = s.Header != null && resp.Header(s.Header) is string hv && (s.HeaderValue == null || R(s.HeaderValue).IsMatch(hv));
            string? why =
                Is(s.Title, title) ? "page title" :
                Is(s.Server, server) ? "Server header" :
                headerHit ? $"{s.Header} header" :
                Is(s.Cookie, cookie) ? "cookie name" :
                Is(s.Realm, realm) ? "login prompt" :
                Is(s.Body, resp.Body) ? "page content" : null;
            if (why == null) continue;
            string? version = null;
            if (s.VersionRegex != null)
            {
                var src = s.VersionFrom switch
                {
                    "server" => server,
                    "title" => title,
                    "body" => resp.Body,
                    { } h when h.StartsWith("header:", StringComparison.Ordinal) => resp.Header(h[7..]),
                    _ => null
                };
                if (src != null && R(s.VersionRegex).Match(src) is { Success: true } m) version = m.Groups["v"].Value;
            }
            hits.Add(new AppHit(s.Name, s.Category, version, s.Device, s.CpeVendor, s.CpeProduct, why));
        }
        return hits;
    }

    public static int Count => Sigs.Length;
}

/// <summary>Plain-English names for Bonjour / mDNS service types.</summary>
public static class MdnsServiceCatalog
{
    private static readonly Dictionary<string, (string Name, string Category, string? Device)> Types = new(StringComparer.OrdinalIgnoreCase)
    {
        ["_airplay._tcp"] = ("AirPlay receiver", "Media", "Media player"),
        ["_raop._tcp"] = ("AirPlay audio", "Media", null),
        ["_googlecast._tcp"] = ("Google Cast (Chromecast)", "Media", "Media player"),
        ["_spotify-connect._tcp"] = ("Spotify Connect", "Media", null),
        ["_sonos._tcp"] = ("Sonos speaker", "Media", "Speaker"),
        ["_daap._tcp"] = ("iTunes / Music sharing", "Media", null),
        ["_dpap._tcp"] = ("Photo sharing", "Media", null),
        ["_plexmediasvr._tcp"] = ("Plex Media Server", "Media", "Media server"),
        ["_amzn-wplay._tcp"] = ("Amazon Fire TV / Echo", "Media", "Media player"),
        ["_androidtvremote2._tcp"] = ("Android TV", "Media", "TV"),
        ["_nvstream._tcp"] = ("NVIDIA GameStream", "Media", null),
        ["_ipp._tcp"] = ("Printer (IPP)", "Printing", "Printer"),
        ["_ipps._tcp"] = ("Printer (IPP over TLS)", "Printing", "Printer"),
        ["_printer._tcp"] = ("Printer (LPD)", "Printing", "Printer"),
        ["_pdl-datastream._tcp"] = ("Printer (raw / JetDirect)", "Printing", "Printer"),
        ["_scanner._tcp"] = ("Scanner", "Printing", null),
        ["_uscan._tcp"] = ("Scanner (eSCL / AirScan)", "Printing", null),
        ["_uscans._tcp"] = ("Scanner (eSCL over TLS)", "Printing", null),
        ["_smb._tcp"] = ("File sharing (SMB)", "File sharing", null),
        ["_afpovertcp._tcp"] = ("Apple file sharing (AFP)", "File sharing", null),
        ["_adisk._tcp"] = ("Time Machine backup target", "Backup", "NAS"),
        ["_nfs._tcp"] = ("File sharing (NFS)", "File sharing", null),
        ["_ftp._tcp"] = ("FTP server", "File transfer", null),
        ["_webdav._tcp"] = ("WebDAV file sharing", "File sharing", null),
        ["_ssh._tcp"] = ("SSH remote login", "Remote access", null),
        ["_sftp-ssh._tcp"] = ("SFTP file transfer", "File transfer", null),
        ["_rfb._tcp"] = ("Screen sharing (VNC)", "Remote access", null),
        ["_rdp._tcp"] = ("Remote Desktop", "Remote access", null),
        ["_http._tcp"] = ("Web interface", "Web server", null),
        ["_https._tcp"] = ("Web interface (HTTPS)", "Web server", null),
        ["_workstation._tcp"] = ("Computer (workstation)", "Computer", "Computer"),
        ["_device-info._tcp"] = ("Device information", "Device info", null),
        ["_companion-link._tcp"] = ("Apple device (Continuity)", "Apple services", "Apple device"),
        ["_apple-mobdev2._tcp"] = ("Apple mobile device sync", "Apple services", "Apple device"),
        ["_homekit._tcp"] = ("HomeKit hub", "Smart home / IoT", "Smart home hub"),
        ["_hap._tcp"] = ("HomeKit accessory", "Smart home / IoT", "Smart home device"),
        ["_hap._udp"] = ("HomeKit accessory (Thread)", "Smart home / IoT", "Smart home device"),
        ["_matter._tcp"] = ("Matter smart-home device", "Smart home / IoT", "Smart home device"),
        ["_matterc._udp"] = ("Matter device (commissioning)", "Smart home / IoT", "Smart home device"),
        ["_meshcop._udp"] = ("Thread border router", "Smart home / IoT", "Smart home hub"),
        ["_home-assistant._tcp"] = ("Home Assistant", "Smart home / IoT", "Smart home hub"),
        ["_hue._tcp"] = ("Philips Hue Bridge", "Smart home / IoT", "Smart home hub"),
        ["_esphomelib._tcp"] = ("ESPHome device", "Smart home / IoT", "Smart home device"),
        ["_mqtt._tcp"] = ("MQTT broker", "Smart home / IoT", null),
        ["_sleep-proxy._udp"] = ("Bonjour Sleep Proxy", "Apple services", null),
        ["_touch-able._tcp"] = ("Apple TV Remote", "Media", "Media player"),
        ["_mediaremotetv._tcp"] = ("Apple TV", "Media", "Media player"),
        ["_airport._tcp"] = ("Apple AirPort base station", "Network gear", "Router"),
        ["_teamviewer._tcp"] = ("TeamViewer", "Remote access", null),
        ["_xbox._tcp"] = ("Xbox", "Gaming", "Games console"),
        ["_psn._tcp"] = ("PlayStation", "Gaming", "Games console"),
        ["_steam._tcp"] = ("Steam", "Gaming", null),
    };

    public static (string Name, string Category, string? Device) Describe(string serviceType)
        => Types.TryGetValue(serviceType, out var d) ? d : ($"Bonjour service {serviceType}", "Other", null);

    public static bool IsKnown(string serviceType) => Types.ContainsKey(serviceType);

    /// <summary>Picks a make/model out of the TXT records services publish (e.g. md= for Cast, ty= for printers, model= for device-info).</summary>
    public static string? ModelFromTxt(string serviceType, IReadOnlyDictionary<string, string> txt)
    {
        string? Get(string k) => txt.TryGetValue(k, out var v) && !string.IsNullOrWhiteSpace(v) ? v.Trim() : null;
        return serviceType.ToLowerInvariant() switch
        {
            "_googlecast._tcp" => Get("md"),
            "_ipp._tcp" or "_ipps._tcp" or "_printer._tcp" or "_pdl-datastream._tcp" => Get("ty") ?? Get("product")?.Trim('(', ')'),
            "_airplay._tcp" or "_raop._tcp" => Get("model") ?? Get("am"),
            "_device-info._tcp" => Get("model"),
            "_hap._tcp" => Get("md"),
            _ => Get("model")
        };
    }
}

/// <summary>Reads a UPnP device description (the XML a device publishes at the LOCATION address from SSDP).</summary>
public static class UpnpDescription
{
    public sealed record Info(string? FriendlyName, string? Manufacturer, string? ModelName, string? ModelNumber,
        string? ModelDescription, IReadOnlyList<string> DeviceTypes, IReadOnlyList<string> ServiceTypes);

    public static Info? Parse(string xml)
    {
        try
        {
            var settings = new System.Xml.XmlReaderSettings { DtdProcessing = System.Xml.DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 1_000_000 };
            using var reader = System.Xml.XmlReader.Create(new StringReader(xml), settings);
            var doc = XDocument.Load(reader);
            var device = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "device");
            if (device == null) return null;
            string? Val(string name) => device.Elements().FirstOrDefault(e => e.Name.LocalName == name)?.Value.Trim() is { Length: > 0 } v ? v : null;
            var deviceTypes = doc.Descendants().Where(e => e.Name.LocalName == "deviceType").Select(e => e.Value.Trim()).Where(v => v.Length > 0).Distinct().ToList();
            var serviceTypes = doc.Descendants().Where(e => e.Name.LocalName == "serviceType").Select(e => e.Value.Trim()).Where(v => v.Length > 0).Distinct().ToList();
            return new Info(Val("friendlyName"), Val("manufacturer"), Val("modelName"), Val("modelNumber"), Val("modelDescription"), deviceTypes, serviceTypes);
        }
        catch (Exception ex) when (ex is System.Xml.XmlException or InvalidOperationException)
        {
            return null;
        }
    }

    private static readonly (string Marker, string Name, string Category, string? Device)[] Known =
    {
        ("device:InternetGatewayDevice", "UPnP Internet gateway (can open ports on request)", "Network gear", "Router"),
        ("service:WANIPConnection", "UPnP port forwarding (IGD)", "Network gear", "Router"),
        ("device:MediaServer", "DLNA media server", "Media", "Media server"),
        ("device:MediaRenderer", "DLNA media renderer (can play media)", "Media", "Media player"),
        ("service:AVTransport", "Media playback control", "Media", null),
        ("device:Printer", "UPnP printer", "Printing", "Printer"),
        ("device:Basic", "UPnP device", "Device info", null),
        ("dial-multiscreen-org:service:dial", "DIAL screen casting", "Media", "TV"),
        ("schemas-sonos-com", "Sonos speaker", "Media", "Speaker"),
        ("device:ZonePlayer", "Sonos speaker", "Media", "Speaker"),
        ("device:WLANAccessPointDevice", "Wireless access point", "Network gear", "Access point"),
        ("device:DigitalSecurityCamera", "Security camera", "Camera", "Camera"),
        ("device:HVAC", "Heating / cooling controller", "Smart home / IoT", "Smart home device"),
        ("device:Lighting", "Lighting controller", "Smart home / IoT", "Smart home device"),
    };

    public static IEnumerable<(string Name, string Category, string? Device)> Describe(Info info)
    {
        var all = info.DeviceTypes.Concat(info.ServiceTypes).ToList();
        foreach (var k in Known)
            if (all.Any(t => t.Contains(k.Marker, StringComparison.OrdinalIgnoreCase)))
                yield return (k.Name, k.Category, k.Device);
    }

    /// <summary>"LOCATION:" header from an SSDP response.</summary>
    public static string? Location(string ssdpResponse)
    {
        foreach (var line in ssdpResponse.Split("\r\n"))
            if (line.StartsWith("LOCATION:", StringComparison.OrdinalIgnoreCase)) return line[9..].Trim();
        return null;
    }
}

/// <summary>Turns the ports already identified into a readable "apps and services" list.</summary>
public static class ServiceCatalog
{
    private static readonly Dictionary<string, (string Name, string Category)> Names = new(StringComparer.OrdinalIgnoreCase)
    {
        ["ssh"] = ("SSH remote login", "Remote access"),
        ["telnet"] = ("Telnet remote login (unencrypted)", "Remote access"),
        ["rdp"] = ("Remote Desktop", "Remote access"),
        ["vnc"] = ("VNC screen sharing", "Remote access"),
        ["winrm"] = ("Windows Remote Management", "Remote access"),
        ["winrm-https"] = ("Windows Remote Management (HTTPS)", "Remote access"),
        ["ftp"] = ("FTP file transfer", "File transfer"),
        ["ftps"] = ("FTP over TLS", "File transfer"),
        ["smb"] = ("Windows file sharing (SMB)", "File sharing"),
        ["netbios-ssn"] = ("NetBIOS file sharing", "File sharing"),
        ["nfs"] = ("NFS file sharing", "File sharing"),
        ["afp"] = ("Apple file sharing (AFP)", "File sharing"),
        ["rsync"] = ("rsync file sync", "File sharing"),
        ["mssql"] = ("Microsoft SQL Server", "Database"),
        ["mysql"] = ("MySQL / MariaDB", "Database"),
        ["postgresql"] = ("PostgreSQL", "Database"),
        ["redis"] = ("Redis", "Database"),
        ["mongodb"] = ("MongoDB", "Database"),
        ["elasticsearch"] = ("Elasticsearch", "Database"),
        ["memcached"] = ("Memcached", "Database"),
        ["oracle"] = ("Oracle Database", "Database"),
        ["smtp"] = ("Mail server (SMTP)", "Mail"),
        ["submission"] = ("Mail submission (SMTP)", "Mail"),
        ["smtps"] = ("Mail server (SMTPS)", "Mail"),
        ["imap"] = ("Mailbox access (IMAP)", "Mail"),
        ["imaps"] = ("Mailbox access (IMAPS)", "Mail"),
        ["pop3"] = ("Mailbox access (POP3)", "Mail"),
        ["pop3s"] = ("Mailbox access (POP3S)", "Mail"),
        ["dns"] = ("DNS server", "Network service"),
        ["ntp"] = ("Time server (NTP)", "Network service"),
        ["snmp"] = ("SNMP management agent", "Network service"),
        ["ssdp"] = ("UPnP discovery (SSDP)", "Network service"),
        ["netbios-ns"] = ("NetBIOS name service", "Network service"),
        ["ldap"] = ("Directory service (LDAP)", "Directory"),
        ["ldaps"] = ("Directory service (LDAPS)", "Directory"),
        ["ldap-gc"] = ("Active Directory global catalog", "Directory"),
        ["kerberos"] = ("Kerberos sign-in (Active Directory)", "Directory"),
        ["adws"] = ("Active Directory Web Services", "Directory"),
        ["msrpc"] = ("Windows RPC", "Windows services"),
        ["http-rpc-epmap"] = ("Windows RPC over HTTP", "Windows services"),
        ["ipp"] = ("Printing (IPP)", "Printing"),
        ["jetdirect"] = ("Printing (JetDirect / raw)", "Printing"),
        ["printer"] = ("Printing (LPD)", "Printing"),
        ["rtsp"] = ("Video streaming (RTSP)", "Camera"),
        ["mqtt"] = ("MQTT broker", "Smart home / IoT"),
        ["docker"] = ("Docker API (unencrypted)", "Containers"),
        ["docker-tls"] = ("Docker API (TLS)", "Containers"),
        ["ipmi"] = ("Server management controller (IPMI)", "Server management (BMC)"),
        ["pptp"] = ("PPTP VPN", "VPN"),
        ["iphone-sync"] = ("Apple device sync", "Apple services"),
        ["http"] = ("Web server", "Web server"),
        ["https"] = ("Web server (HTTPS)", "Web server"),
        ["http-proxy"] = ("Web server / proxy", "Web server"),
        ["https-alt"] = ("Web server (HTTPS)", "Web server"),
    };

    public static (string Name, string Category)? Describe(string? serviceName)
        => serviceName != null && Names.TryGetValue(serviceName, out var d) ? d : null;
}
