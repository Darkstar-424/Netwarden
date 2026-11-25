using System.Text.RegularExpressions;

namespace NetWarden.Core.Fingerprinting;

public sealed record ProductVersion(string Product, string? Version);

/// <summary>Extracts product/version pairs from common banners and headers.</summary>
public static class BannerParser
{
    private static readonly (Regex Pattern, string Product)[] HttpServers =
    {
        (new Regex(@"Apache/(?<v>\d+\.\d+\.\d+)", RegexOptions.Compiled), "Apache httpd"),
        (new Regex(@"^Apache(?!/)", RegexOptions.Compiled), "Apache httpd"),
        (new Regex(@"nginx/(?<v>\d+\.\d+\.\d+)", RegexOptions.Compiled), "nginx"),
        (new Regex(@"^nginx$", RegexOptions.Compiled), "nginx"),
        (new Regex(@"Microsoft-IIS/(?<v>\d+\.\d+)", RegexOptions.Compiled), "Microsoft IIS"),
        (new Regex(@"lighttpd/(?<v>\d+\.\d+\.\d+)", RegexOptions.Compiled), "lighttpd"),
        (new Regex(@"Microsoft-HTTPAPI/(?<v>\d+\.\d+)", RegexOptions.Compiled), "Microsoft-HTTPAPI"),
        (new Regex(@"Jetty\((?<v>[\d.]+)", RegexOptions.Compiled), "Jetty"),
        (new Regex(@"Apache-Coyote/(?<v>[\d.]+)", RegexOptions.Compiled), "Apache Tomcat (Coyote)"),
        (new Regex(@"lighttpd", RegexOptions.Compiled), "lighttpd"),
        (new Regex(@"GoAhead-Webs", RegexOptions.Compiled), "GoAhead embedded web server"),
        (new Regex(@"mini_httpd/(?<v>[\d.]+)", RegexOptions.Compiled), "mini_httpd"),
        (new Regex(@"Boa/(?<v>[\d.]+)", RegexOptions.Compiled), "Boa"),
        (new Regex(@"cloudflare", RegexOptions.Compiled | RegexOptions.IgnoreCase), "Cloudflare"),
        (new Regex(@"Caddy", RegexOptions.Compiled), "Caddy"),
    };

    private static readonly Regex OpenSslInServer = new(@"OpenSSL/(?<v>\d+\.\d+\.\d+[a-z]?)", RegexOptions.Compiled);
    private static readonly Regex PhpInHeader = new(@"PHP/(?<v>\d+\.\d+\.\d+)", RegexOptions.Compiled);
    private static readonly Regex TomcatTitle = new(@"Apache Tomcat/(?<v>\d+\.\d+\.\d+)", RegexOptions.Compiled);

    public static ProductVersion? HttpServer(string? serverHeader)
    {
        if (string.IsNullOrWhiteSpace(serverHeader)) return null;
        foreach (var (pattern, product) in HttpServers)
        {
            var m = pattern.Match(serverHeader);
            if (m.Success)
                return new ProductVersion(product, m.Groups["v"].Success ? m.Groups["v"].Value : null);
        }
        return new ProductVersion(serverHeader.Split(' ')[0], null);
    }

    public static IEnumerable<ProductVersion> HttpComponents(string? serverHeader, string? poweredBy, string? body)
    {
        if (serverHeader != null)
        {
            var m = OpenSslInServer.Match(serverHeader);
            if (m.Success) yield return new ProductVersion("OpenSSL", m.Groups["v"].Value);
            var php = PhpInHeader.Match(serverHeader);
            if (php.Success) yield return new ProductVersion("PHP", php.Groups["v"].Value);
        }
        if (poweredBy != null)
        {
            var php = PhpInHeader.Match(poweredBy);
            if (php.Success) yield return new ProductVersion("PHP", php.Groups["v"].Value);
        }
        if (body != null)
        {
            var t = TomcatTitle.Match(body);
            if (t.Success) yield return new ProductVersion("Apache Tomcat", t.Groups["v"].Value);
        }
    }

    private static readonly Regex OpenSsh = new(@"^OpenSSH_(?<v>[\d.]+(?:p\d+)?)", RegexOptions.Compiled);
    private static readonly Regex Dropbear = new(@"^dropbear_(?<v>[\d.]+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static ProductVersion? Ssh(string software)
    {
        var m = OpenSsh.Match(software);
        if (m.Success) return new ProductVersion("OpenSSH", m.Groups["v"].Value);
        m = Dropbear.Match(software);
        if (m.Success) return new ProductVersion("Dropbear", m.Groups["v"].Value);
        if (software.StartsWith("Cisco", StringComparison.OrdinalIgnoreCase)) return new ProductVersion("Cisco SSH", null);
        if (software.Contains("RomSShell", StringComparison.OrdinalIgnoreCase)) return new ProductVersion("Allegro RomSShell", null);
        return new ProductVersion(software, null);
    }

    private static readonly (Regex, string)[] Ftp =
    {
        (new Regex(@"\(vsFTPd (?<v>[\d.]+)\)", RegexOptions.Compiled | RegexOptions.IgnoreCase), "vsftpd"),
        (new Regex(@"ProFTPD (?<v>\d+\.\d+\.\d+[a-z]?)", RegexOptions.Compiled), "ProFTPD"),
        (new Regex(@"Pure-FTPd", RegexOptions.Compiled), "Pure-FTPd"),
        (new Regex(@"FileZilla Server(?: version)? (?<v>[\d.]+)", RegexOptions.Compiled), "FileZilla Server"),
        (new Regex(@"Microsoft FTP Service", RegexOptions.Compiled), "Microsoft FTP Service"),
    };

    public static ProductVersion? FtpBanner(string banner) => MatchFirst(Ftp, banner);

    private static readonly (Regex, string)[] Smtp =
    {
        (new Regex(@"Exim (?<v>\d+\.\d+(?:\.\d+)?)", RegexOptions.Compiled), "Exim"),
        (new Regex(@"Postfix", RegexOptions.Compiled), "Postfix"),
        (new Regex(@"Microsoft ESMTP MAIL Service", RegexOptions.Compiled), "Microsoft Exchange/IIS SMTP"),
        (new Regex(@"Sendmail (?<v>[\d.]+)", RegexOptions.Compiled), "Sendmail"),
        (new Regex(@"hMailServer", RegexOptions.Compiled), "hMailServer"),
    };

    public static ProductVersion? SmtpBanner(string banner) => MatchFirst(Smtp, banner);

    private static ProductVersion? MatchFirst((Regex, string)[] patterns, string text)
    {
        foreach (var (pattern, product) in patterns)
        {
            var m = pattern.Match(text);
            if (m.Success) return new ProductVersion(product, m.Groups["v"].Success ? m.Groups["v"].Value : null);
        }
        return null;
    }

    private static readonly Regex HtmlTitle = new(@"<title[^>]*>(?<t>[^<]{0,200})</title>", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static string? Title(string? html)
    {
        if (string.IsNullOrEmpty(html)) return null;
        var m = HtmlTitle.Match(html);
        return m.Success ? System.Net.WebUtility.HtmlDecode(m.Groups["t"].Value).Trim() : null;
    }

    public static ProductVersion? MySql(string versionString)
    {
        if (versionString.Contains("MariaDB", StringComparison.OrdinalIgnoreCase))
        {
            var m = Regex.Match(versionString, @"(\d+\.\d+\.\d+)-MariaDB");
            if (!m.Success) m = Regex.Match(versionString, @"^(\d+\.\d+\.\d+)");
            return new ProductVersion("MariaDB", m.Success ? m.Groups[1].Value : null);
        }
        var v = Regex.Match(versionString, @"^(\d+\.\d+\.\d+)");
        return new ProductVersion("MySQL", v.Success ? v.Groups[1].Value : null);
    }
}
