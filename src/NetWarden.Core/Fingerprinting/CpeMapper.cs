using System.Text.RegularExpressions;

namespace NetWarden.Core.Fingerprinting;

/// <summary>Turns detected product names and versions into CPE 2.3 names used by the NVD.</summary>
public static class CpeMapper
{
    private static readonly Regex VersionWithSuffix = new(@"^(?<v>\d+(?:\.\d+)*)(?<u>[a-z]+\d*)?$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static string Escape(string s) => s.Replace(":", "\\:").ToLowerInvariant();

    public static string Build(string vendor, string product, string version, string update = "*")
        => $"cpe:2.3:a:{vendor}:{product}:{Escape(version)}:{Escape(string.IsNullOrEmpty(update) ? "*" : update)}:*:*:*:*:*:*";

    /// <summary>Splits "8.2p1" into ("8.2", "p1"), "1.3.5a" into ("1.3.5", "a").</summary>
    public static (string Version, string Update) SplitUpdate(string version)
    {
        var m = VersionWithSuffix.Match(version.Trim());
        if (!m.Success) return (version.Trim(), "*");
        return (m.Groups["v"].Value, m.Groups["u"].Success && m.Groups["u"].Value.Length > 0 ? m.Groups["u"].Value.ToLowerInvariant() : "*");
    }

    /// <summary>Returns candidate CPEs for a product name as reported by a banner.</summary>
    public static IReadOnlyList<string> Map(string? product, string? version)
    {
        if (string.IsNullOrWhiteSpace(product) || string.IsNullOrWhiteSpace(version)) return Array.Empty<string>();
        var p = product.Trim().ToLowerInvariant();
        var v = version.Trim();
        if (!char.IsDigit(v[0])) return Array.Empty<string>();
        var list = new List<string>();
        switch (p)
        {
            case "openssh":
            {
                var (ver, upd) = SplitUpdate(v);
                list.Add(Build("openbsd", "openssh", ver, upd));
                break;
            }
            case "dropbear":
            case "dropbear ssh":
                list.Add(Build("dropbear_ssh_project", "dropbear_ssh", v));
                break;
            case "apache httpd":
            case "apache":
                list.Add(Build("apache", "http_server", v));
                break;
            case "nginx":
                list.Add(Build("f5", "nginx", v));
                list.Add(Build("nginx", "nginx", v));
                break;
            case "microsoft iis":
            case "microsoft-iis":
                list.Add(Build("microsoft", "internet_information_services", v));
                break;
            case "lighttpd":
                list.Add(Build("lighttpd", "lighttpd", v));
                break;
            case "apache tomcat":
                list.Add(Build("apache", "tomcat", v));
                break;
            case "openssl":
                list.Add(Build("openssl", "openssl", v));
                break;
            case "php":
                list.Add(Build("php", "php", v));
                break;
            case "vsftpd":
                list.Add(Build("beasts", "vsftpd", v));
                break;
            case "proftpd":
            {
                var (ver, upd) = SplitUpdate(v);
                list.Add(Build("proftpd", "proftpd", ver, upd));
                break;
            }
            case "pure-ftpd":
                list.Add(Build("pureftpd", "pure-ftpd", v));
                break;
            case "filezilla server":
                list.Add(Build("filezilla-project", "filezilla_server", v));
                break;
            case "exim":
                list.Add(Build("exim", "exim", v));
                break;
            case "postfix":
                list.Add(Build("postfix", "postfix", v));
                break;
            case "mysql":
                list.Add(Build("oracle", "mysql", v));
                break;
            case "mariadb":
                list.Add(Build("mariadb", "mariadb", v));
                break;
            case "redis":
                list.Add(Build("redis", "redis", v));
                break;
            case "elasticsearch":
                list.Add(Build("elastic", "elasticsearch", v));
                break;
            case "samba":
                list.Add(Build("samba", "samba", v));
                break;
            case "microsoft-httpapi":
                break;
        }
        return list;
    }

    /// <summary>Converts a CPE 2.2 URI (as found in Nmap XML, e.g. cpe:/a:openbsd:openssh:8.2p1) to CPE 2.3.</summary>
    public static string? FromCpe22(string uri)
    {
        if (!uri.StartsWith("cpe:/", StringComparison.OrdinalIgnoreCase)) return uri.StartsWith("cpe:2.3:", StringComparison.OrdinalIgnoreCase) ? uri : null;
        var parts = uri[5..].Split(':');
        if (parts.Length < 3) return null;
        var part = parts[0];
        var vendor = parts[1];
        var product = parts[2];
        var version = parts.Length > 3 && parts[3].Length > 0 ? parts[3] : "*";
        var update = parts.Length > 4 && parts[4].Length > 0 ? parts[4] : "*";
        if (update == "*" && vendor == "openbsd" && product == "openssh" && version != "*")
        {
            var (v, u) = SplitUpdate(version);
            version = v;
            update = u;
        }
        return $"cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:*:*:*:*:*:*".ToLowerInvariant();
    }

    public sealed record CpeParts(string Part, string Vendor, string Product, string Version, string Update);

    public static CpeParts? Parse(string cpe23)
    {
        var parts = SplitCpe(cpe23);
        if (parts.Count < 7 || parts[0] != "cpe" || parts[1] != "2.3") return null;
        return new CpeParts(parts[2], parts[3], parts[4], Unescape(parts[5]), Unescape(parts[6]));
    }

    private static string Unescape(string s) => s.Replace("\\", "");

    private static List<string> SplitCpe(string cpe)
    {
        var result = new List<string>();
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < cpe.Length; i++)
        {
            var c = cpe[i];
            if (c == '\\' && i + 1 < cpe.Length) { sb.Append(c).Append(cpe[++i]); continue; }
            if (c == ':') { result.Add(sb.ToString()); sb.Clear(); continue; }
            sb.Append(c);
        }
        result.Add(sb.ToString());
        return result;
    }
}
