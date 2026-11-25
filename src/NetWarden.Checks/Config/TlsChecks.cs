using NetWarden.Core.Checks;
using NetWarden.Core.Models;

namespace NetWarden.Checks.Config;

internal static class TlsRemediation
{
    public static readonly string[] Generic =
    {
        "Windows/IIS/RDP: disable old protocols and ciphers under HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL, or use IIS Crypto / a hardening GPO, then restart.",
        "Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3 and SSLCipherSuite with modern AEAD suites.",
        "nginx: ssl_protocols TLSv1.2 TLSv1.3; ssl_ciphers with ECDHE+AESGCM/CHACHA20 suites.",
        "Appliances and printers: set the minimum TLS version in the device's web admin, and update its firmware if the option is missing."
    };
}

public sealed class LegacyTlsCheck : CheckBase
{
    public override string Id => "tls.legacy-protocol";
    public override string Name => "Outdated SSL/TLS versions";
    public override string Category => "TLS";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Port?.Tls?.Protocols.Any(p => p is "SSLv2" or "SSLv3" or "TLS 1.0" or "TLS 1.1") == true;

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var protos = ctx.Port!.Tls!.Protocols;
        var results = new List<Finding>();
        var ssl = protos.Where(p => p is "SSLv2" or "SSLv3").ToList();
        if (ssl.Count > 0)
        {
            var f = ctx.NewFinding(this, $"{string.Join(" and ", ssl)} enabled", Severity.High, Confidence.Confirmed, "ssl");
            f.Description = "SSL 2.0 and 3.0 are broken (DROWN, POODLE). Anyone able to watch the traffic may be able to decrypt it.";
            f.Evidence = $"Server completed a ServerHello for: {string.Join(", ", ssl)}.";
            f.Cves.AddRange(ssl.Contains("SSLv3") ? new[] { "CVE-2014-3566" } : Array.Empty<string>());
            if (ssl.Contains("SSLv2")) f.Cves.Add("CVE-2016-0800");
            f.Cvss = 7.4;
            Fill(f);
            results.Add(f);
        }
        var old = protos.Where(p => p is "TLS 1.0" or "TLS 1.1").ToList();
        if (old.Count > 0)
        {
            var f = ctx.NewFinding(this, $"{string.Join(" and ", old)} enabled", Severity.Medium, Confidence.Confirmed, "tls1x");
            f.Description = "TLS 1.0 and 1.1 were formally retired in 2021 (RFC 8996). They rely on weak hashing and are no longer accepted by modern browsers.";
            f.Evidence = $"Server accepted ClientHello for: {string.Join(", ", old)}. Supported overall: {string.Join(", ", protos)}.";
            f.Cvss = 5.3;
            Fill(f);
            results.Add(f);
        }
        return Task.FromResult<IReadOnlyList<Finding>>(results);
    }

    private static void Fill(Finding f)
    {
        f.FixAction = "Turn off old SSL/TLS versions";
        f.Remediation.Add("Allow only TLS 1.2 and TLS 1.3.");
        f.Remediation.AddRange(TlsRemediation.Generic);
        f.Remediation.Add("Rescan to confirm.");
        f.References.Add("https://www.rfc-editor.org/rfc/rfc8996");
    }
}

public sealed class WeakCipherCheck : CheckBase
{
    public override string Id => "tls.weak-cipher";
    public override string Name => "Weak TLS cipher suites";
    public override string Category => "TLS";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Port?.Tls?.Ciphers.Any(c => c.Weak) == true;

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var weak = ctx.Port!.Tls!.Ciphers.Where(c => c.Weak).ToList();
        var broken = weak.Any(c => c.Name.Contains("NULL") || c.Name.Contains("EXPORT") || c.Name.Contains("_anon_"));
        var f = ctx.NewFinding(this, broken ? "Broken TLS cipher suites accepted (NULL/EXPORT/anonymous)" : "Weak TLS cipher suites accepted (RC4/3DES/DES)",
            broken ? Severity.High : Severity.Medium, Confidence.Confirmed);
        f.Description = broken
            ? "The server accepts cipher suites that provide no encryption, export-grade (40-bit) keys or no server authentication."
            : "The server accepts outdated ciphers. RC4 has known biases and 3DES is vulnerable to the SWEET32 birthday attack.";
        f.Evidence = "Accepted: " + string.Join(", ", weak.Select(c => $"{c.Name} ({c.Protocol})"));
        if (weak.Any(c => c.Name.Contains("3DES"))) f.Cves.Add("CVE-2016-2183");
        if (weak.Any(c => c.Name.Contains("RC4"))) f.Cves.Add("CVE-2015-2808");
        if (weak.Any(c => c.Name.Contains("EXPORT"))) f.Cves.Add("CVE-2015-0204");
        f.Cvss = broken ? 7.4 : 5.9;
        f.FixAction = "Remove weak TLS ciphers";
        f.Remediation.Add("Allow only AEAD suites with forward secrecy (ECDHE with AES-GCM or ChaCha20-Poly1305).");
        f.Remediation.AddRange(TlsRemediation.Generic);
        f.References.Add("https://ssl-config.mozilla.org/");
        return One(f);
    }
}

public sealed class NoForwardSecrecyCheck : CheckBase
{
    public override string Id => "tls.no-forward-secrecy";
    public override string Name => "No forward secrecy";
    public override string Category => "TLS";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Port?.Tls is { Ciphers.Count: > 0 } tls && tls.Ciphers.All(c => !c.ForwardSecret);

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var f = ctx.NewFinding(this, "TLS without forward secrecy", Severity.Low, Confidence.Confirmed);
        f.Description = "None of the accepted cipher suites use ephemeral key exchange. If the server's private key is ever stolen, recorded past traffic can be decrypted.";
        f.Evidence = "Accepted: " + string.Join(", ", ctx.Port!.Tls!.Ciphers.Select(c => c.Name).Distinct());
        f.FixAction = "Enable ECDHE cipher suites";
        f.Remediation.Add("Enable ECDHE_RSA/ECDHE_ECDSA suites and prefer them over plain RSA key exchange.");
        f.Remediation.AddRange(TlsRemediation.Generic);
        return One(f);
    }
}

public sealed class WeakDhCheck : CheckBase
{
    public override string Id => "tls.weak-dh";
    public override string Name => "Weak Diffie-Hellman parameters";
    public override string Category => "TLS";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Port?.Tls?.DhPrimeBits is int bits && bits < 2048;

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var bits = ctx.Port!.Tls!.DhPrimeBits!.Value;
        var f = ctx.NewFinding(this, $"Weak Diffie-Hellman group ({bits}-bit)", bits <= 1024 ? Severity.Medium : Severity.Low, Confidence.Confirmed);
        f.Description = "The server uses a small Diffie-Hellman prime for DHE key exchange. Groups of 1024 bits or less are within reach of well-funded attackers (Logjam).";
        f.Evidence = $"ServerKeyExchange DH prime length: {bits} bits.";
        if (bits <= 1024) f.Cves.Add("CVE-2015-4000");
        f.FixAction = "Use 2048-bit or larger DH groups (or ECDHE only)";
        f.Remediation.Add("Generate 2048-bit+ DH parameters (openssl dhparam 2048) or disable DHE suites in favour of ECDHE.");
        f.Remediation.Add("Windows: set ServerMinKeyBitLength = 2048 under SCHANNEL\\KeyExchangeAlgorithms\\Diffie-Hellman.");
        f.References.Add("https://weakdh.org/");
        return One(f);
    }
}

public sealed class CertificateExpiryCheck : CheckBase
{
    public override string Id => "tls.cert-expiry";
    public override string Name => "Expired or expiring certificate";
    public override string Category => "TLS";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Port?.Tls?.Certificate != null;

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var cert = ctx.Port!.Tls!.Certificate!;
        var days = (cert.NotAfter - ctx.Now).TotalDays;
        if (days > 30 && cert.NotBefore <= ctx.Now) return None();
        Finding f;
        if (cert.NotBefore > ctx.Now)
        {
            f = ctx.NewFinding(this, "Certificate not yet valid", Severity.Medium, Confidence.Configuration, "notyet");
            f.Description = "The certificate's start date is in the future, so clients reject it. The device clock may be wrong.";
        }
        else if (days < 0)
        {
            f = ctx.NewFinding(this, $"Expired TLS certificate ({(int)-days} days ago)", Severity.Medium, Confidence.Configuration, "expired");
            f.Description = "The certificate has expired. Browsers show warnings, and users who learn to click through warnings won't notice a real attack.";
        }
        else
        {
            f = ctx.NewFinding(this, $"TLS certificate expires in {(int)days} days", Severity.Low, Confidence.Configuration, "expiring");
            f.Description = "The certificate expires soon. Renew it before services break.";
        }
        f.Evidence = $"Subject: {cert.Subject}\nIssuer: {cert.Issuer}\nValid: {cert.NotBefore:yyyy-MM-dd} to {cert.NotAfter:yyyy-MM-dd}";
        f.FixAction = "Renew the certificate";
        f.Remediation.AddRange(new[]
        {
            "Issue a new certificate (internal CA, or a public CA such as Let's Encrypt for internet-facing sites).",
            "Install it on the service and restart it.",
            "Automate renewal (ACME/certbot, AD CS auto-enrolment) and add expiry monitoring."
        });
        return One(f);
    }
}

public sealed class UntrustedCertificateCheck : CheckBase
{
    public override string Id => "tls.cert-untrusted";
    public override string Name => "Self-signed or untrusted certificate";
    public override string Category => "TLS";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Port?.Tls?.Certificate is { } c && (c.SelfSigned || !c.ChainTrusted);

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var cert = ctx.Port!.Tls!.Certificate!;
        var f = ctx.NewFinding(this, cert.SelfSigned ? "Self-signed TLS certificate" : "TLS certificate not trusted by this PC", Severity.Low, Confidence.Configuration);
        f.Description = "Clients can't verify who they're talking to, so a man-in-the-middle could impersonate the service. " +
                        "Common (and often acceptable) on printers and appliances, but better replaced with a certificate from your internal CA.";
        f.Evidence = $"Subject: {cert.Subject}\nIssuer: {cert.Issuer}\nTrusted chain on scanning PC: {(cert.ChainTrusted ? "yes" : "no")}";
        f.FixAction = "Replace with a trusted certificate";
        f.Remediation.Add("Issue a certificate from your internal CA (e.g. AD Certificate Services) or a public CA and install it on the service.");
        f.Remediation.Add("If the device can't take a custom certificate, accept the risk and document it here.");
        return One(f);
    }
}

public sealed class WeakCertificateKeyCheck : CheckBase
{
    public override string Id => "tls.cert-weak";
    public override string Name => "Weak certificate key or signature";
    public override string Category => "TLS";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Port?.Tls?.Certificate is { } c &&
        ((c.KeyAlgorithm == "RSA" && c.KeySize is > 0 and < 2048) ||
         c.SignatureAlgorithm.Contains("md5", StringComparison.OrdinalIgnoreCase) ||
         (c.SignatureAlgorithm.StartsWith("sha1", StringComparison.OrdinalIgnoreCase) && !c.SelfSigned));

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var cert = ctx.Port!.Tls!.Certificate!;
        var f = ctx.NewFinding(this, "Weak certificate key or signature", Severity.Medium, Confidence.Configuration);
        f.Description = "The certificate uses a short RSA key or an obsolete signature hash (MD5/SHA-1), which can allow forged certificates.";
        f.Evidence = $"Key: {cert.KeyAlgorithm} {cert.KeySize} bits; signature: {cert.SignatureAlgorithm}";
        f.FixAction = "Re-issue the certificate with a strong key";
        f.Remediation.Add("Re-issue with RSA 2048+ (or ECDSA P-256) and a SHA-256 signature.");
        return One(f);
    }
}
