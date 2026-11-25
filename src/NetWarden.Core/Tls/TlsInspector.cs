using System.Security.Cryptography.X509Certificates;
using NetWarden.Core.Models;
using NetWarden.Core.Util;

namespace NetWarden.Core.Tls;

/// <summary>
/// Works out which TLS/SSL versions and cipher suites a server accepts by sending ClientHello messages
/// and reading the server's reply. The handshake is abandoned straight after the ServerHello.
/// </summary>
public sealed class TlsInspector
{
    private readonly IProbeClient _probe;
    private readonly INwLog _log;
    public int MaxCipherRounds { get; init; } = 30;

    public TlsInspector(IProbeClient probe, INwLog? log = null)
    {
        _probe = probe;
        _log = log ?? NullLog.Instance;
    }

    /// <summary>Quick check: does this port speak TLS at all?</summary>
    public async Task<bool> SpeaksTlsAsync(string host, int port, TimeSpan timeout, CancellationToken ct)
    {
        foreach (var v in new[] { TlsVersions.Tls12, TlsVersions.Tls13, TlsVersions.Tls10 })
        {
            var hs = await HelloAsync(host, port, v, v == TlsVersions.Tls13 ? CipherSuites.Tls13.Select(c => c.Id) : CipherSuites.Tls12AndBelow.Select(c => c.Id), null, timeout, ct).ConfigureAwait(false);
            if (hs == null) return false;
            if (hs.GotServerHello || hs.GotAlert) return true;
        }
        return false;
    }

    public async Task<TlsInfo?> InspectAsync(string host, int port, string? sniHost, TimeSpan timeout, CancellationToken ct)
    {
        var info = new TlsInfo();
        var certs = new List<byte[]>();
        var preferred = new Dictionary<ushort, ushort>();

        // SSLv2
        try
        {
            await using var s2 = await _probe.ConnectAsync(host, port, timeout, ct).ConfigureAwait(false);
            if (s2 != null)
            {
                await s2.SendAsync(TlsPackets.Sslv2ClientHello(), ct).ConfigureAwait(false);
                var resp = await s2.ReceiveAsync(4096, timeout, ct).ConfigureAwait(false);
                if (TlsPackets.IsSslv2ServerHello(resp)) info.Protocols.Add("SSLv2");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Debug($"SSLv2 probe {host}:{port}: {ex.Message}");
        }

        foreach (var version in new[] { TlsVersions.Ssl3, TlsVersions.Tls10, TlsVersions.Tls11, TlsVersions.Tls12 })
        {
            var hs = await HelloAsync(host, port, version, CipherSuites.Tls12AndBelow.Select(c => c.Id), sniHost, timeout, ct).ConfigureAwait(false);
            if (hs is { GotServerHello: true } && hs.NegotiatedVersion == version)
            {
                info.Protocols.Add(TlsVersions.Name(version));
                preferred[version] = hs.Cipher;
                if (certs.Count == 0 && hs.Certificates.Count > 0) certs.AddRange(hs.Certificates);
                if (hs.DhPrimeBits is int bits) info.DhPrimeBits = info.DhPrimeBits is int prev ? Math.Min(prev, bits) : bits;
            }
        }

        var hs13 = await HelloAsync(host, port, TlsVersions.Tls13, CipherSuites.Tls13.Select(c => c.Id), sniHost, timeout, ct).ConfigureAwait(false);
        if (hs13 is { GotServerHello: true } && hs13.NegotiatedVersion == TlsVersions.Tls13)
        {
            info.Protocols.Add("TLS 1.3");
            AddCipher(info, hs13.Cipher, "TLS 1.3");
        }

        if (info.Protocols.Count == 0) return null;

        // Enumerate cipher suites on the newest pre-1.3 version the server accepts.
        var enumVersion = preferred.Keys.OrderByDescending(v => v).FirstOrDefault();
        if (enumVersion != 0)
        {
            var remaining = CipherSuites.Tls12AndBelow.Select(c => c.Id).ToList();
            for (int round = 0; round < MaxCipherRounds && remaining.Count > 0; round++)
            {
                var hs = await HelloAsync(host, port, enumVersion, remaining, sniHost, timeout, ct).ConfigureAwait(false);
                if (hs is not { GotServerHello: true } || !remaining.Contains(hs.Cipher)) break;
                AddCipher(info, hs.Cipher, TlsVersions.Name(enumVersion));
                if (hs.DhPrimeBits is int bits) info.DhPrimeBits = info.DhPrimeBits is int prev ? Math.Min(prev, bits) : bits;
                if (certs.Count == 0 && hs.Certificates.Count > 0) certs.AddRange(hs.Certificates);
                remaining.Remove(hs.Cipher);
            }
            // Older versions: record what they choose by preference.
            foreach (var (v, c) in preferred.Where(kv => kv.Key != enumVersion))
                AddCipher(info, c, TlsVersions.Name(v));
        }

        info.Certificate = certs.Count > 0
            ? CertificateInspector.Describe(certs[0], certs.Skip(1))
            : await FetchCertificateAsync(host, port, sniHost, timeout, ct).ConfigureAwait(false);
        return info;
    }

    private async Task<CertificateInfo?> FetchCertificateAsync(string host, int port, string? sni, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            var cert = await _probe.GetCertificateAsync(host, port, sni, timeout, ct).ConfigureAwait(false);
            return cert == null ? null : CertificateInspector.Describe(cert, Array.Empty<X509Certificate2>());
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Debug($"Certificate fetch {host}:{port}: {ex.Message}");
            return null;
        }
    }

    private static void AddCipher(TlsInfo info, ushort id, string protocol)
    {
        if (info.Ciphers.Any(c => c.Id == id && c.Protocol == protocol)) return;
        var suite = CipherSuites.Lookup(id);
        info.Ciphers.Add(new CipherInfo { Id = id, Name = suite.Name, Protocol = protocol, Weak = suite.Weak, ForwardSecret = suite.ForwardSecret });
    }

    private async Task<TlsPackets.ServerHandshake?> HelloAsync(string host, int port, ushort version, IEnumerable<ushort> ciphers, string? sni, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            await using var session = await _probe.ConnectAsync(host, port, timeout, ct).ConfigureAwait(false);
            if (session == null) return null;
            await session.SendAsync(TlsPackets.ClientHello(version, ciphers, sni ?? host), ct).ConfigureAwait(false);
            var data = await TlsPackets.ReadHandshakeAsync(session, timeout, ct).ConfigureAwait(false);
            return TlsPackets.Parse(data);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Debug($"TLS hello {TlsVersions.Name(version)} {host}:{port}: {ex.Message}");
            return new TlsPackets.ServerHandshake();
        }
    }
}

public static class CertificateInspector
{
    public static CertificateInfo? Describe(byte[] der, IEnumerable<byte[]> intermediates)
    {
        try
        {
#pragma warning disable SYSLIB0057
            var cert = new X509Certificate2(der);
            var extra = intermediates.Select(b => new X509Certificate2(b)).ToList();
#pragma warning restore SYSLIB0057
            return Describe(cert, extra);
        }
        catch (Exception)
        {
            return null;
        }
    }

    public static CertificateInfo Describe(X509Certificate2 cert, IEnumerable<X509Certificate2> intermediates)
    {
        var info = new CertificateInfo
        {
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            NotBefore = new DateTimeOffset(cert.NotBefore.ToUniversalTime(), TimeSpan.Zero),
            NotAfter = new DateTimeOffset(cert.NotAfter.ToUniversalTime(), TimeSpan.Zero),
            SelfSigned = string.Equals(cert.Subject, cert.Issuer, StringComparison.Ordinal),
            SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "",
            Thumbprint = cert.Thumbprint
        };
        try
        {
            using var rsa = cert.GetRSAPublicKey();
            if (rsa != null) { info.KeyAlgorithm = "RSA"; info.KeySize = rsa.KeySize; }
            else
            {
                using var ec = cert.GetECDsaPublicKey();
                if (ec != null) { info.KeyAlgorithm = "ECDSA"; info.KeySize = ec.KeySize; }
                else info.KeyAlgorithm = cert.PublicKey.Oid.FriendlyName ?? "unknown";
            }
        }
        catch (Exception)
        {
            info.KeyAlgorithm = cert.PublicKey.Oid.FriendlyName ?? "unknown";
        }
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509SubjectAlternativeNameExtension san)
            {
                info.SubjectAltNames.AddRange(san.EnumerateDnsNames());
                info.SubjectAltNames.AddRange(san.EnumerateIPAddresses().Select(a => a.ToString()));
            }
        }
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
            foreach (var i in intermediates) chain.ChainPolicy.ExtraStore.Add(i);
            info.ChainTrusted = chain.Build(cert);
        }
        catch (Exception)
        {
            info.ChainTrusted = false;
        }
        return info;
    }
}
