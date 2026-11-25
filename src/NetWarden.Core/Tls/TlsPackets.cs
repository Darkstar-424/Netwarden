using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using NetWarden.Core.Util;

namespace NetWarden.Core.Tls;

public static class TlsVersions
{
    public const ushort Ssl3 = 0x0300;
    public const ushort Tls10 = 0x0301;
    public const ushort Tls11 = 0x0302;
    public const ushort Tls12 = 0x0303;
    public const ushort Tls13 = 0x0304;

    public static string Name(ushort v) => v switch
    {
        0x0002 => "SSLv2",
        Ssl3 => "SSLv3",
        Tls10 => "TLS 1.0",
        Tls11 => "TLS 1.1",
        Tls12 => "TLS 1.2",
        Tls13 => "TLS 1.3",
        _ => $"0x{v:X4}"
    };
}

public sealed record CipherSuite(ushort Id, string Name)
{
    public bool IsTls13 => Id is >= 0x1301 and <= 0x1305;
    public bool ForwardSecret => IsTls13 || Name.Contains("_ECDHE_", StringComparison.Ordinal) || Name.Contains("_DHE_", StringComparison.Ordinal);
    public bool UsesDhe => Name.Contains("_DHE_", StringComparison.Ordinal);
    public bool Weak =>
        Name.Contains("NULL", StringComparison.Ordinal) || Name.Contains("EXPORT", StringComparison.Ordinal) ||
        Name.Contains("RC4", StringComparison.Ordinal) || Name.Contains("_DES", StringComparison.Ordinal) ||
        Name.Contains("3DES", StringComparison.Ordinal) || Name.Contains("_anon_", StringComparison.Ordinal) ||
        Name.Contains("RC2", StringComparison.Ordinal) || Name.EndsWith("_MD5", StringComparison.Ordinal);
    public bool Broken =>
        Name.Contains("NULL", StringComparison.Ordinal) || Name.Contains("EXPORT", StringComparison.Ordinal) ||
        Name.Contains("_anon_", StringComparison.Ordinal);
}

public static class CipherSuites
{
    public static readonly IReadOnlyList<CipherSuite> Tls12AndBelow = new List<CipherSuite>
    {
        new(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        new(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
        new(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
        new(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
        new(0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
        new(0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
        new(0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
        new(0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
        new(0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
        new(0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
        new(0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"),
        new(0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"),
        new(0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"),
        new(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
        new(0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
        new(0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
        new(0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
        new(0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"),
        new(0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"),
        new(0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
        new(0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"),
        new(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256"),
        new(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384"),
        new(0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256"),
        new(0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256"),
        new(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"),
        new(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"),
        new(0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"),
        new(0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"),
        new(0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
        new(0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"),
        new(0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
        new(0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
        new(0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"),
        new(0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"),
        new(0x0005, "TLS_RSA_WITH_RC4_128_SHA"),
        new(0x0004, "TLS_RSA_WITH_RC4_128_MD5"),
        new(0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA"),
        new(0x0009, "TLS_RSA_WITH_DES_CBC_SHA"),
        new(0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"),
        new(0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"),
        new(0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"),
        new(0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"),
        new(0x0018, "TLS_DH_anon_WITH_RC4_128_MD5"),
        new(0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA"),
        new(0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA"),
        new(0x003B, "TLS_RSA_WITH_NULL_SHA256"),
        new(0x0002, "TLS_RSA_WITH_NULL_SHA"),
        new(0x0001, "TLS_RSA_WITH_NULL_MD5"),
    };

    public static readonly IReadOnlyList<CipherSuite> Tls13 = new List<CipherSuite>
    {
        new(0x1301, "TLS_AES_128_GCM_SHA256"),
        new(0x1302, "TLS_AES_256_GCM_SHA384"),
        new(0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
    };

    private static readonly Dictionary<ushort, CipherSuite> ById =
        Tls12AndBelow.Concat(Tls13).ToDictionary(c => c.Id);

    public static CipherSuite Lookup(ushort id)
        => ById.TryGetValue(id, out var c) ? c : new CipherSuite(id, $"UNKNOWN_0x{id:X4}");
}

/// <summary>Builds ClientHello messages and parses the server's plaintext handshake. No key exchange is ever completed.</summary>
public static class TlsPackets
{
    public static byte[] ClientHello(ushort version, IEnumerable<ushort> ciphers, string? sniHost)
    {
        var cipherList = ciphers.ToList();
        bool tls13 = version == TlsVersions.Tls13;
        var body = new PacketWriter();
        body.U16BE(tls13 ? TlsVersions.Tls12 : version);
        body.Bytes(RandomNumberGenerator.GetBytes(32));
        if (tls13) body.U8(32).Bytes(RandomNumberGenerator.GetBytes(32)); else body.U8(0);
        body.U16BE((ushort)(cipherList.Count * 2));
        foreach (var c in cipherList) body.U16BE(c);
        body.U8(1).U8(0); // compression: null

        var ext = new PacketWriter();
        if (!string.IsNullOrEmpty(sniHost) && !System.Net.IPAddress.TryParse(sniHost, out _))
        {
            var host = Encoding.ASCII.GetBytes(sniHost);
            ext.U16BE(0x0000).U16BE((ushort)(host.Length + 5)).U16BE((ushort)(host.Length + 3)).U8(0).U16BE((ushort)host.Length).Bytes(host);
        }
        if (version != TlsVersions.Ssl3)
        {
            // supported_groups: x25519, secp256r1, secp384r1, secp521r1, ffdhe2048
            ushort[] groups = { 0x001D, 0x0017, 0x0018, 0x0019, 0x0100 };
            ext.U16BE(0x000A).U16BE((ushort)(groups.Length * 2 + 2)).U16BE((ushort)(groups.Length * 2));
            foreach (var g in groups) ext.U16BE(g);
            // ec_point_formats: uncompressed
            ext.U16BE(0x000B).U16BE(2).U8(1).U8(0);
            // signature_algorithms
            ushort[] sigs = { 0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201 };
            ext.U16BE(0x000D).U16BE((ushort)(sigs.Length * 2 + 2)).U16BE((ushort)(sigs.Length * 2));
            foreach (var s in sigs) ext.U16BE(s);
            // renegotiation_info (empty)
            ext.U16BE(0xFF01).U16BE(1).U8(0);
        }
        if (tls13)
        {
            // supported_versions: TLS 1.3 only
            ext.U16BE(0x002B).U16BE(3).U8(2).U16BE(TlsVersions.Tls13);
            // key_share: x25519 with a random 32-byte value (we never finish the handshake)
            var key = RandomNumberGenerator.GetBytes(32);
            ext.U16BE(0x0033).U16BE(38).U16BE(36).U16BE(0x001D).U16BE(32).Bytes(key);
            // psk_key_exchange_modes: psk_dhe_ke
            ext.U16BE(0x002D).U16BE(2).U8(1).U8(1);
        }
        var extBytes = ext.ToArray();
        if (extBytes.Length > 0) body.U16BE((ushort)extBytes.Length).Bytes(extBytes);

        var bodyBytes = body.ToArray();
        var handshake = new PacketWriter().U8(0x01).U24BE(bodyBytes.Length).Bytes(bodyBytes).ToArray();
        var recordVersion = version == TlsVersions.Ssl3 ? TlsVersions.Ssl3 : TlsVersions.Tls10;
        return new PacketWriter().U8(0x16).U16BE(recordVersion).U16BE((ushort)handshake.Length).Bytes(handshake).ToArray();
    }

    /// <summary>SSLv2 CLIENT-HELLO offering the classic SSLv2 cipher kinds.</summary>
    public static byte[] Sslv2ClientHello()
    {
        byte[] specs =
        {
            0x01, 0x00, 0x80, 0x02, 0x00, 0x80, 0x03, 0x00, 0x80, 0x04, 0x00, 0x80,
            0x05, 0x00, 0x80, 0x06, 0x00, 0x40, 0x07, 0x00, 0xC0
        };
        var challenge = RandomNumberGenerator.GetBytes(16);
        var msg = new PacketWriter()
            .U8(0x01).U16BE(0x0002).U16BE((ushort)specs.Length).U16BE(0).U16BE((ushort)challenge.Length)
            .Bytes(specs).Bytes(challenge).ToArray();
        return new PacketWriter().U8((byte)(0x80 | (msg.Length >> 8))).U8((byte)msg.Length).Bytes(msg).ToArray();
    }

    public static bool IsSslv2ServerHello(ReadOnlySpan<byte> data)
        => data.Length >= 3 && (data[0] & 0x80) != 0 && data[2] == 0x04;

    public sealed class ServerHandshake
    {
        public bool GotServerHello { get; set; }
        public bool GotAlert { get; set; }
        public byte AlertDescription { get; set; }
        public ushort NegotiatedVersion { get; set; }
        public ushort Cipher { get; set; }
        public List<byte[]> Certificates { get; } = new();
        public int? DhPrimeBits { get; set; }
        public bool Complete { get; set; }
    }

    /// <summary>
    /// Parses whatever plaintext handshake records were received. Returns true when enough was read
    /// (ServerHelloDone, a TLS 1.3 ServerHello, or an alert).
    /// </summary>
    public static ServerHandshake Parse(ReadOnlySpan<byte> data)
    {
        var result = new ServerHandshake();
        var handshakeBytes = new MemoryStream();
        int pos = 0;
        while (pos + 5 <= data.Length)
        {
            var type = data[pos];
            var len = BinaryPrimitives.ReadUInt16BigEndian(data[(pos + 3)..]);
            if (pos + 5 + len > data.Length) break;
            var frag = data.Slice(pos + 5, len);
            if (type == 0x15)
            {
                result.GotAlert = true;
                if (frag.Length >= 2) result.AlertDescription = frag[1];
                result.Complete = true;
                break;
            }
            if (type == 0x16) handshakeBytes.Write(frag);
            else if (type == 0x14 || type == 0x17) { result.Complete = result.GotServerHello; break; }
            pos += 5 + len;
        }

        var hs = handshakeBytes.ToArray().AsSpan();
        int p = 0;
        while (p + 4 <= hs.Length)
        {
            var msgType = hs[p];
            var msgLen = (hs[p + 1] << 16) | (hs[p + 2] << 8) | hs[p + 3];
            if (p + 4 + msgLen > hs.Length) break;
            var msg = hs.Slice(p + 4, msgLen);
            switch (msgType)
            {
                case 0x02:
                    ParseServerHello(msg, result);
                    if (result.NegotiatedVersion == TlsVersions.Tls13) result.Complete = true;
                    break;
                case 0x0B:
                    ParseCertificates(msg, result);
                    break;
                case 0x0C:
                    if (CipherSuites.Lookup(result.Cipher).UsesDhe && msg.Length >= 2)
                    {
                        var pLen = BinaryPrimitives.ReadUInt16BigEndian(msg);
                        var bits = pLen * 8;
                        if (pLen > 0 && msg.Length >= 2 + pLen)
                        {
                            // Do not count leading zero bits of the prime.
                            var first = msg[2];
                            int lead = 0;
                            for (int b = 7; b >= 0 && (first & (1 << b)) == 0; b--) lead++;
                            bits -= lead;
                        }
                        result.DhPrimeBits = bits;
                    }
                    break;
                case 0x0E:
                    result.Complete = true;
                    break;
            }
            p += 4 + msgLen;
        }
        return result;
    }

    private static void ParseServerHello(ReadOnlySpan<byte> msg, ServerHandshake r)
    {
        if (msg.Length < 38) return;
        r.GotServerHello = true;
        r.NegotiatedVersion = BinaryPrimitives.ReadUInt16BigEndian(msg);
        int pos = 2 + 32;
        int sidLen = msg[pos];
        pos += 1 + sidLen;
        if (pos + 3 > msg.Length) return;
        r.Cipher = BinaryPrimitives.ReadUInt16BigEndian(msg[pos..]);
        pos += 3; // cipher + compression
        if (pos + 2 > msg.Length) return;
        var extLen = BinaryPrimitives.ReadUInt16BigEndian(msg[pos..]);
        pos += 2;
        var end = Math.Min(msg.Length, pos + extLen);
        while (pos + 4 <= end)
        {
            var et = BinaryPrimitives.ReadUInt16BigEndian(msg[pos..]);
            var el = BinaryPrimitives.ReadUInt16BigEndian(msg[(pos + 2)..]);
            if (et == 0x002B && el == 2 && pos + 6 <= end)
                r.NegotiatedVersion = BinaryPrimitives.ReadUInt16BigEndian(msg[(pos + 4)..]);
            pos += 4 + el;
        }
    }

    private static void ParseCertificates(ReadOnlySpan<byte> msg, ServerHandshake r)
    {
        if (msg.Length < 3) return;
        var total = (msg[0] << 16) | (msg[1] << 8) | msg[2];
        int pos = 3;
        var end = Math.Min(msg.Length, 3 + total);
        while (pos + 3 <= end)
        {
            var len = (msg[pos] << 16) | (msg[pos + 1] << 8) | msg[pos + 2];
            pos += 3;
            if (pos + len > end) break;
            r.Certificates.Add(msg.Slice(pos, len).ToArray());
            pos += len;
        }
    }

    /// <summary>Reads records until the handshake is complete, an alert arrives, or the timeout expires.</summary>
    public static async Task<byte[]> ReadHandshakeAsync(ITcpSession session, TimeSpan timeout, CancellationToken ct, int maxBytes = 65536)
    {
        var buf = new MemoryStream();
        var deadline = DateTime.UtcNow + timeout;
        while (buf.Length < maxBytes)
        {
            var left = deadline - DateTime.UtcNow;
            if (left <= TimeSpan.Zero) break;
            var chunk = await session.ReceiveAsync(16384, left, ct).ConfigureAwait(false);
            if (chunk.Length == 0) break;
            buf.Write(chunk);
            var parsed = Parse(buf.GetBuffer().AsSpan(0, (int)buf.Length));
            if (parsed.Complete) break;
        }
        return buf.ToArray();
    }
}
