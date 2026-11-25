using System.Buffers.Binary;
using System.Text;
using NetWarden.Core.Util;

namespace NetWarden.Core.Protocols;

public static class RdpPackets
{
    public const uint ProtocolRdp = 0x00;
    public const uint ProtocolSsl = 0x01;
    public const uint ProtocolHybrid = 0x02;   // CredSSP / NLA
    public const uint ProtocolHybridEx = 0x08;

    /// <summary>X.224 Connection Request carrying an RDP_NEG_REQ with the given requested protocols.</summary>
    public static byte[] ConnectionRequest(uint requestedProtocols)
        => new PacketWriter()
            .U8(0x03).U8(0x00).U16BE(19)               // TPKT
            .U8(14).U8(0xE0).U16BE(0).U16BE(0).U8(0)   // X.224 CR
            .U8(0x01).U8(0x00).U16LE(8).U32LE(requestedProtocols) // RDP_NEG_REQ
            .ToArray();

    public enum NegotiationOutcome { NoResponse, NotRdp, Selected, Failure, LegacyNoNegotiation }

    public sealed record NegotiationResult(NegotiationOutcome Outcome, uint Value)
    {
        public string Describe() => Outcome switch
        {
            NegotiationOutcome.Selected => $"selected protocol 0x{Value:X}",
            NegotiationOutcome.Failure => $"failure code {Value} ({FailureName(Value)})",
            NegotiationOutcome.LegacyNoNegotiation => "legacy server (no negotiation, standard RDP security)",
            NegotiationOutcome.NotRdp => "not an RDP response",
            _ => "no response"
        };
    }

    public static string FailureName(uint code) => code switch
    {
        1 => "SSL_REQUIRED_BY_SERVER",
        2 => "SSL_NOT_ALLOWED_BY_SERVER",
        3 => "SSL_CERT_NOT_ON_SERVER",
        4 => "INCONSISTENT_FLAGS",
        5 => "HYBRID_REQUIRED_BY_SERVER",
        6 => "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
        _ => "unknown"
    };

    public static NegotiationResult ParseConfirm(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return new(NegotiationOutcome.NoResponse, 0);
        if (data.Length < 11 || data[0] != 0x03 || data[5] != 0xD0) return new(NegotiationOutcome.NotRdp, 0);
        if (data.Length < 19) return new(NegotiationOutcome.LegacyNoNegotiation, ProtocolRdp);
        var type = data[11];
        var value = BinaryPrimitives.ReadUInt32LittleEndian(data[15..]);
        return type switch
        {
            0x02 => new(NegotiationOutcome.Selected, value),
            0x03 => new(NegotiationOutcome.Failure, value),
            _ => new(NegotiationOutcome.NotRdp, 0)
        };
    }
}

public static class SshPackets
{
    public const string ClientBanner = "SSH-2.0-NetWarden_1.0";

    public sealed record KexInit(
        IReadOnlyList<string> Kex, IReadOnlyList<string> HostKey,
        IReadOnlyList<string> CiphersC2S, IReadOnlyList<string> CiphersS2C,
        IReadOnlyList<string> MacsC2S, IReadOnlyList<string> MacsS2C,
        IReadOnlyList<string> Compression);

    /// <summary>Parses the first binary packet after the banner (must be SSH_MSG_KEXINIT, code 20).</summary>
    public static KexInit? ParseKexInit(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 6) return null;
        var len = BinaryPrimitives.ReadUInt32BigEndian(packet);
        var padding = packet[4];
        if (len < 2 || len > 35000 || packet.Length < 4 + len) return null;
        var payload = packet.Slice(5, (int)len - padding - 1);
        if (payload.Length < 17 || payload[0] != 20) return null;
        int pos = 17; // msg code + 16-byte cookie
        var lists = new List<IReadOnlyList<string>>();
        for (int i = 0; i < 10; i++)
        {
            if (pos + 4 > payload.Length) return null;
            var l = (int)BinaryPrimitives.ReadUInt32BigEndian(payload[pos..]);
            pos += 4;
            if (l < 0 || pos + l > payload.Length) return null;
            var text = Encoding.ASCII.GetString(payload.Slice(pos, l));
            pos += l;
            lists.Add(text.Length == 0 ? Array.Empty<string>() : text.Split(','));
        }
        return new KexInit(lists[0], lists[1], lists[2], lists[3], lists[4], lists[5], lists[6]);
    }

    /// <summary>Splits "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5" into software and comment.</summary>
    public static (string Software, string? Comment) ParseBanner(string banner)
    {
        var b = banner.Trim();
        if (!b.StartsWith("SSH-", StringComparison.Ordinal)) return (b, null);
        var parts = b.Split('-', 3);
        if (parts.Length < 3) return (b, null);
        var rest = parts[2];
        var sp = rest.IndexOf(' ');
        return sp < 0 ? (rest, null) : (rest[..sp], rest[(sp + 1)..]);
    }
}

public static class TdsPackets
{
    /// <summary>TDS PRELOGIN request (no credentials) asking for the server version.</summary>
    public static byte[] PreLogin()
    {
        var payload = new PacketWriter()
            .U8(0x00).U16BE(26).U16BE(6)   // VERSION
            .U8(0x01).U16BE(32).U16BE(1)   // ENCRYPTION
            .U8(0x02).U16BE(33).U16BE(1)   // INSTOPT
            .U8(0x03).U16BE(34).U16BE(4)   // THREADID
            .U8(0x04).U16BE(38).U16BE(1)   // MARS
            .U8(0xFF)
            .Bytes(new byte[] { 0x0F, 0x00, 0x07, 0xD0, 0x00, 0x00 }) // client version
            .U8(0x02)                      // ENCRYPT_NOT_SUP
            .U8(0x00)                      // instance: default
            .U32BE(0)
            .U8(0x00)
            .ToArray();
        return new PacketWriter()
            .U8(0x12).U8(0x01).U16BE((ushort)(8 + payload.Length)).U16BE(0).U8(1).U8(0)
            .Bytes(payload)
            .ToArray();
    }

    public sealed record PreLoginInfo(int Major, int Minor, int Build, int SubBuild, byte Encryption)
    {
        public string Version => $"{Major}.{Minor}.{Build}.{SubBuild}";
        public string ProductName => Major switch
        {
            16 => "SQL Server 2022",
            15 => "SQL Server 2019",
            14 => "SQL Server 2017",
            13 => "SQL Server 2016",
            12 => "SQL Server 2014",
            11 => "SQL Server 2012",
            10 => Minor >= 50 ? "SQL Server 2008 R2" : "SQL Server 2008",
            9 => "SQL Server 2005",
            8 => "SQL Server 2000",
            _ => "Microsoft SQL Server"
        };
        public string EncryptionName => Encryption switch
        {
            0 => "off (login only)",
            1 => "on",
            2 => "not supported",
            3 => "required",
            _ => $"0x{Encryption:X2}"
        };
    }

    public static PreLoginInfo? ParsePreLoginResponse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 8 + 6 || data[0] != 0x04) return null;
        var payload = data[8..];
        int pos = 0;
        int versionOffset = -1, versionLen = 0, encOffset = -1;
        while (pos < payload.Length && payload[pos] != 0xFF)
        {
            if (pos + 5 > payload.Length) return null;
            var token = payload[pos];
            var off = BinaryPrimitives.ReadUInt16BigEndian(payload[(pos + 1)..]);
            var len = BinaryPrimitives.ReadUInt16BigEndian(payload[(pos + 3)..]);
            if (token == 0x00) { versionOffset = off; versionLen = len; }
            if (token == 0x01) encOffset = off;
            pos += 5;
        }
        if (versionOffset < 0 || versionLen < 6 || versionOffset + 6 > payload.Length) return null;
        var v = payload.Slice(versionOffset, 6);
        byte enc = encOffset >= 0 && encOffset < payload.Length ? payload[encOffset] : (byte)0xFF;
        return new PreLoginInfo(v[0], v[1], BinaryPrimitives.ReadUInt16BigEndian(v[2..]), BinaryPrimitives.ReadUInt16BigEndian(v[4..]), enc);
    }
}

public static class MySqlPackets
{
    public sealed record Greeting(int ProtocolVersion, string ServerVersion, bool IsError, string? ErrorMessage);

    public static Greeting? ParseGreeting(ReadOnlySpan<byte> data)
    {
        if (data.Length < 5) return null;
        var len = data[0] | (data[1] << 8) | (data[2] << 16);
        if (len <= 0 || len > 1 << 16) return null;
        var payload = data[4..];
        if (payload.Length == 0) return null;
        if (payload[0] == 0xFF)
        {
            var msg = payload.Length > 3 ? Encoding.UTF8.GetString(payload[3..]) : "";
            return new Greeting(0, "", true, msg.TrimStart('#'));
        }
        if (payload[0] != 10 && payload[0] != 9) return null;
        var end = payload[1..].IndexOf((byte)0);
        if (end <= 0) return null;
        var version = Encoding.ASCII.GetString(payload.Slice(1, end));
        return new Greeting(payload[0], version, false, null);
    }
}

public static class PostgresPackets
{
    public static readonly byte[] SslRequest = { 0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F };
}

public static class VncPackets
{
    /// <summary>Returns the security types a VNC server offers before authentication (RFB 3.7+).</summary>
    public static IReadOnlyList<byte>? ParseSecurityTypes(ReadOnlySpan<byte> data)
    {
        if (data.Length < 1) return null;
        var n = data[0];
        if (n == 0) return Array.Empty<byte>();
        if (data.Length < 1 + n) return null;
        return data.Slice(1, n).ToArray();
    }

    public static string SecurityTypeName(byte t) => t switch
    {
        1 => "None",
        2 => "VNC Authentication",
        5 => "RA2",
        6 => "RA2ne",
        16 => "Tight",
        18 => "TLS",
        19 => "VeNCrypt",
        30 => "Apple Remote Desktop",
        _ => $"type {t}"
    };
}
