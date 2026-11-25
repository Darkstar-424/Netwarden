using System.Buffers.Binary;
using System.Text;
using NetWarden.Core.Util;

namespace NetWarden.Core.Protocols;

public static class DnsPackets
{
    /// <summary>Standard query. recursionDesired=false asks only for what the server already holds.</summary>
    public static byte[] Query(string name, ushort type, bool recursionDesired, ushort id = 0x4E57)
    {
        var w = new PacketWriter()
            .U16BE(id)
            .U16BE((ushort)(recursionDesired ? 0x0100 : 0x0000))
            .U16BE(1).U16BE(0).U16BE(0).U16BE(0);
        foreach (var label in name.TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var b = Encoding.ASCII.GetBytes(label);
            w.U8((byte)b.Length).Bytes(b);
        }
        w.U8(0).U16BE(type).U16BE(1);
        return w.ToArray();
    }

    public sealed record DnsHeader(ushort Id, bool IsResponse, bool RecursionAvailable, int ResponseCode, int AnswerCount);

    public static DnsHeader? ParseHeader(ReadOnlySpan<byte> data)
    {
        if (data.Length < 12) return null;
        var flags = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);
        return new DnsHeader(
            BinaryPrimitives.ReadUInt16BigEndian(data),
            (flags & 0x8000) != 0,
            (flags & 0x0080) != 0,
            flags & 0x000F,
            BinaryPrimitives.ReadUInt16BigEndian(data[6..]));
    }
}

public static class NtpPackets
{
    /// <summary>Plain NTPv4 client (mode 3) request. Asks only for the time.</summary>
    public static byte[] ClientRequest()
    {
        var b = new byte[48];
        b[0] = 0x23; // LI=0, VN=4, Mode=3
        return b;
    }

    public static (int Version, int Mode, int Stratum)? ParseResponse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 48) return null;
        return ((data[0] >> 3) & 0x7, data[0] & 0x7, data[1]);
    }
}

public static class SnmpPackets
{
    /// <summary>
    /// SNMPv3 engine discovery (RFC 3414 §4): an unauthenticated request with an empty engine ID and user.
    /// The agent answers with a Report containing its engine ID. No community string is guessed.
    /// </summary>
    public static byte[] V3DiscoveryRequest(int messageId = 0x4E57, int requestId = 0x4E57)
    {
        var globalData = Ber.Sequence(
            Ber.Integer(messageId),
            Ber.Integer(65507),
            Ber.OctetString(new byte[] { 0x04 }), // reportable flag
            Ber.Integer(3));                       // USM
        var usm = Ber.Sequence(
            Ber.OctetString(Array.Empty<byte>()),
            Ber.Integer(0),
            Ber.Integer(0),
            Ber.OctetString(Array.Empty<byte>()),
            Ber.OctetString(Array.Empty<byte>()),
            Ber.OctetString(Array.Empty<byte>()));
        var pdu = Ber.Tagged(0xA0,
            Ber.Integer(requestId), Ber.Integer(0), Ber.Integer(0), Ber.Sequence());
        var scoped = Ber.Sequence(Ber.OctetString(Array.Empty<byte>()), Ber.OctetString(Array.Empty<byte>()), pdu);
        return Ber.Sequence(Ber.Integer(3), globalData, Ber.OctetString(usm), scoped);
    }

    /// <summary>Extracts the authoritative engine ID from a v3 Report, or null if not an SNMPv3 reply.</summary>
    public static byte[]? ParseEngineId(ReadOnlySpan<byte> data)
    {
        try
        {
            var r = new Ber.Reader(data.ToArray());
            var msg = r.ReadSequence();
            var version = msg.ReadInteger();
            if (version != 3) return null;
            msg.ReadSequence(); // global data
            var secParams = msg.ReadOctetString();
            var usm = new Ber.Reader(secParams).ReadSequence();
            return usm.ReadOctetString();
        }
        catch (Exception ex) when (ex is FormatException or IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    /// <summary>Private Enterprise Number from an RFC 3411 engine ID, when present.</summary>
    public static int? EnterpriseNumber(byte[] engineId)
    {
        if (engineId.Length < 5 || (engineId[0] & 0x80) == 0) return null;
        return (int)(BinaryPrimitives.ReadUInt32BigEndian(engineId) & 0x7FFFFFFF);
    }

    public static string? EnterpriseName(int pen) => pen switch
    {
        9 => "Cisco",
        11 => "HP",
        311 => "Microsoft",
        2021 => "Net-SNMP (UC Davis)",
        8072 => "Net-SNMP",
        4526 => "Netgear",
        2636 => "Juniper",
        14988 => "MikroTik",
        6574 => "Synology",
        24681 => "QNAP",
        367 => "Ricoh",
        1602 => "Canon",
        2435 => "Brother",
        253 => "Xerox",
        641 => "Lexmark",
        41112 => "Ubiquiti",
        12356 => "Fortinet",
        25461 => "Palo Alto Networks",
        _ => null
    };
}

/// <summary>Tiny BER encoder/decoder sufficient for SNMP discovery.</summary>
public static class Ber
{
    private static byte[] Tlv(byte tag, byte[] value)
    {
        var w = new PacketWriter().U8(tag);
        if (value.Length < 0x80) w.U8((byte)value.Length);
        else if (value.Length <= 0xFF) w.U8(0x81).U8((byte)value.Length);
        else w.U8(0x82).U16BE((ushort)value.Length);
        return w.Bytes(value).ToArray();
    }

    public static byte[] Integer(int v)
    {
        var bytes = new List<byte>();
        var x = v;
        do { bytes.Insert(0, (byte)(x & 0xFF)); x >>= 8; } while (x != 0 && x != -1);
        if (v >= 0 && (bytes[0] & 0x80) != 0) bytes.Insert(0, 0);
        if (v < 0 && (bytes[0] & 0x80) == 0) bytes.Insert(0, 0xFF);
        return Tlv(0x02, bytes.ToArray());
    }

    public static byte[] OctetString(byte[] v) => Tlv(0x04, v);
    public static byte[] Sequence(params byte[][] items) => Tagged(0x30, items);
    public static byte[] Tagged(byte tag, params byte[][] items) => Tlv(tag, items.SelectMany(i => i).ToArray());

    public sealed class Reader
    {
        private readonly byte[] _d;
        private int _p;
        private readonly int _end;
        public Reader(byte[] data) : this(data, 0, data.Length) { }
        private Reader(byte[] d, int start, int end) { _d = d; _p = start; _end = end; }

        private (byte Tag, int Start, int Length) Next()
        {
            if (_p + 2 > _end) throw new FormatException("Truncated BER.");
            var tag = _d[_p++];
            int len = _d[_p++];
            if ((len & 0x80) != 0)
            {
                var n = len & 0x7F;
                if (n is < 1 or > 3) throw new FormatException("Bad BER length.");
                len = 0;
                for (int i = 0; i < n; i++) len = (len << 8) | _d[_p++];
            }
            if (_p + len > _end) throw new FormatException("BER overflow.");
            var start = _p;
            _p += len;
            return (tag, start, len);
        }

        public Reader ReadSequence()
        {
            var (tag, start, len) = Next();
            if ((tag & 0x20) == 0) throw new FormatException("Expected constructed type.");
            return new Reader(_d, start, start + len);
        }

        public int ReadInteger()
        {
            var (tag, start, len) = Next();
            if (tag != 0x02) throw new FormatException("Expected INTEGER.");
            int v = (_d[start] & 0x80) != 0 ? -1 : 0;
            for (int i = 0; i < len; i++) v = (v << 8) | _d[start + i];
            return v;
        }

        public byte[] ReadOctetString()
        {
            var (tag, start, len) = Next();
            if (tag != 0x04) throw new FormatException("Expected OCTET STRING.");
            return _d.AsSpan(start, len).ToArray();
        }
    }
}

public static class NetBiosPackets
{
    /// <summary>NBSTAT (node status) query for the wildcard name "*". Read-only.</summary>
    public static byte[] NodeStatusRequest(ushort id = 0x4E57)
    {
        var name = new byte[32];
        // "*" followed by 15 NULs, first-level encoded.
        var raw = new byte[16];
        raw[0] = (byte)'*';
        for (int i = 0; i < 16; i++)
        {
            name[i * 2] = (byte)('A' + (raw[i] >> 4));
            name[i * 2 + 1] = (byte)('A' + (raw[i] & 0x0F));
        }
        return new PacketWriter()
            .U16BE(id).U16BE(0x0000).U16BE(1).U16BE(0).U16BE(0).U16BE(0)
            .U8(32).Bytes(name).U8(0)
            .U16BE(0x0021).U16BE(0x0001)
            .ToArray();
    }

    public sealed record NodeStatus(string? ComputerName, string? Workgroup, string? Mac, IReadOnlyList<(string Name, byte Suffix, bool Group)> Names);

    public static NodeStatus? ParseNodeStatus(ReadOnlySpan<byte> data)
    {
        // header(12) + name(34) + type(2) + class(2) + ttl(4) + rdlength(2) = 56
        if (data.Length < 57) return null;
        var answers = BinaryPrimitives.ReadUInt16BigEndian(data[6..]);
        if (answers < 1) return null;
        int pos = 12;
        // skip the encoded name (length-prefixed labels or pointer)
        if ((data[pos] & 0xC0) == 0xC0) pos += 2;
        else
        {
            while (pos < data.Length && data[pos] != 0) pos += data[pos] + 1;
            pos++;
        }
        pos += 2 + 2 + 4 + 2; // type, class, ttl, rdlength
        if (pos >= data.Length) return null;
        int count = data[pos++];
        var names = new List<(string, byte, bool)>();
        string? computer = null, group = null;
        for (int i = 0; i < count; i++)
        {
            if (pos + 18 > data.Length) break;
            var n = Encoding.ASCII.GetString(data.Slice(pos, 15)).TrimEnd(' ', '\0');
            var suffix = data[pos + 15];
            var flags = BinaryPrimitives.ReadUInt16BigEndian(data[(pos + 16)..]);
            var isGroup = (flags & 0x8000) != 0;
            names.Add((n, suffix, isGroup));
            if (suffix == 0x00 && !isGroup && computer == null) computer = n;
            if (suffix == 0x00 && isGroup && group == null) group = n;
            pos += 18;
        }
        string? mac = null;
        if (pos + 6 <= data.Length)
        {
            var m = data.Slice(pos, 6);
            if (m.IndexOfAnyExcept((byte)0) >= 0)
                mac = string.Join(":", m.ToArray().Select(b => b.ToString("X2")));
        }
        return new NodeStatus(computer, group, mac, names);
    }
}

public static class SsdpPackets
{
    public static byte[] MSearch(string host) => Encoding.ASCII.GetBytes(
        $"M-SEARCH * HTTP/1.1\r\nHOST: {host}:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n");

    public static string? ParseServer(ReadOnlySpan<byte> data)
    {
        var text = Encoding.ASCII.GetString(data);
        if (!text.StartsWith("HTTP/1.1 200", StringComparison.OrdinalIgnoreCase)) return null;
        foreach (var line in text.Split("\r\n"))
            if (line.StartsWith("SERVER:", StringComparison.OrdinalIgnoreCase)) return line[7..].Trim();
        return "";
    }
}

public static class IpmiPackets
{
    /// <summary>RMCP/ASF Presence Ping. BMCs (iLO, iDRAC, IPMI) answer with a Presence Pong.</summary>
    public static readonly byte[] AsfPresencePing =
        { 0x06, 0x00, 0xFF, 0x06, 0x00, 0x00, 0x11, 0xBE, 0x80, 0x00, 0x00, 0x00 };

    public static bool IsPresencePong(ReadOnlySpan<byte> data)
        => data.Length >= 12 && data[0] == 0x06 && data[3] == 0x06 && data[8] == 0x40;
}
