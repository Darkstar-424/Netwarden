using System.Buffers.Binary;
using System.Net;
using System.Text;
using NetWarden.Core.Util;

namespace NetWarden.Core.Protocols;

/// <summary>
/// Multicast DNS / DNS-SD (Bonjour, Avahi) packets. NetWarden sends ordinary read-only questions straight to one
/// device's port 5353 ("legacy unicast", RFC 6762 §6.7) and reads the answer. This is the same question any phone,
/// printer dialog or media app asks to find services on a network.
/// </summary>
public static class MdnsPackets
{
    public const ushort TypeA = 1, TypePtr = 12, TypeTxt = 16, TypeAaaa = 28, TypeSrv = 33, TypeAny = 255;
    public const string ServicesMetaQuery = "_services._dns-sd._udp.local";

    public sealed record Record(string Name, ushort Type, string? Target = null, int Port = 0,
        IReadOnlyDictionary<string, string>? Txt = null, string? Address = null);

    public static byte[] Query(IEnumerable<(string Name, ushort Type)> questions, ushort id = 0x4E57)
    {
        var list = questions.ToList();
        var w = new PacketWriter().U16BE(id).U16BE(0).U16BE((ushort)list.Count).U16BE(0).U16BE(0).U16BE(0);
        foreach (var (name, type) in list)
        {
            WriteName(w, name);
            w.U16BE(type).U16BE(1);
        }
        return w.ToArray();
    }

    private static void WriteName(PacketWriter w, string name)
    {
        foreach (var label in name.TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var b = Encoding.UTF8.GetBytes(label);
            if (b.Length > 63) b = b[..63];
            w.U8((byte)b.Length).Bytes(b);
        }
        w.U8(0);
    }

    /// <summary>Parses every answer, authority and additional record. Returns null if this isn't a DNS response.</summary>
    public static List<Record>? Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 12) return null;
        var flags = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);
        if ((flags & 0x8000) == 0) return null;
        int qd = BinaryPrimitives.ReadUInt16BigEndian(data[4..]);
        int total = BinaryPrimitives.ReadUInt16BigEndian(data[6..]) + BinaryPrimitives.ReadUInt16BigEndian(data[8..]) + BinaryPrimitives.ReadUInt16BigEndian(data[10..]);
        var records = new List<Record>();
        int pos = 12;
        try
        {
            for (int i = 0; i < qd; i++)
            {
                ReadName(data, ref pos);
                pos += 4;
            }
            for (int i = 0; i < total && pos + 10 <= data.Length; i++)
            {
                var name = ReadName(data, ref pos);
                if (pos + 10 > data.Length) break;
                var type = BinaryPrimitives.ReadUInt16BigEndian(data[pos..]);
                int rdLen = BinaryPrimitives.ReadUInt16BigEndian(data[(pos + 8)..]);
                pos += 10;
                if (pos + rdLen > data.Length) break;
                int rd = pos;
                pos += rdLen;
                switch (type)
                {
                    case TypePtr:
                        { int p = rd; records.Add(new Record(name, type, Target: ReadName(data, ref p))); break; }
                    case TypeSrv when rdLen >= 7:
                        {
                            int port = BinaryPrimitives.ReadUInt16BigEndian(data[(rd + 4)..]);
                            int p = rd + 6;
                            records.Add(new Record(name, type, Target: ReadName(data, ref p), Port: port));
                            break;
                        }
                    case TypeTxt:
                        records.Add(new Record(name, type, Txt: ParseTxt(data.Slice(rd, rdLen))));
                        break;
                    case TypeA when rdLen == 4:
                        records.Add(new Record(name, type, Address: new IPAddress(data.Slice(rd, 4)).ToString()));
                        break;
                    case TypeAaaa when rdLen == 16:
                        records.Add(new Record(name, type, Address: new IPAddress(data.Slice(rd, 16)).ToString()));
                        break;
                }
            }
        }
        catch (FormatException) { /* malformed tail: keep what we have */ }
        return records;
    }

    private static Dictionary<string, string> ParseTxt(ReadOnlySpan<byte> rd)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        int p = 0;
        while (p < rd.Length)
        {
            int len = rd[p++];
            if (len == 0 || p + len > rd.Length) { p += len; continue; }
            var s = Encoding.UTF8.GetString(rd.Slice(p, len));
            p += len;
            var eq = s.IndexOf('=');
            var key = eq < 0 ? s : s[..eq];
            if (key.Length > 0 && !d.ContainsKey(key)) d[key] = eq < 0 ? "" : s[(eq + 1)..];
        }
        return d;
    }

    private static string ReadName(ReadOnlySpan<byte> data, ref int pos)
    {
        var sb = new StringBuilder();
        int p = pos, jumps = 0;
        bool jumped = false;
        while (true)
        {
            if (p >= data.Length) throw new FormatException("name runs past end");
            int len = data[p];
            if ((len & 0xC0) == 0xC0)
            {
                if (p + 1 >= data.Length || ++jumps > 20) throw new FormatException("bad pointer");
                if (!jumped) pos = p + 2;
                jumped = true;
                p = ((len & 0x3F) << 8) | data[p + 1];
                continue;
            }
            p++;
            if (len == 0) break;
            if (p + len > data.Length) throw new FormatException("label runs past end");
            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.UTF8.GetString(data.Slice(p, len)));
            p += len;
        }
        if (!jumped) pos = p;
        return sb.ToString();
    }

    /// <summary>"Living Room._googlecast._tcp.local" → ("Living Room", "_googlecast._tcp").</summary>
    public static (string Instance, string ServiceType)? SplitInstance(string fullName)
    {
        var idx = fullName.IndexOf("._", StringComparison.Ordinal);
        if (idx <= 0) return null;
        var type = fullName[(idx + 1)..];
        if (type.EndsWith(".local", StringComparison.OrdinalIgnoreCase)) type = type[..^6];
        // A bare service type such as "_ipp._tcp.local" has no instance part.
        if (type is "_tcp" or "_udp") return null;
        return (fullName[..idx], type);
    }
}
