using System.Buffers.Binary;
using System.Text;
using NetWarden.Core.Util;

namespace NetWarden.Core.Protocols;

/// <summary>Read-only SMB negotiation packets. Nothing here authenticates or writes anything.</summary>
public static class SmbPackets
{
    public const uint StatusSuccess = 0x00000000;
    public const uint StatusInsuffServerResources = 0xC0000205;
    public const uint StatusInvalidHandle = 0xC0000008;
    public const uint StatusAccessDenied = 0xC0000022;

    private static byte[] WithNetBios(byte[] smb)
    {
        var w = new PacketWriter().U8(0).U24BE(smb.Length).Bytes(smb);
        return w.ToArray();
    }

    /// <summary>SMB2 NEGOTIATE offering 2.0.2, 2.1, 3.0, 3.0.2 (3.1.1 needs negotiate contexts, which we avoid).</summary>
    public static byte[] Smb2Negotiate()
    {
        ushort[] dialects = { 0x0202, 0x0210, 0x0300, 0x0302 };
        var w = new PacketWriter();
        // SMB2 header (64 bytes)
        w.Bytes(new byte[] { 0xFE, (byte)'S', (byte)'M', (byte)'B' })
         .U16LE(64)      // StructureSize
         .U16LE(0)       // CreditCharge
         .U32LE(0)       // Status
         .U16LE(0)       // Command NEGOTIATE
         .U16LE(1)       // CreditRequest
         .U32LE(0)       // Flags
         .U32LE(0)       // NextCommand
         .U64LE(0)       // MessageId
         .U32LE(0xFEFF)  // Reserved / ProcessId
         .U32LE(0)       // TreeId
         .U64LE(0)       // SessionId
         .Zeros(16);     // Signature
        // NEGOTIATE request
        w.U16LE(36)
         .U16LE((ushort)dialects.Length)
         .U16LE(0x0001)  // SecurityMode: signing enabled
         .U16LE(0)
         .U32LE(0)       // Capabilities
         .Bytes(Guid.NewGuid().ToByteArray())
         .U64LE(0);      // ClientStartTime
        foreach (var d in dialects) w.U16LE(d);
        return WithNetBios(w.ToArray());
    }

    public sealed record Smb2NegotiateInfo(ushort Dialect, bool SigningEnabled, bool SigningRequired, Guid ServerGuid, DateTime? SystemTime, DateTime? BootTime)
    {
        public string DialectName => Dialect switch
        {
            0x0202 => "2.0.2",
            0x0210 => "2.1",
            0x0300 => "3.0",
            0x0302 => "3.0.2",
            0x0311 => "3.1.1",
            0x02FF => "2.???",
            _ => $"0x{Dialect:X4}"
        };
    }

    public static Smb2NegotiateInfo? ParseSmb2NegotiateResponse(ReadOnlySpan<byte> data)
    {
        // Skip the 4-byte NetBIOS session header.
        // Fixed part of the NEGOTIATE response is 64 bytes (StructureSize 65 counts one byte of the variable buffer).
        if (data.Length < 4 + 64 + 56) return null;
        var smb = data[4..];
        if (smb[0] != 0xFE || smb[1] != (byte)'S' || smb[2] != (byte)'M' || smb[3] != (byte)'B') return null;
        var status = BinaryPrimitives.ReadUInt32LittleEndian(smb[8..]);
        if (status != StatusSuccess) return null;
        var body = smb[64..];
        if (BinaryPrimitives.ReadUInt16LittleEndian(body) != 65) return null;
        var secMode = BinaryPrimitives.ReadUInt16LittleEndian(body[2..]);
        var dialect = BinaryPrimitives.ReadUInt16LittleEndian(body[4..]);
        var guid = new Guid(body.Slice(8, 16));
        DateTime? sys = FileTime(BinaryPrimitives.ReadInt64LittleEndian(body[40..]));
        DateTime? boot = FileTime(BinaryPrimitives.ReadInt64LittleEndian(body[48..]));
        return new Smb2NegotiateInfo(dialect, (secMode & 0x01) != 0, (secMode & 0x02) != 0, guid, sys, boot);
    }

    private static DateTime? FileTime(long ft)
    {
        if (ft <= 0) return null;
        try { return DateTime.FromFileTimeUtc(ft); } catch { return null; }
    }

    private static PacketWriter Smb1Header(byte command, ushort tid = 0, ushort uid = 0, ushort mid = 1)
    {
        return new PacketWriter()
            .Bytes(new byte[] { 0xFF, (byte)'S', (byte)'M', (byte)'B' })
            .U8(command)
            .U32LE(0)          // Status
            .U8(0x18)          // Flags: canonical paths, case insensitive
            .U16LE(0x4001)     // Flags2: NT status codes, long names
            .U16LE(0)          // PIDHigh
            .Zeros(8)          // SecurityFeatures
            .U16LE(0)          // Reserved
            .U16LE(tid)
            .U16LE(0xFEFF)     // PIDLow
            .U16LE(uid)
            .U16LE(mid);
    }

    /// <summary>SMB1 NEGOTIATE offering only "NT LM 0.12". Servers with SMB1 disabled refuse or reset.</summary>
    public static byte[] Smb1Negotiate()
    {
        var dialect = Encoding.ASCII.GetBytes("NT LM 0.12\0");
        var w = Smb1Header(0x72)
            .U8(0)                                   // WordCount
            .U16LE((ushort)(dialect.Length + 1))     // ByteCount
            .U8(0x02).Bytes(dialect);                // BufferFormat + dialect
        return WithNetBios(w.ToArray());
    }

    public sealed record Smb1NegotiateInfo(bool Accepted, bool SigningRequired, bool SigningEnabled, bool ExtendedSecurity);

    public static Smb1NegotiateInfo ParseSmb1NegotiateResponse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4 + 32 + 3) return new Smb1NegotiateInfo(false, false, false, false);
        var smb = data[4..];
        if (smb[0] != 0xFF || smb[1] != (byte)'S' || smb[2] != (byte)'M' || smb[3] != (byte)'B' || smb[4] != 0x72)
            return new Smb1NegotiateInfo(false, false, false, false);
        var status = BinaryPrimitives.ReadUInt32LittleEndian(smb[5..]);
        if (status != StatusSuccess) return new Smb1NegotiateInfo(false, false, false, false);
        var flags2 = BinaryPrimitives.ReadUInt16LittleEndian(smb[10..]);
        var wordCount = smb[32];
        if (wordCount < 1) return new Smb1NegotiateInfo(false, false, false, false);
        var dialectIndex = BinaryPrimitives.ReadUInt16LittleEndian(smb[33..]);
        if (dialectIndex == 0xFFFF) return new Smb1NegotiateInfo(false, false, false, false);
        bool sigReq = false, sigEn = false;
        if (wordCount >= 17 && smb.Length >= 36)
        {
            var securityMode = smb[35];
            sigEn = (securityMode & 0x04) != 0;
            sigReq = (securityMode & 0x08) != 0;
        }
        return new Smb1NegotiateInfo(true, sigReq, sigEn, (flags2 & 0x0800) != 0);
    }

    // ---- MS17-010 safe status-code probe (same approach as Nmap's smb-vuln-ms17-010) ----

    /// <summary>Anonymous (null) SESSION_SETUP_ANDX, non-extended security.</summary>
    public static byte[] Smb1AnonymousSessionSetup()
    {
        var nativeOs = Encoding.ASCII.GetBytes("Windows 2000 2195\0");
        var nativeLm = Encoding.ASCII.GetBytes("Windows 2000 5.0\0");
        var bytes = new PacketWriter()
            .U8(0)            // empty account name (ASCII, null)
            .U8(0)            // empty primary domain
            .Bytes(nativeOs)
            .Bytes(nativeLm)
            .ToArray();
        var w = Smb1Header(0x73, mid: 2)
            .U8(13)            // WordCount
            .U8(0xFF).U8(0).U16LE(0)   // AndX: none
            .U16LE(4356)       // MaxBufferSize
            .U16LE(10)         // MaxMpxCount
            .U16LE(0)          // VcNumber
            .U32LE(0)          // SessionKey
            .U16LE(0)          // OEM password length
            .U16LE(0)          // Unicode password length
            .U32LE(0)          // Reserved
            .U32LE(0x00000050) // Capabilities: NT status, large files
            .U16LE((ushort)bytes.Length)
            .Bytes(bytes);
        return WithNetBios(w.ToArray());
    }

    public static (uint Status, ushort Uid) ParseSmb1Status(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4 + 32) return (0xFFFFFFFF, 0);
        var smb = data[4..];
        if (smb[0] != 0xFF || smb[1] != (byte)'S') return (0xFFFFFFFF, 0);
        var status = BinaryPrimitives.ReadUInt32LittleEndian(smb[5..]);
        var uid = BinaryPrimitives.ReadUInt16LittleEndian(smb[28..]);
        return (status, uid);
    }

    public static ushort ParseSmb1Tid(ReadOnlySpan<byte> data)
        => data.Length < 4 + 32 ? (ushort)0 : BinaryPrimitives.ReadUInt16LittleEndian(data[(4 + 24)..]);

    /// <summary>TREE_CONNECT_ANDX to \\host\IPC$ (read-only named-pipe share).</summary>
    public static byte[] Smb1TreeConnectIpc(string host, ushort uid)
    {
        var path = Encoding.ASCII.GetBytes($"\\\\{host}\\IPC$\0");
        var service = Encoding.ASCII.GetBytes("?????\0");
        var w = Smb1Header(0x75, uid: uid, mid: 3)
            .U8(4)                       // WordCount
            .U8(0xFF).U8(0).U16LE(0)     // AndX none
            .U16LE(0)                    // Flags
            .U16LE(1)                    // PasswordLength (1 null byte)
            .U16LE((ushort)(1 + path.Length + service.Length))
            .U8(0)
            .Bytes(path)
            .Bytes(service);
        return WithNetBios(w.ToArray());
    }

    /// <summary>TRANSACTION with PeekNamedPipe on FID 0. A vulnerable host answers STATUS_INSUFF_SERVER_RESOURCES.</summary>
    public static byte[] Smb1PeekNamedPipeFid0(ushort tid, ushort uid)
    {
        var w = Smb1Header(0x25, tid: tid, uid: uid, mid: 4)
            .U8(16)                  // WordCount (14 + SetupCount 2)
            .U16LE(0)                // TotalParameterCount
            .U16LE(0)                // TotalDataCount
            .U16LE(0xFFFF)           // MaxParameterCount
            .U16LE(0xFFFF)           // MaxDataCount
            .U8(0)                   // MaxSetupCount
            .U8(0)                   // Reserved
            .U16LE(0)                // Flags
            .U32LE(0)                // Timeout
            .U16LE(0)                // Reserved2
            .U16LE(0)                // ParameterCount
            .U16LE(0x4A)             // ParameterOffset
            .U16LE(0)                // DataCount
            .U16LE(0x4A)             // DataOffset
            .U8(2)                   // SetupCount
            .U8(0)                   // Reserved3
            .U16LE(0x0023)           // Setup[0]: PeekNamedPipe
            .U16LE(0)                // Setup[1]: FID 0
            .U16LE(7)                // ByteCount
            .Bytes(Encoding.ASCII.GetBytes("\\PIPE\\\0"));
        return WithNetBios(w.ToArray());
    }

    /// <summary>Reads one full NetBIOS-framed SMB message from the session.</summary>
    public static async Task<byte[]> ReadMessageAsync(ITcpSession session, TimeSpan timeout, CancellationToken ct)
    {
        var header = await session.ReceiveExactAsync(4, timeout, ct).ConfigureAwait(false);
        if (header.Length < 4) return header;
        var len = (header[1] << 16) | (header[2] << 8) | header[3];
        if (len <= 0 || len > 1 << 20) return header;
        var body = await session.ReceiveExactAsync(len, timeout, ct).ConfigureAwait(false);
        var all = new byte[4 + body.Length];
        header.CopyTo(all, 0);
        body.CopyTo(all, 4);
        return all;
    }
}
