using System.Buffers.Binary;
using System.Text;
using NetWarden.Core.Protocols;
using NetWarden.Core.Tls;
using NetWarden.Core.Util;
using Xunit;

namespace NetWarden.Tests;

public class ProtocolTests
{
    public static byte[] Smb2NegotiateResponse(ushort dialect, ushort securityMode)
    {
        var w = new PacketWriter()
            .Bytes(new byte[] { 0xFE, (byte)'S', (byte)'M', (byte)'B' }).U16LE(64).U16LE(0).U32LE(0).U16LE(0).U16LE(1).U32LE(1).U32LE(0)
            .U64LE(0).U32LE(0).U32LE(0).U64LE(0).Zeros(16)
            .U16LE(65).U16LE(securityMode).U16LE(dialect).U16LE(0).Bytes(Guid.NewGuid().ToByteArray())
            .U32LE(0x2F).U32LE(65536).U32LE(65536).U32LE(65536)
            .U64LE((ulong)DateTime.UtcNow.ToFileTimeUtc()).U64LE(0)
            .U16LE(0x80).U16LE(0).U32LE(0);
        var smb = w.ToArray();
        return new PacketWriter().U8(0).U24BE(smb.Length).Bytes(smb).ToArray();
    }

    public static byte[] Smb1NegotiateResponse(bool accepted, byte securityMode = 0x03)
    {
        var w = new PacketWriter()
            .Bytes(new byte[] { 0xFF, (byte)'S', (byte)'M', (byte)'B' }).U8(0x72).U32LE(0).U8(0x98).U16LE(0xC853)
            .U16LE(0).Zeros(8).U16LE(0).U16LE(0).U16LE(0xFEFF).U16LE(0).U16LE(1);
        if (accepted) w.U8(17).U16LE(0).U8(securityMode).Zeros(31).U16LE(0);
        else w.U8(1).U16LE(0xFFFF).U16LE(0);
        var smb = w.ToArray();
        return new PacketWriter().U8(0).U24BE(smb.Length).Bytes(smb).ToArray();
    }

    [Fact]
    public void Smb2_negotiate_request_is_well_formed()
    {
        var p = SmbPackets.Smb2Negotiate();
        Assert.Equal(p.Length - 4, (p[1] << 16) | (p[2] << 8) | p[3]);
        Assert.Equal(0xFE, p[4]);
        Assert.Equal((ushort)36, BinaryPrimitives.ReadUInt16LittleEndian(p.AsSpan(4 + 64)));
    }

    [Theory]
    [InlineData(0x0302, 0x01, false)]
    [InlineData(0x0311, 0x03, true)]
    public void Smb2_negotiate_response_signing(int dialect, int mode, bool required)
    {
        var info = SmbPackets.ParseSmb2NegotiateResponse(Smb2NegotiateResponse((ushort)dialect, (ushort)mode));
        Assert.NotNull(info);
        Assert.Equal(required, info!.SigningRequired);
        Assert.True(info.SigningEnabled);
    }

    [Fact]
    public void Smb1_negotiate_detects_acceptance_and_rejection()
    {
        Assert.True(SmbPackets.ParseSmb1NegotiateResponse(Smb1NegotiateResponse(true)).Accepted);
        Assert.False(SmbPackets.ParseSmb1NegotiateResponse(Smb1NegotiateResponse(false)).Accepted);
        Assert.False(SmbPackets.ParseSmb1NegotiateResponse(Array.Empty<byte>()).Accepted);
        Assert.True(SmbPackets.ParseSmb1NegotiateResponse(Smb1NegotiateResponse(true, 0x0F)).SigningRequired);
    }

    [Fact]
    public void Smb1_transaction_parameter_offset_matches_layout()
    {
        var p = SmbPackets.Smb1PeekNamedPipeFid0(2048, 4096);
        // NetBIOS(4) + header(32) + wordcount(1) + 16 words + bytecount(2) + "\PIPE\" (7) = 4 + 74
        Assert.Equal(4 + 74, p.Length);
        Assert.Equal((byte)16, p[4 + 32]);
    }

    public static byte[] RdpConfirm(byte type, uint value)
        => new PacketWriter().U8(3).U8(0).U16BE(19).U8(14).U8(0xD0).U16BE(0).U16BE(0x1234).U8(0)
            .U8(type).U8(0).U16LE(8).U32LE(value).ToArray();

    [Fact]
    public void Rdp_confirm_parsing()
    {
        Assert.Equal(19, RdpPackets.ConnectionRequest(RdpPackets.ProtocolSsl).Length);
        var failure = RdpPackets.ParseConfirm(RdpConfirm(0x03, 5));
        Assert.Equal(RdpPackets.NegotiationOutcome.Failure, failure.Outcome);
        Assert.Equal(5u, failure.Value);
        var selected = RdpPackets.ParseConfirm(RdpConfirm(0x02, RdpPackets.ProtocolSsl));
        Assert.Equal(RdpPackets.NegotiationOutcome.Selected, selected.Outcome);
        Assert.Equal(RdpPackets.NegotiationOutcome.NotRdp, RdpPackets.ParseConfirm(Encoding.ASCII.GetBytes("HTTP/1.1 400 Bad Request\r\n\r\n")).Outcome);
    }

    public static byte[] KexInitPacket(string kex, string ciphers, string macs)
    {
        var payload = new PacketWriter().U8(20).Zeros(16);
        foreach (var list in new[] { kex, "ssh-ed25519,rsa-sha2-512", ciphers, ciphers, macs, macs, "none", "none", "", "" })
        {
            var b = Encoding.ASCII.GetBytes(list);
            payload.U32BE((uint)b.Length).Bytes(b);
        }
        payload.U8(0).U32BE(0);
        var body = payload.ToArray();
        var padding = 8 - ((body.Length + 5) % 8);
        if (padding < 4) padding += 8;
        return new PacketWriter().U32BE((uint)(body.Length + padding + 1)).U8((byte)padding).Bytes(body).Zeros(padding).ToArray();
    }

    [Fact]
    public void Ssh_kexinit_and_banner_parse()
    {
        var kex = SshPackets.ParseKexInit(KexInitPacket("curve25519-sha256,diffie-hellman-group1-sha1", "chacha20-poly1305@openssh.com,aes128-ctr", "hmac-sha2-256-etm@openssh.com"));
        Assert.NotNull(kex);
        Assert.Contains("diffie-hellman-group1-sha1", kex!.Kex);
        Assert.Contains("chacha20-poly1305@openssh.com", kex.CiphersS2C);
        var (software, comment) = SshPackets.ParseBanner("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5");
        Assert.Equal("OpenSSH_8.2p1", software);
        Assert.Equal("Ubuntu-4ubuntu0.5", comment);
    }

    [Fact]
    public void Tds_prelogin_roundtrip()
    {
        var req = TdsPackets.PreLogin();
        Assert.Equal(0x12, req[0]);
        Assert.Equal(req.Length, BinaryPrimitives.ReadUInt16BigEndian(req.AsSpan(2)));
        // Server answer: same layout with type 0x04 and version 15.0.2000.5
        var resp = (byte[])req.Clone();
        resp[0] = 0x04;
        resp[8 + 26] = 15; resp[8 + 27] = 0; resp[8 + 28] = 0x07; resp[8 + 29] = 0xD0; resp[8 + 30] = 0; resp[8 + 31] = 5;
        var info = TdsPackets.ParsePreLoginResponse(resp);
        Assert.NotNull(info);
        Assert.Equal("15.0.2000.5", info!.Version);
        Assert.Equal("SQL Server 2019", info.ProductName);
    }

    [Fact]
    public void Mysql_greeting_parses()
    {
        var payload = new PacketWriter().U8(10).Ascii("8.0.36-0ubuntu0.22.04.1").U8(0).Zeros(20).ToArray();
        var packet = new PacketWriter().U8((byte)payload.Length).U8(0).U8(0).U8(0).Bytes(payload).ToArray();
        var g = MySqlPackets.ParseGreeting(packet);
        Assert.Equal("8.0.36-0ubuntu0.22.04.1", g!.ServerVersion);
        var error = new PacketWriter().U8(10).U8(0).U8(0).U8(0).U8(0xFF).U16LE(1130).Ascii("Host not allowed").ToArray();
        Assert.True(MySqlPackets.ParseGreeting(error)!.IsError);
    }

    [Fact]
    public void Netbios_node_status_parses()
    {
        var w = new PacketWriter().U16BE(0x4E57).U16BE(0x8400).U16BE(0).U16BE(1).U16BE(0).U16BE(0)
            .U8(32).Bytes(Enumerable.Repeat((byte)'A', 32).ToArray()).U8(0)
            .U16BE(0x21).U16BE(1).U32BE(0).U16BE(0);
        void Name(string n, byte suffix, ushort flags) => w.Ascii(n.PadRight(15)).U8(suffix).U16BE(flags);
        var body = new PacketWriter();
        w.U8(2);
        Name("FILESRV01", 0x00, 0x0400);
        Name("WORKGROUP", 0x00, 0x8400);
        w.Bytes(new byte[] { 0x00, 0x15, 0x5D, 0x01, 0x02, 0x03 });
        var ns = NetBiosPackets.ParseNodeStatus(w.ToArray());
        Assert.NotNull(ns);
        Assert.Equal("FILESRV01", ns!.ComputerName);
        Assert.Equal("WORKGROUP", ns.Workgroup);
        Assert.Equal("00:15:5D:01:02:03", ns.Mac);
    }

    [Fact]
    public void Snmpv3_discovery_request_and_report_roundtrip()
    {
        var req = SnmpPackets.V3DiscoveryRequest();
        Assert.Equal(0x30, req[0]);
        // Build a Report like an agent would: engine ID with Net-SNMP enterprise number 8072.
        var engine = new byte[] { 0x80, 0x00, 0x1F, 0x88, 0x80, 0x01, 0x02, 0x03, 0x04 };
        var usm = Ber.Sequence(Ber.OctetString(engine), Ber.Integer(1), Ber.Integer(100), Ber.OctetString(Array.Empty<byte>()), Ber.OctetString(Array.Empty<byte>()), Ber.OctetString(Array.Empty<byte>()));
        var report = Ber.Sequence(Ber.Integer(3), Ber.Sequence(Ber.Integer(1), Ber.Integer(65507), Ber.OctetString(new byte[] { 0 }), Ber.Integer(3)),
            Ber.OctetString(usm), Ber.Sequence(Ber.OctetString(engine), Ber.OctetString(Array.Empty<byte>()), Ber.Tagged(0xA8, Ber.Integer(1), Ber.Integer(0), Ber.Integer(0), Ber.Sequence())));
        var parsed = SnmpPackets.ParseEngineId(report);
        Assert.Equal(engine, parsed!);
        Assert.Equal(8072, SnmpPackets.EnterpriseNumber(parsed!));
        Assert.Null(SnmpPackets.ParseEngineId(new byte[] { 1, 2, 3 }));
    }

    [Fact]
    public void Dns_query_and_header()
    {
        var q = DnsPackets.Query("example.com", 1, recursionDesired: true, id: 0x1234);
        Assert.Equal((ushort)0x0100, BinaryPrimitives.ReadUInt16BigEndian(q.AsSpan(2)));
        var resp = (byte[])q.Clone();
        resp[2] = 0x81; resp[3] = 0x80; resp[7] = 1;
        var h = DnsPackets.ParseHeader(resp)!;
        Assert.True(h.IsResponse);
        Assert.True(h.RecursionAvailable);
        Assert.Equal(1, h.AnswerCount);
    }

    public static byte[] ServerHello(ushort version, ushort cipher, bool tls13 = false)
    {
        var body = new PacketWriter().U16BE(tls13 ? (ushort)0x0303 : version).Zeros(32).U8(0).U16BE(cipher).U8(0);
        if (tls13) body.U16BE(6).U16BE(0x002B).U16BE(2).U16BE(0x0304); else body.U16BE(0);
        var b = body.ToArray();
        var hs = new PacketWriter().U8(2).U24BE(b.Length).Bytes(b);
        // ServerHelloDone
        hs.U8(0x0E).U24BE(0);
        var h = hs.ToArray();
        return new PacketWriter().U8(0x16).U16BE(0x0303).U16BE((ushort)h.Length).Bytes(h).ToArray();
    }

    [Fact]
    public void Tls_server_hello_parsing()
    {
        var hs = TlsPackets.Parse(ServerHello(TlsVersions.Tls10, 0x000A));
        Assert.True(hs.GotServerHello);
        Assert.True(hs.Complete);
        Assert.Equal(TlsVersions.Tls10, hs.NegotiatedVersion);
        Assert.Equal((ushort)0x000A, hs.Cipher);
        var hs13 = TlsPackets.Parse(ServerHello(0, 0x1301, tls13: true));
        Assert.Equal(TlsVersions.Tls13, hs13.NegotiatedVersion);
        var alert = TlsPackets.Parse(new byte[] { 0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46 });
        Assert.True(alert.GotAlert);
        Assert.Equal(0x46, alert.AlertDescription);
    }

    [Fact]
    public void Tls_client_hello_is_valid_record()
    {
        var hello = TlsPackets.ClientHello(TlsVersions.Tls12, CipherSuites.Tls12AndBelow.Select(c => c.Id), "server.example");
        Assert.Equal(0x16, hello[0]);
        Assert.Equal(hello.Length - 5, BinaryPrimitives.ReadUInt16BigEndian(hello.AsSpan(3)));
        Assert.Equal(0x01, hello[5]);
        Assert.Contains("server.example", Encoding.ASCII.GetString(hello));
    }

    [Theory]
    [InlineData(0x000A, true, false)]
    [InlineData(0x0005, true, false)]
    [InlineData(0xC02F, false, true)]
    [InlineData(0x002F, false, false)]
    [InlineData(0x1301, false, true)]
    [InlineData(0x0003, true, false)]
    public void Cipher_classification(int id, bool weak, bool forwardSecret)
    {
        var c = CipherSuites.Lookup((ushort)id);
        Assert.Equal(weak, c.Weak);
        Assert.Equal(forwardSecret, c.ForwardSecret);
    }

    [Fact]
    public void Vnc_security_types()
    {
        Assert.Equal(new byte[] { 1, 2 }, VncPackets.ParseSecurityTypes(new byte[] { 2, 1, 2 })!.ToArray());
        Assert.Equal("None", VncPackets.SecurityTypeName(1));
    }

    [Fact]
    public void Http_parser_handles_chunked_bodies()
    {
        var raw = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
        Assert.True(HttpParser.IsComplete(raw));
        var r = HttpParser.Parse(raw, false)!;
        Assert.Equal(200, r.StatusCode);
        Assert.Equal("nginx/1.18.0", r.Header("server"));
        Assert.Equal("hello world", r.Body);
    }

    [Fact]
    public void Ipmi_presence_pong_detection()
    {
        Assert.True(IpmiPackets.IsPresencePong(new byte[] { 0x06, 0x00, 0xFF, 0x06, 0x00, 0x00, 0x11, 0xBE, 0x40, 0x00, 0x00, 0x10 }));
        Assert.False(IpmiPackets.IsPresencePong(IpmiPackets.AsfPresencePing));
    }
}
