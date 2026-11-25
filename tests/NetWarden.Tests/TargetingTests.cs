using System.Net;
using NetWarden.Core.Targeting;
using Xunit;

namespace NetWarden.Tests;

public class TargetingTests
{
    [Theory]
    [InlineData("192.168.1.0/24", 254)]
    [InlineData("10.0.0.0/30", 2)]
    [InlineData("10.0.0.0/31", 2)]
    [InlineData("10.0.0.7/32", 1)]
    [InlineData("172.16.0.0/16", 65534)]
    public void Cidr_expands_to_expected_host_count(string cidr, int expected)
    {
        var spec = TargetParser.Parse(cidr);
        Assert.Equal(TargetKind.Cidr, spec.Kind);
        Assert.Equal((long)expected, spec.Count);
        Assert.Equal(expected, TargetParser.ExpandAddresses(new[] { spec }).Count);
    }

    [Fact]
    public void Cidr_skips_network_and_broadcast()
    {
        var list = TargetParser.ExpandAddresses(new[] { TargetParser.Parse("192.168.5.77/24") });
        Assert.Equal("192.168.5.1", list[0].ToString());
        Assert.Equal("192.168.5.254", list[^1].ToString());
    }

    [Fact]
    public void Full_and_short_ranges_parse()
    {
        var full = TargetParser.Parse("10.0.0.250-10.0.1.5");
        Assert.Equal(12L, full.Count);
        var shortRange = TargetParser.Parse("10.0.0.1-50");
        Assert.Equal(50L, shortRange.Count);
        Assert.True(shortRange.Contains(IPAddress.Parse("10.0.0.50")));
        Assert.False(shortRange.Contains(IPAddress.Parse("10.0.0.51")));
    }

    [Theory]
    [InlineData("nas.local", TargetKind.HostName)]
    [InlineData("fileserver", TargetKind.HostName)]
    [InlineData("192.168.1.10", TargetKind.SingleAddress)]
    [InlineData("fe80::1", TargetKind.SingleAddress)]
    public void Single_targets_are_classified(string text, TargetKind kind)
        => Assert.Equal(kind, TargetParser.Parse(text).Kind);

    [Theory]
    [InlineData("192.168.1.0/33")]
    [InlineData("10.0.0.50-10.0.0.1")]
    [InlineData("300.1.1.1")]
    [InlineData("bad host name!")]
    [InlineData("2001:db8::/64")]
    public void Invalid_targets_throw(string text)
        => Assert.Throws<FormatException>(() => TargetParser.Parse(text));

    [Fact]
    public void Lists_accept_commas_lines_and_comments()
    {
        var list = TargetParser.ParseList("10.0.0.1, 10.0.0.2\n# printers\n10.0.1.0/30");
        Assert.Equal(3, list.Count);
        Assert.Equal(4L, TargetParser.CountAddresses(list));
    }

    [Fact]
    public void Expansion_limit_is_enforced()
        => Assert.Throws<InvalidOperationException>(() => TargetParser.ExpandAddresses(new[] { TargetParser.Parse("10.0.0.0/15") }));

    [Theory]
    [InlineData("10.1.2.3", true)]
    [InlineData("172.31.255.1", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("192.168.0.1", true)]
    [InlineData("100.64.1.1", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("fd00::1", true)]
    [InlineData("2001:4860:4860::8888", false)]
    public void Private_address_detection(string ip, bool isPrivate)
        => Assert.Equal(isPrivate, AddressClassifier.IsPrivate(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("192.168.1.0/24", false)]
    [InlineData("10.0.0.0/8", false)]
    [InlineData("8.8.8.0/24", true)]
    [InlineData("192.168.255.0-192.169.0.10", true)]
    public void Public_range_detection(string spec, bool expectPublic)
        => Assert.Equal(expectPublic, AddressClassifier.ContainsPublic(TargetParser.Parse(spec)));

    [Fact]
    public void Scope_requires_authorization()
    {
        var scope = new ScanScope { Targets = "192.168.1.0/24" };
        Assert.Throws<ScopeException>(() => scope.Validate());
        scope.Authorized = true;
        Assert.Empty(scope.Validate());
    }

    [Fact]
    public void Scope_with_public_targets_needs_acknowledgement()
    {
        var scope = new ScanScope { Targets = "203.0.113.10", Authorized = true };
        Assert.Throws<ScopeException>(() => scope.Validate());
        scope.PublicAddressesAcknowledged = true;
        Assert.Single(scope.Validate());
    }

    [Fact]
    public void Scope_exclusions_are_honoured()
    {
        var scope = new ScanScope { Targets = "192.168.1.0/24", Exclusions = "192.168.1.60\n192.168.1.200-210", Authorized = true };
        Assert.True(scope.Allows(IPAddress.Parse("192.168.1.10")));
        Assert.False(scope.Allows(IPAddress.Parse("192.168.1.60")));
        Assert.False(scope.Allows(IPAddress.Parse("192.168.1.205")));
        Assert.False(scope.Allows(IPAddress.Parse("10.0.0.1")));
    }

    [Theory]
    [InlineData("top100", 100)]
    [InlineData("22,80,443", 3)]
    [InlineData("8000-8010, 22", 12)]
    [InlineData("all", 65535)]
    [InlineData("", 0)]
    public void Port_specs_parse(string spec, int expected)
        => Assert.Equal(expected, NetWarden.Core.Targeting.PortSpec.Parse(spec).Count);

    [Fact]
    public void Top1000_list_is_about_a_thousand_ports()
        => Assert.InRange(NetWarden.Core.Targeting.PortSpec.Parse("top1000").Count, 990, 1010);

    [Theory]
    [InlineData("0")]
    [InlineData("70000")]
    [InlineData("http")]
    public void Invalid_port_specs_are_rejected(string spec)
        => Assert.False(NetWarden.Core.Targeting.PortSpec.TryValidate(spec, out _));

    [Fact]
    public void Subnet_key_groups_by_24()
        => Assert.Equal("10.1.2.0/24", IpMath.SubnetKey("10.1.2.200"));
}
