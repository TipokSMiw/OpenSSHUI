using Microsoft.Extensions.Logging.Abstractions;
using OpensshUI.Services.OpenSsh;
using Xunit;

namespace OpensshUI.Tests;

public class SshKeyGeneratorTests
{
    private readonly SshKeyGenerator _generator = new(NullLogger<SshKeyGenerator>.Instance);

    [Fact]
    public async Task GenerateKeyPairAsync_Ed25519_GeneratesValidKeyPairAndCleansUp()
    {
        var result = await _generator.GenerateKeyPairAsync("ed25519", "test-automation-ed25519");

        Assert.True(result.Success, $"Failed with: {result.ErrorMessage}");
        Assert.Equal("ssh-ed25519", result.KeyType);
        Assert.StartsWith("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5", result.PublicKeyOpenSsh);
        Assert.Contains("BEGIN OPENSSH PRIVATE KEY", result.PrivateKeyPem);
        Assert.NotEmpty(result.FingerprintSha256);
        Assert.Equal("test-automation-ed25519", result.Comment);
    }

    [Fact]
    public async Task GenerateKeyPairAsync_Rsa_GeneratesValid4096BitKeyPair()
    {
        var result = await _generator.GenerateKeyPairAsync("rsa", "test-automation-rsa");

        Assert.True(result.Success);
        Assert.Equal("ssh-rsa", result.KeyType);
        Assert.StartsWith("ssh-rsa AAAAB3NzaC1yc2E", result.PublicKeyOpenSsh);
        Assert.Contains("PRIVATE KEY", result.PrivateKeyPem);
        Assert.NotEmpty(result.FingerprintSha256);
        Assert.Equal("test-automation-rsa", result.Comment);
    }

    [Theory]
    [InlineData("dsa")]
    [InlineData("ecdsa-sk")]
    [InlineData("../invalid")]
    [InlineData(";rmdir /s /q")]
    public async Task GenerateKeyPairAsync_UnsupportedOrMaliciousAlgorithm_ReturnsFailure(string badAlgo)
    {
        var result = await _generator.GenerateKeyPairAsync(badAlgo);

        Assert.False(result.Success);
        Assert.NotNull(result.ErrorMessage);
        Assert.Contains("Unsupported key algorithm", result.ErrorMessage);
    }
}
