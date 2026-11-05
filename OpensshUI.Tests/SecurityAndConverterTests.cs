using System.Security;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using OpensshUI.Services.Files;
using OpensshUI.Services.OpenSsh;
using OpensshUI.Services.Security;

namespace OpensshUI.Tests;

public class SecurityAndConverterTests
{
    [Fact]
    public void SshKeyConverter_ShouldParseStandardOpenSshKey()
    {
        // Sample standard OpenSSH ed25519 public key (valid base64 length)
        var openSshKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG1N8z5O7U8N9gO7oP3U8X4yqR1zT8jL2wP5qK9eR4tY test@host";

        var result = SshKeyConverter.ParseAndNormalizeKey(openSshKey);

        Assert.True(result.IsSuccess);
        Assert.Equal("ssh-ed25519", result.KeyType);
        Assert.StartsWith("SHA256:", result.FingerprintSha256);
        Assert.Equal("test@host", result.Comment);
        Assert.Contains("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA", result.RawPublicKey);
    }

    [Fact]
    public void SshKeyConverter_ShouldConvertPuttyRfc4716KeyToOpenSsh()
    {
        // Create a valid RFC 4716 blob with real ssh-rsa wire format
        // Wire format: 4-byte len (7) + "ssh-rsa" + 4-byte exp len + exponent + 4-byte mod len + modulus
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);
        
        // Key type length: 7 (big endian)
        writer.Write(new byte[] { 0x00, 0x00, 0x00, 0x07 });
        writer.Write(System.Text.Encoding.ASCII.GetBytes("ssh-rsa"));
        // Exponent length: 3 (big endian)
        writer.Write(new byte[] { 0x00, 0x00, 0x00, 0x03 });
        writer.Write(new byte[] { 0x01, 0x00, 0x01 }); // 65537
        // Modulus dummy length: 4 (big endian)
        writer.Write(new byte[] { 0x00, 0x00, 0x00, 0x04 });
        writer.Write(new byte[] { 0x12, 0x34, 0x56, 0x78 });

        var validBase64 = Convert.ToBase64String(ms.ToArray());

        var puttyKey = $@"---- BEGIN SSH2 PUBLIC KEY ----
Comment: ""putty-test-key""
{validBase64}
---- END SSH2 PUBLIC KEY ----";

        var result = SshKeyConverter.ParseAndNormalizeKey(puttyKey);

        Assert.True(result.IsSuccess);
        Assert.Equal("ssh-rsa", result.KeyType);
        Assert.StartsWith("ssh-rsa ", result.RawPublicKey);
        Assert.DoesNotContain("\n", result.RawPublicKey);
        Assert.DoesNotContain("\r", result.RawPublicKey);
        Assert.StartsWith("SHA256:", result.FingerprintSha256);
        Assert.Equal("putty-test-key", result.Comment);
    }

    [Fact]
    public void SshKeyConverter_ShouldRejectInvalidKey()
    {
        var invalidKey = "invalid-random-gibberish-string";
        var result = SshKeyConverter.ParseAndNormalizeKey(invalidKey);

        Assert.False(result.IsSuccess);
        Assert.NotNull(result.ErrorMessage);
    }

    [Theory]
    [InlineData("../../Windows/System32")]
    [InlineData("../../../")]
    [InlineData("..\\..\\Windows")]
    [InlineData("files/../../secret.txt")]
    [InlineData("/../../etc/passwd")]
    public async Task SecureFileBrowserService_ShouldBlockPathTraversal(string traversalPath)
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), "SFTPRootTest_" + Guid.NewGuid().ToString("N"));
        var service = new SecureFileBrowserService(NullLogger<SecureFileBrowserService>.Instance, tempRoot);

        try
        {
            await Assert.ThrowsAsync<SecurityException>(() => service.ListItemsAsync("testuser", traversalPath));
            await Assert.ThrowsAsync<SecurityException>(() => service.CreateDirectoryAsync("testuser", traversalPath, "hack"));
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                try { Directory.Delete(tempRoot, true); } catch { }
            }
        }
    }

    [Fact]
    public void PasswordHasher_ShouldHashAndVerifyCorrectly()
    {
        var password = "SecureAdminPassword!2026";
        var hash = PasswordHasher.HashPassword(password);

        Assert.NotNull(hash);
        Assert.Contains(".", hash);

        // Verify correct password
        var isValid = PasswordHasher.VerifyPassword(password, hash);
        Assert.True(isValid);

        // Verify wrong password
        var isInvalid = PasswordHasher.VerifyPassword("WrongPassword", hash);
        Assert.False(isInvalid);
    }
}
