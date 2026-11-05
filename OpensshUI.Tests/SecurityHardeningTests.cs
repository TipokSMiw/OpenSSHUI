using System.Security;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using OpensshUI.Data;
using OpensshUI.Models;
using OpensshUI.Services.Audit;
using OpensshUI.Services.Auth;
using OpensshUI.Services.Files;
using OpensshUI.Services.Groups;
using OpensshUI.Services.OpenSsh;
using OpensshUI.Services.Security;
using OpensshUI.Services.Users;

namespace OpensshUI.Tests;

public class SecurityHardeningTests
{
    [Theory]
    [InlineData("alice", true)]
    [InlineData("bob_123", true)]
    [InlineData("john-doe", true)]
    [InlineData("user.test", true)]
    [InlineData("/add", false)]
    [InlineData("-switch", false)]
    [InlineData("user;whoami", false)]
    [InlineData("user&calc", false)]
    [InlineData("user|dir", false)]
    [InlineData("user`hack`", false)]
    [InlineData("user$var", false)]
    [InlineData("user>out", false)]
    [InlineData("user<in", false)]
    [InlineData("user/slash", false)]
    [InlineData("user\\backslash", false)]
    [InlineData("../traverse", false)]
    [InlineData("..\\traverse", false)]
    [InlineData("CON", false)]
    [InlineData("PRN", false)]
    [InlineData("AUX", false)]
    [InlineData("NUL", false)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    public void SecurityValidator_ShouldValidateUsernameCorrectly(string username, bool expectedValid)
    {
        var (isValid, errorMessage) = SecurityValidator.ValidateUsername(username);

        Assert.Equal(expectedValid, isValid);
        if (!expectedValid)
        {
            Assert.NotNull(errorMessage);
        }
    }

    [Theory]
    [InlineData("Finance", true)]
    [InlineData("DevOps Team", true)]
    [InlineData("SFTP-Group_1", true)]
    [InlineData("/delete", false)]
    [InlineData("-bad", false)]
    [InlineData("Group;whoami", false)]
    [InlineData("Group&calc", false)]
    [InlineData("Group|dir", false)]
    [InlineData("Group/hack", false)]
    [InlineData("Group\\hack", false)]
    [InlineData("", false)]
    public void SecurityValidator_ShouldValidateGroupNameCorrectly(string groupName, bool expectedValid)
    {
        var (isValid, errorMessage) = SecurityValidator.ValidateGroupName(groupName);

        Assert.Equal(expectedValid, isValid);
        if (!expectedValid)
        {
            Assert.NotNull(errorMessage);
        }
    }

    [Theory]
    [InlineData(@"C:\", false)] // Drive root forbidden
    [InlineData(@"D:\", false)] // Drive root forbidden
    [InlineData(@"C:\Windows", false)]
    [InlineData(@"C:\Windows\System32", false)]
    [InlineData(@"C:\Program Files", false)]
    [InlineData(@"C:\Program Files (x86)", false)]
    [InlineData(@"C:\ProgramData\ssh", false)]
    [InlineData(@"D:\SFTPShare\Data", true)]
    [InlineData(@"C:\SFTPRoot\SharedFolder", true)]
    public void SecurityValidator_ShouldProtectSystemDirectories(string path, bool expectedSafe)
    {
        var (isSafe, errorMessage) = SecurityValidator.ValidateSafeCustomPath(path);

        Assert.Equal(expectedSafe, isSafe);
        if (!expectedSafe)
        {
            Assert.NotNull(errorMessage);
        }
    }

    [Fact]
    public void SecurityValidator_ShouldEscapeLdapFilterCorrectly()
    {
        var dangerousLdapInput = "admin*)(|(sAMAccountName=*)\\\0";
        var escaped = SecurityValidator.EscapeLdapFilter(dangerousLdapInput);

        Assert.DoesNotContain("*", escaped);
        Assert.DoesNotContain("(", escaped);
        Assert.DoesNotContain(")", escaped);
        Assert.Contains(@"\2a", escaped);
        Assert.Contains(@"\28", escaped);
        Assert.Contains(@"\29", escaped);
        Assert.Contains(@"\5c", escaped);
        Assert.Contains(@"\00", escaped);
    }

    [Theory]
    [InlineData("../../Windows")]
    [InlineData("..\\..\\Windows")]
    [InlineData("../test")]
    [InlineData("..\\test")]
    [InlineData("CON")]
    [InlineData("bad;user")]
    [InlineData("/hack")]
    public async Task SecureFileBrowserService_ShouldBlockUsernamePathTraversal(string maliciousUser)
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), "SFTPRootAuditTest_" + Guid.NewGuid().ToString("N"));
        var service = new SecureFileBrowserService(NullLogger<SecureFileBrowserService>.Instance, tempRoot);

        try
        {
            await Assert.ThrowsAsync<SecurityException>(() => service.ListItemsAsync(maliciousUser, ""));
            await Assert.ThrowsAsync<SecurityException>(() => service.CreateDirectoryAsync(maliciousUser, "", "test"));
            await Assert.ThrowsAsync<SecurityException>(() => service.DeleteItemAsync(maliciousUser, "test.txt"));
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
    public void SshKeyConverter_ShouldSanitizeCrlfInKeyComment()
    {
        // Malicious key with newline injection in the comment attempting to append an authorized_keys option
        var maliciousKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG1N8z5O7U8N9gO7oP3U8X4yqR1zT8jL2wP5qK9eR4tY test\r\ncommand=\"powershell.exe\" ssh-rsa AAAAB3...";

        var result = SshKeyConverter.ParseAndNormalizeKey(maliciousKey);

        Assert.True(result.IsSuccess);
        Assert.DoesNotContain("\r", result.RawPublicKey);
        Assert.DoesNotContain("\n", result.RawPublicKey);
        Assert.DoesNotContain("\r", result.Comment);
        Assert.DoesNotContain("\n", result.Comment);
    }

    [Fact]
    public void OpenSshServiceManager_ShouldSanitizeDirectiveInjectionInManagedBlock()
    {
        var manager = new OpenSshServiceManager(NullLogger<OpenSshServiceManager>.Instance);

        var maliciousRules = new List<DirectChrootRule>
        {
            new DirectChrootRule
            {
                IsGroup = false,
                Identifier = "alice\r\nPermitRootLogin yes\r\n",
                RootPath = "D:\\Shared\r\nAuthorizedKeysCommand evil.exe\r\n"
            }
        };

        var block = manager.GenerateManagedBlock(maliciousRules);

        // Lines should NOT contain raw injected directives on separate lines
        var lines = block.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
        Assert.DoesNotContain(lines, l => l.Trim().Equals("PermitRootLogin yes", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(lines, l => l.Trim().StartsWith("AuthorizedKeysCommand", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task LdapAuthService_ShouldDetectDefaultFallbackAdminPassword()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();

        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(connection)
            .Options;

        using (var initDb = new AppDbContext(options))
        {
            initDb.Database.EnsureCreated();
        }

        var dbFactory = new TestDbContextFactory(options);
        var protectionService = new ProtectionServiceTestStub();
        var ldapService = new LdapAuthService(dbFactory, protectionService, NullLogger<LdapAuthService>.Instance);

        // Fresh config should default to Admin@123456
        var isDefault = await ldapService.IsUsingDefaultFallbackPasswordAsync();
        Assert.True(isDefault);

        // Update password to something new
        var config = await ldapService.GetConfigAsync();
        await ldapService.SaveConfigAsync(config, newFallbackAdminPassword: "NewSuperSecurePassword!2026");

        var isStillDefault = await ldapService.IsUsingDefaultFallbackPasswordAsync();
        Assert.False(isStillDefault);
    }

    [Theory]
    [InlineData("Administrator")]
    [InlineData("administrator")]
    [InlineData("Guest")]
    [InlineData("SYSTEM")]
    [InlineData("LocalService")]
    [InlineData("NetworkService")]
    [InlineData("DefaultAccount")]
    [InlineData("WDAGUtilityAccount")]
    [InlineData("sshd")]
    [InlineData("krbtgt")]
    [InlineData(".hiddenuser")]
    public void SecurityValidator_ShouldBlockProtectedWindowsAccounts(string protectedUsername)
    {
        var (isValid, errorMessage) = SecurityValidator.ValidateUsername(protectedUsername);

        Assert.False(isValid);
        Assert.NotNull(errorMessage);
    }

    [Theory]
    [InlineData("SFTP-Users")]
    [InlineData("Administrators")]
    [InlineData("Users")]
    [InlineData("Guests")]
    [InlineData("Remote Desktop Users")]
    [InlineData("Backup Operators")]
    public void SecurityValidator_ShouldBlockProtectedWindowsGroups(string protectedGroup)
    {
        var (isValid, errorMessage) = SecurityValidator.ValidateGroupName(protectedGroup);

        Assert.False(isValid);
        Assert.NotNull(errorMessage);

        // Internal EnsureSftpUsersGroup with allowDefaultSftpUsersGroup=true should still allow SFTP-Users
        if (string.Equals(protectedGroup, "SFTP-Users", StringComparison.OrdinalIgnoreCase))
        {
            var (allowedInternal, _) = SecurityValidator.ValidateGroupName(protectedGroup, allowDefaultSftpUsersGroup: true);
            Assert.True(allowedInternal);
        }
    }

    [Theory]
    [InlineData("StrongPass#2026", true)]
    [InlineData("/delete", false)]
    [InlineData("/active:no", false)]
    [InlineData("-switch", false)]
    [InlineData("pass\r\nword", false)]
    [InlineData("pass\0word", false)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    public void SecurityValidator_ShouldValidateWindowsPasswordAgainstSwitchInjection(string password, bool expectedValid)
    {
        var (isValid, _) = SecurityValidator.ValidateWindowsPassword(password);
        Assert.Equal(expectedValid, isValid);
    }

    [Theory]
    [InlineData(@"\\127.0.0.1\c$\Windows")]
    [InlineData(@"\\server\share\folder")]
    [InlineData(@"\\?\C:\Windows")]
    [InlineData(@"\\.\C:\Windows")]
    [InlineData(@"D:\Share&calc.exe")]
    [InlineData(@"D:\Share|whoami")]
    [InlineData(@"D:\Share;dir")]
    [InlineData(@"D:\Share%PATH%")]
    [InlineData(@"D:\Share""Quote")]
    public void SecurityValidator_ShouldBlockUncDeviceAndShellInjectionPaths(string unsafePath)
    {
        var (isSafe, errorMessage) = SecurityValidator.ValidateSafeCustomPath(unsafePath);

        Assert.False(isSafe);
        Assert.NotNull(errorMessage);
    }

    [Fact]
    public void SshKeyConverter_ShouldRejectPuttyRfc4716KeyWithInjectedKeyType()
    {
        // Craft a malicious RFC 4716 binary blob where the embedded keyType string attempts authorized_keys option injection
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        var injectedKeyType = Encoding.ASCII.GetBytes("command=\"calc.exe\" ssh-rsa");
        int len = injectedKeyType.Length;
        writer.Write(new byte[] { (byte)(len >> 24), (byte)(len >> 16), (byte)(len >> 8), (byte)len });
        writer.Write(injectedKeyType);
        writer.Write(new byte[] { 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x01 });

        var maliciousBase64 = Convert.ToBase64String(ms.ToArray());
        var puttyPayload = $@"---- BEGIN SSH2 PUBLIC KEY ----
Comment: ""injected-key""
{maliciousBase64}
---- END SSH2 PUBLIC KEY ----";

        var result = SshKeyConverter.ParseAndNormalizeKey(puttyPayload);

        Assert.False(result.IsSuccess);
        Assert.Contains("Unsupported or invalid SSH key type", result.ErrorMessage);
    }

    [Fact]
    public async Task LdapAuthService_ShouldEncryptBindDnAndEnforceBruteForceLockout()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();

        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(connection)
            .Options;

        using (var initDb = new AppDbContext(options))
        {
            initDb.Database.EnsureCreated();
        }

        var dbFactory = new TestDbContextFactory(options);
        var protectionService = new ProtectionServiceTestStub();
        var ldapService = new LdapAuthService(dbFactory, protectionService, NullLogger<LdapAuthService>.Instance);

        var config = await ldapService.GetConfigAsync();
        config.EncryptedBindDn = "CN=svc_sftp,OU=ServiceAccounts,DC=corp,DC=local";
        await ldapService.SaveConfigAsync(config, newBindPassword: "SecretBindPassword");

        // Verify raw value in DB is encrypted with IProtectionService
        using (var verifyDb = new AppDbContext(options))
        {
            var rawRow = await verifyDb.LdapConfigs.AsNoTracking().FirstAsync();
            Assert.Equal("ENC_CN=svc_sftp,OU=ServiceAccounts,DC=corp,DC=local", rawRow.EncryptedBindDn);
            Assert.Equal("ENC_SecretBindPassword", rawRow.EncryptedBindPassword);
        }

        // Verify GetConfigAsync transparently decrypts EncryptedBindDn for application use
        var loadedConfig = await ldapService.GetConfigAsync();
        Assert.Equal("CN=svc_sftp,OU=ServiceAccounts,DC=corp,DC=local", loadedConfig.EncryptedBindDn);

        // Verify Brute-Force Lockout after 5 failed attempts
        var testAdminUser = "admin";
        LdapAuthService.ResetLockoutForUser(testAdminUser);

        for (int i = 0; i < 5; i++)
        {
            var badAttempt = await ldapService.AuthenticateAsync(testAdminUser, "WrongPassword_" + i);
            Assert.False(badAttempt.IsSuccess);
        }

        // 6th attempt even with the CORRECT password must be rejected while locked out
        var lockedAttempt = await ldapService.AuthenticateAsync(testAdminUser, "Admin@123456");
        Assert.False(lockedAttempt.IsSuccess);
        Assert.Contains("temporarily locked", lockedAttempt.ErrorMessage, StringComparison.OrdinalIgnoreCase);

        // Reset lockout and verify valid login succeeds again
        LdapAuthService.ResetLockoutForUser(testAdminUser);
        var validAttempt = await ldapService.AuthenticateAsync(testAdminUser, "Admin@123456");
        Assert.True(validAttempt.IsSuccess);
        Assert.True(validAttempt.IsAdmin);
    }

    [Fact]
    public async Task SftpUserService_DeleteUserAsync_ShouldDetachGroupJunctionsBeforeDeletingUserFiles()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();

        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(connection)
            .Options;

        using (var initDb = new AppDbContext(options))
        {
            initDb.Database.EnsureCreated();
            var grp = new SftpGroup
            {
                Id = "grp-shared",
                Name = "SharedDocs",
                RootPath = @"D:\SharedDocs",
                AccessMode = SftpAccessMode.VirtualFolder
            };
            var usr = new SftpUser
            {
                Username = "junction_user",
                AccountType = SftpAccountType.LocalWindows
            };
            usr.UserGroups.Add(new SftpUserGroup { Username = "junction_user", GroupId = "grp-shared", Group = grp });
            initDb.SftpGroups.Add(grp);
            initDb.SftpUsers.Add(usr);
            await initDb.SaveChangesAsync();
        }

        var dbFactory = new TestDbContextFactory(options);
        var aclProvisioner = Substitute.For<INativeAclProvisioner>();
        var windowsUserManager = Substitute.For<IWindowsUserManager>();
        var sshServiceManager = Substitute.For<IOpenSshServiceManager>();
        var groupService = Substitute.For<ISftpGroupService>();
        var auditService = Substitute.For<IAuditService>();
        var sshKeyGenerator = Substitute.For<ISshKeyGenerator>();

        sshServiceManager.SftpRoot.Returns(@"C:\SFTPRoot");
        sshServiceManager.KeysPath.Returns(@"C:\ProgramData\ssh\keys");

        var userService = new SftpUserService(
            dbFactory,
            aclProvisioner,
            windowsUserManager,
            sshServiceManager,
            groupService,
            auditService,
            sshKeyGenerator,
            NullLogger<SftpUserService>.Instance);

        var (success, _) = await userService.DeleteUserAsync("junction_user", deleteFiles: true);

        Assert.True(success);
        var expectedJunctionPath = Path.Combine(@"C:\SFTPRoot", "junction_user", "files", "SharedDocs");
        aclProvisioner.Received(1).RemoveDirectoryJunction(expectedJunctionPath);
    }

    [Theory]
    [InlineData("not-an-int.salt.key")]
    [InlineData("-500.AAAA.BBBB")]
    [InlineData("50000000.AAAA.BBBB")]
    [InlineData("100000.invalid_base64!.invalid_base64!")]
    public void PasswordHasher_ShouldReturnFalseSafelyOnMalformedHash(string malformedHash)
    {
        var result = PasswordHasher.VerifyPassword("SomePassword", malformedHash);
        Assert.False(result);
    }

    private class TestDbContextFactory : IDbContextFactory<AppDbContext>
    {
        private readonly DbContextOptions<AppDbContext> _options;
        public TestDbContextFactory(DbContextOptions<AppDbContext> options) => _options = options;
        public AppDbContext CreateDbContext() => new AppDbContext(_options);
        public Task<AppDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new AppDbContext(_options));
    }

    private class ProtectionServiceTestStub : IProtectionService
    {
        public string? Protect(string? clearText) => clearText == null ? null : $"ENC_{clearText}";
        public string? Unprotect(string? cipherText) => cipherText?.Replace("ENC_", "");
    }
}
