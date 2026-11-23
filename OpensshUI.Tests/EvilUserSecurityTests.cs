using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security;
using System.Text;
using FluentAssertions;
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
using Xunit;

namespace OpensshUI.Tests;

/// <summary>
/// Cross-Component & "Evil User" Security Test Suite (aligned with AGENT.md §3, §4, and §8 OWASP Top 10).
/// Simulates adversarial/mischievous usage patterns across interacting modules.
/// </summary>
public class EvilUserSecurityTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<AppDbContext> _dbOptions;
    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly string _tempDir;

    public EvilUserSecurityTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        _dbOptions = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .Options;

        using (var initDb = new AppDbContext(_dbOptions))
        {
            initDb.Database.EnsureCreated();
        }

        _dbFactory = Substitute.For<IDbContextFactory<AppDbContext>>();
        _dbFactory.CreateDbContextAsync(Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromResult(new AppDbContext(_dbOptions)));
        _dbFactory.CreateDbContext()
            .Returns(_ => new AppDbContext(_dbOptions));

        _tempDir = Path.Combine(Path.GetTempPath(), $"OpensshUI_EvilUserTest_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        LdapAuthService.ResetLockoutForUser("target_admin");
        LdapAuthService.ResetLockoutForUser("evil_bob");
        LdapAuthService.ResetLockoutForUser("auditor_jane");
        LdapAuthService.ResetLockoutForUser("unregistered_ad_user");
        _connection.Dispose();

        try
        {
            if (Directory.Exists(_tempDir))
            {
                Directory.Delete(_tempDir, recursive: true);
            }
        }
        catch { }
    }

    // =========================================================================
    // Domain A: AD Username Format Variations, Fallback Guard & Brute-Force Evasion
    // =========================================================================

    [Theory]
    [InlineData("alice", "alice")]
    [InlineData("CORP\\alice", "alice")]
    [InlineData("alice@corp.local", "alice")]
    [InlineData("  CORP\\alice@corp.local  ", "alice")]
    public void ExtractCanonicalUsername_ShouldStripDomainPrefixAndUpnSuffix(string rawInput, string expectedCanonical)
    {
        var canonical = SecurityValidator.ExtractCanonicalUsername(rawInput);
        canonical.Should().Be(expectedCanonical);
    }

    [Theory]
    [InlineData("evil_bob")]
    [InlineData("CORP\\evil_bob")]
    [InlineData("evil_bob@corp.local")]
    public async Task AuthenticateAsync_WhenAdminIsDeactivated_ShouldBlockLoginViaDomainPrefixOrUpnSuffix(string loginAttemptName)
    {
        var audit = Substitute.For<IAuditService>();
        var protection = Substitute.For<IProtectionService>();
        var webAdminService = new WebAdminService(_dbFactory, audit, NullLogger<WebAdminService>.Instance);
        var authService = new LdapAuthService(_dbFactory, protection, NullLogger<LdapAuthService>.Instance);

        // Enable LDAP so Step 3 fallback would be reachable if Step 1 were bypassed
        var cfg = await authService.GetConfigAsync();
        cfg.IsLdapEnabled = true;
        cfg.AdminGroup = ""; // Even with blank AdminGroup
        await authService.SaveConfigAsync(cfg);

        // Register 'evil_bob' and then deactivate him
        await webAdminService.CreateLocalAdminAsync("evil_bob", "Evil Bob", null, "Password@123", WebAdminRole.Operator, "admin");
        var bob = await webAdminService.GetAdminByUsernameAsync("evil_bob");
        await webAdminService.ToggleStatusAsync(bob!.Id, "admin");

        // Act: Evil Bob tries logging in with DOMAIN\evil_bob or evil_bob@corp.local
        var result = await authService.AuthenticateAsync(loginAttemptName, "Password@123");

        // Assert: Must be caught by Step 1 deactivation guard and never reach Step 3
        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Contain("ระงับการใช้งาน");
    }

    [Theory]
    [InlineData("auditor_jane")]
    [InlineData("CORP\\auditor_jane")]
    [InlineData("auditor_jane@corp.local")]
    public async Task AuthenticateAsync_WhenAdminIsAuditor_ShouldPreserveAuditorRoleViaDomainPrefixOrUpnSuffix(string loginAttemptName)
    {
        var audit = Substitute.For<IAuditService>();
        var protection = Substitute.For<IProtectionService>();
        var webAdminService = new WebAdminService(_dbFactory, audit, NullLogger<WebAdminService>.Instance);
        var authService = new LdapAuthService(_dbFactory, protection, NullLogger<LdapAuthService>.Instance);

        await webAdminService.CreateLocalAdminAsync("auditor_jane", "Jane Auditor", null, "Password@123", WebAdminRole.Auditor, "admin");

        var result = await authService.AuthenticateAsync(loginAttemptName, "Password@123");

        result.IsSuccess.Should().BeTrue();
        result.Username.Should().Be("auditor_jane");
        result.Role.Should().Be(WebAdminRole.Auditor, "logging in with DOMAIN\\user or user@domain must not escalate role.");
    }

    [Fact]
    public async Task AuthenticateAsync_BruteForceLockout_ShouldShareQuotaAcrossUsernameFormatVariations()
    {
        var audit = Substitute.For<IAuditService>();
        var protection = Substitute.For<IProtectionService>();
        var webAdminService = new WebAdminService(_dbFactory, audit, NullLogger<WebAdminService>.Instance);
        var authService = new LdapAuthService(_dbFactory, protection, NullLogger<LdapAuthService>.Instance);

        await webAdminService.CreateLocalAdminAsync("target_admin", "Target Admin", null, "CorrectPass@123", WebAdminRole.SuperAdmin, "system");

        // Evil user alternates formats to try to get 3x brute-force attempts
        string[] variations =
        {
            "target_admin",
            "target_admin@corp.local",
            "CORP\\target_admin",
            "TARGET_ADMIN@corp.local",
            "corp\\TARGET_ADMIN"
        };

        foreach (var variant in variations)
        {
            var badAttempt = await authService.AuthenticateAsync(variant, "WrongPass!");
            badAttempt.IsSuccess.Should().BeFalse();
        }

        // 6th attempt with the CORRECT password must be locked out regardless of format used
        var sixthAttempt = await authService.AuthenticateAsync("target_admin", "CorrectPass@123");
        sixthAttempt.IsSuccess.Should().BeFalse();
        sixthAttempt.ErrorMessage.Should().ContainEquivalentOf("temporarily locked");
    }

    [Fact]
    public async Task AuthenticateAsync_WhenUnregisteredUserAndAdminGroupBlank_ShouldRejectFallbackLogin()
    {
        var protection = Substitute.For<IProtectionService>();
        var authService = new LdapAuthService(_dbFactory, protection, NullLogger<LdapAuthService>.Instance);

        var cfg = await authService.GetConfigAsync();
        cfg.IsLdapEnabled = true;
        cfg.AdminGroup = "   "; // Blank AdminGroup
        await authService.SaveConfigAsync(cfg);

        var result = await authService.AuthenticateAsync("unregistered_ad_user@corp.local", "SomePassword123");

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Contain("no fallback AD Admin Group is configured");
    }

    [Fact]
    public async Task WebAdminService_SelfLockoutAndDuplicateCheck_ShouldEnforceCanonicalUsername()
    {
        var audit = Substitute.For<IAuditService>();
        var webAdminService = new WebAdminService(_dbFactory, audit, NullLogger<WebAdminService>.Instance);

        // 1. Create AD admin with DOMAIN\alice -> stored canonically as 'alice'
        var create1 = await webAdminService.CreateAdAdminAsync("CORP\\alice", "Alice", null, WebAdminRole.SuperAdmin, "system");
        create1.Success.Should().BeTrue();

        // 2. Trying to create duplicate with alice@corp.local must fail
        var create2 = await webAdminService.CreateAdAdminAsync("alice@corp.local", "Alice 2", null, WebAdminRole.Operator, "system");
        create2.Success.Should().BeFalse();

        // 3. Self-lockout guard when operatorUser is passed as 'CORP\alice' or 'alice@corp.local'
        var alice = await webAdminService.GetAdminByUsernameAsync("alice");
        var toggleSelf = await webAdminService.ToggleStatusAsync(alice!.Id, "alice@corp.local");
        toggleSelf.Success.Should().BeFalse();
        toggleSelf.Message.Should().Contain("บัญชีของตนเอง");

        var deleteSelf = await webAdminService.DeleteAdminAsync(alice.Id, "CORP\\alice");
        deleteSelf.Success.Should().BeFalse();
        deleteSelf.Message.Should().Contain("บัญชีของตนเอง");
    }

    // =========================================================================
    // Domain B: Live Session Revocation, Role Demotion & Bounded State
    // =========================================================================

    [Fact]
    public async Task UserSessionState_WhenAdminDemotedOrDeactivated_ShouldImmediatelyRevokeOrDowngradeActiveSession()
    {
        var audit = Substitute.For<IAuditService>();
        var webAdminService = new WebAdminService(_dbFactory, audit, NullLogger<WebAdminService>.Instance);

        await webAdminService.CreateLocalAdminAsync("super_a", "Super A", null, "Password@123", WebAdminRole.SuperAdmin, "system");
        await webAdminService.CreateLocalAdminAsync("super_b", "Super B", null, "Password@123", WebAdminRole.SuperAdmin, "super_a");
        var adminB = await webAdminService.GetAdminByUsernameAsync("super_b");

        // Admin B logs into an active Blazor circuit
        var sessionB = new UserSessionState();
        sessionB.SetUser("super_b", "Super B", true, WebAdminRole.SuperAdmin);
        sessionB.CanManageSystem.Should().BeTrue();
        sessionB.CanManageSftp.Should().BeTrue();

        // 1. Admin A demotes Admin B to Auditor while Admin B's session is still open
        var demoteRes = await webAdminService.UpdateRoleAsync(adminB!.Id, WebAdminRole.Auditor, "super_a");
        demoteRes.Success.Should().BeTrue();

        // Session B must immediately lose system & SFTP write privileges without waiting 8 hours
        sessionB.Role.Should().Be(WebAdminRole.Auditor);
        sessionB.CanManageSystem.Should().BeFalse();
        sessionB.CanManageSftp.Should().BeFalse();
        sessionB.IsReadOnly.Should().BeTrue();

        // 2. Admin A deactivates Admin B
        var deactivateRes = await webAdminService.ToggleStatusAsync(adminB.Id, "super_a");
        deactivateRes.Success.Should().BeTrue();

        // Session B must immediately become unauthenticated
        sessionB.IsAuthenticated.Should().BeFalse();
        sessionB.CanManageSystem.Should().BeFalse();
        sessionB.CanManageSftp.Should().BeFalse();
    }

    [Fact]
    public void UserSessionState_OverrideCache_ShouldEnforceBoundedCapacity()
    {
        for (int i = 0; i < 1250; i++)
        {
            UserSessionState.NotifyUserStatusChanged($"bounded_test_user_{i}", false, WebAdminRole.Auditor);
        }

        UserSessionState.GetTrackedOverrideCount().Should().BeLessThanOrEqualTo(1000);
    }

    // =========================================================================
    // Domain C: SSH Key Wire-Format Spoofing, Truncated Blobs & Comment Injection
    // =========================================================================

    [Fact]
    public void SshKeyConverter_WhenEd25519PrefixWrapsSshDssOrRsaWirePayload_ShouldRejectSpoofedKey()
    {
        // Construct an RFC 4251 binary payload whose internal header says "ssh-dss"
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);
        var dssHeader = Encoding.ASCII.GetBytes("ssh-dss");
        int len = dssHeader.Length;
        writer.Write(new byte[] { (byte)(len >> 24), (byte)(len >> 16), (byte)(len >> 8), (byte)len });
        writer.Write(dssHeader);
        writer.Write(new byte[32]); // Dummy key material

        var spoofedBase64 = Convert.ToBase64String(ms.ToArray());
        var spoofedLine = $"ssh-ed25519 {spoofedBase64} evil@spoofed";

        var result = SshKeyConverter.ParseAndNormalizeKey(spoofedLine);

        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Contain("does not match declared key type");
    }

    [Fact]
    public void SshKeyConverter_WhenPayloadTooShortOrExceedsMaxLength_ShouldRejectKey()
    {
        // 1. Short 3-byte Base64 ("AAAA") pretending to be an ed25519 key
        var shortResult = SshKeyConverter.ParseAndNormalizeKey("ssh-ed25519 AAAA evil@short");
        shortResult.IsSuccess.Should().BeFalse();

        // 2. Oversized > 16 KB input attempting memory DoS
        var hugeInput = "ssh-ed25519 " + new string('A', 20000);
        var hugeResult = SshKeyConverter.ParseAndNormalizeKey(hugeInput);
        hugeResult.IsSuccess.Should().BeFalse();
        hugeResult.ErrorMessage.Should().Contain("exceeds maximum allowed length");
    }

    [Fact]
    public async Task SftpUserService_AddPublicKeyAsync_ShouldSanitizeNewlinesInCustomCommentParameter()
    {
        var acl = Substitute.For<INativeAclProvisioner>();
        var winMgr = Substitute.For<IWindowsUserManager>();
        var sshMgr = Substitute.For<IOpenSshServiceManager>();
        var grpSvc = Substitute.For<ISftpGroupService>();
        var audit = Substitute.For<IAuditService>();
        var keyGen = Substitute.For<ISshKeyGenerator>();

        sshMgr.SftpRoot.Returns(@"C:\SFTPRoot");
        sshMgr.KeysPath.Returns(@"C:\ProgramData\ssh\keys");

        await using (var db = new AppDbContext(_dbOptions))
        {
            db.SftpUsers.Add(new SftpUser { Username = "alice", AccountType = SftpAccountType.LocalWindows });
            await db.SaveChangesAsync();
        }

        var userService = new SftpUserService(_dbFactory, acl, winMgr, sshMgr, grpSvc, audit, keyGen, NullLogger<SftpUserService>.Instance);
        const string validKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@host";

        var (success, _, key) = await userService.AddPublicKeyAsync("alice", validKey, "custom\r\nPermitRootLogin yes\tcomment");

        success.Should().BeTrue();
        key.Should().NotBeNull();
        key!.Comment.Should().NotContain("\r");
        key.Comment.Should().NotContain("\n");
        key.Comment.Should().NotContain("\t");
    }

    [Fact]
    public async Task SshdConfigService_ShouldStripMatchWildcardsAndSkipUnsafePaths()
    {
        var configPath = Path.Combine(_tempDir, "sshd_config_evil_rules");
        await File.WriteAllTextAsync(configPath, "Port 22\nSubsystem sftp internal-sftp\n");

        var configService = new SshdConfigService(NullLogger<SshdConfigService>.Instance);
        var safeDir = Path.Combine(_tempDir, "PartnerChroot");

        var rules = new List<DirectChrootRule>
        {
            // Rule 1: Attempt wildcard/negation injection in Identifier
            new() { IsGroup = false, Identifier = "alice*,!root,?", RootPath = safeDir },
            // Rule 2: Attempt targeting forbidden C:\Windows in RootPath
            new() { IsGroup = false, Identifier = "bob", RootPath = @"C:\Windows\System32" }
        };

        var (success, _) = await configService.SyncManagedBlocksAsync(rules, @"C:\SFTPRoot", @"C:\ProgramData\ssh\keys", configPath);
        success.Should().BeTrue();

        var written = await File.ReadAllTextAsync(configPath);
        written.Should().Contain("Match User alice!root".Replace("!", ""));
        written.Should().NotContain("*");
        written.Should().NotContain("?");
        written.Should().NotContain("!");
        written.Should().NotContain("Match User bob", "unsafe RootPath targeting C:\\Windows\\System32 must be skipped.");
    }

    // =========================================================================
    // Domain D: Evil CustomRootPath & OS Escape Attempts
    // =========================================================================

    [Theory]
    [InlineData(@"C:\PROGRA~1\OpenSSH", null)]               // Windows 8.3 short name
    [InlineData(@"D:\SFTPShare\folder:hiddenstream", null)]  // NTFS Alternate Data Stream
    [InlineData(@"D:\SFTPShare\CON\subfolder", null)]        // Reserved DOS device segment
    [InlineData(@"D:\SFTPShare\.ssh", null)]                 // Sensitive .ssh folder
    [InlineData(@"C:\Users\Administrator", null)]            // Windows user profile
    [InlineData(@"C:\Users\Public\Documents", null)]         // Windows Public profile
    [InlineData(@"C:\ProgramData", null)]                    // ProgramData root
    [InlineData(@"C:\SFTPRoot", @"C:\SFTPRoot")]             // Exact SftpRoot container collision
    public void SecurityValidator_ValidateSafeCustomPath_ShouldBlockShortNamesAdsDosDevicesUserProfilesAndSftpRootCollision(
        string evilPath,
        string? sftpRoot)
    {
        var (isSafe, errorMessage) = SecurityValidator.ValidateSafeCustomPath(evilPath, sftpRoot);

        isSafe.Should().BeFalse($"Path '{evilPath}' should be blocked.");
        errorMessage.Should().NotBeNullOrWhiteSpace();
    }

    // =========================================================================
    // Domain E: DirectChroot File Browser Integrity
    // =========================================================================

    [Fact]
    public async Task SecureFileBrowserService_DirectChroot_ShouldBlockDeletingProtectedFilesSubfolder()
    {
        var directRoot = Path.Combine(_tempDir, "DirectPartnerRoot");
        var filesSubDir = Path.Combine(directRoot, "files");
        Directory.CreateDirectory(filesSubDir);

        await using (var db = new AppDbContext(_dbOptions))
        {
            db.SftpUsers.Add(new SftpUser
            {
                Username = "partner1",
                AccountType = SftpAccountType.LocalWindows,
                AccessMode = SftpAccessMode.DirectChroot,
                CustomRootPath = directRoot
            });
            await db.SaveChangesAsync();
        }

        var browser = new SecureFileBrowserService(NullLogger<SecureFileBrowserService>.Instance, _tempDir, _dbFactory);

        // Attempting to delete the 'files' writable subdirectory inside a DirectChroot root must throw
        var act = async () => await browser.DeleteItemAsync("partner1", "files");
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*protected 'files' subdirectory*");

        Directory.Exists(filesSubDir).Should().BeTrue();
    }

    [Fact]
    public async Task SecureFileBrowserService_DirectChroot_WhenRootMissing_ShouldRefuseCreatingUnprovisionedRoot()
    {
        var missingDirectRoot = Path.Combine(_tempDir, "MissingDirectRoot");

        await using (var db = new AppDbContext(_dbOptions))
        {
            db.SftpUsers.Add(new SftpUser
            {
                Username = "partner_missing",
                AccountType = SftpAccountType.LocalWindows,
                AccessMode = SftpAccessMode.DirectChroot,
                CustomRootPath = missingDirectRoot
            });
            await db.SaveChangesAsync();
        }

        var browser = new SecureFileBrowserService(NullLogger<SecureFileBrowserService>.Instance, _tempDir, _dbFactory);

        var act = async () => await browser.ListItemsAsync("partner_missing", "");
        await act.Should().ThrowAsync<DirectoryNotFoundException>();
        Directory.Exists(missingDirectRoot).Should().BeFalse("File browser must not create an unprovisioned DirectChroot root with inherited permissions.");
    }

    // =========================================================================
    // Domain F: Safe Junction Detach Verification on User Delete
    // =========================================================================

    [Fact]
    public async Task SftpUserService_DeleteUserAsync_WhenJunctionDetachFails_ShouldAbortRecursiveDeleteToProtectSharedFiles()
    {
        var userHome = Path.Combine(_tempDir, "victim_user");
        var userFiles = Path.Combine(userHome, "files");
        var simulatedJunctionDir = Path.Combine(userFiles, "SharedFinance");
        Directory.CreateDirectory(simulatedJunctionDir);

        var importantSharedFile = Path.Combine(simulatedJunctionDir, "critical_budget.xlsx");
        await File.WriteAllTextAsync(importantSharedFile, "DO NOT DELETE");

        await using (var db = new AppDbContext(_dbOptions))
        {
            var grp = new SftpGroup
            {
                Id = "grp-fin",
                Name = "SharedFinance",
                RootPath = simulatedJunctionDir,
                AccessMode = SftpAccessMode.VirtualFolder
            };
            var usr = new SftpUser
            {
                Username = "victim_user",
                HomeDirectory = userHome,
                AccountType = SftpAccountType.LocalWindows
            };
            usr.UserGroups.Add(new SftpUserGroup { Username = "victim_user", GroupId = "grp-fin", Group = grp });
            db.SftpGroups.Add(grp);
            db.SftpUsers.Add(usr);
            await db.SaveChangesAsync();
        }

        var acl = Substitute.For<INativeAclProvisioner>();
        // Simulate RemoveDirectoryJunction failing (returns false while directory still exists on disk)
        acl.RemoveDirectoryJunction(simulatedJunctionDir).Returns(false);

        var winMgr = Substitute.For<IWindowsUserManager>();
        var sshMgr = Substitute.For<IOpenSshServiceManager>();
        var grpSvc = Substitute.For<ISftpGroupService>();
        var audit = Substitute.For<IAuditService>();
        var keyGen = Substitute.For<ISshKeyGenerator>();

        sshMgr.SftpRoot.Returns(_tempDir);
        sshMgr.KeysPath.Returns(Path.Combine(_tempDir, "keys"));

        var userService = new SftpUserService(_dbFactory, acl, winMgr, sshMgr, grpSvc, audit, keyGen, NullLogger<SftpUserService>.Instance);

        var (success, _) = await userService.DeleteUserAsync("victim_user", deleteFiles: true);

        success.Should().BeTrue();
        File.Exists(importantSharedFile).Should().BeTrue("when detaching a junction fails and the directory still exists, recursive Directory.Delete must be aborted to protect shared group files.");
    }

    // =========================================================================
    // Domain G: Comprehensive Audit Remediation Regression Suite
    // =========================================================================

    private static void WriteRfc4251Field(BinaryWriter writer, byte[] payload)
    {
        var len = BitConverter.GetBytes(payload.Length);
        if (BitConverter.IsLittleEndian) Array.Reverse(len);
        writer.Write(len);
        writer.Write(payload);
    }

    private static string BuildWireRsaOpenSshKey(int modulusBytesLength)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);
        WriteRfc4251Field(writer, Encoding.ASCII.GetBytes("ssh-rsa"));
        WriteRfc4251Field(writer, new byte[] { 0x01, 0x00, 0x01 });

        var mod = new byte[modulusBytesLength + 1];
        mod[1] = 0x80;
        mod[^1] = 0x01;
        WriteRfc4251Field(writer, mod);

        return $"ssh-rsa {Convert.ToBase64String(ms.ToArray())} test@rsa";
    }

    [Fact]
    public void SshKeyConverter_ShouldEnforceKeyStrengthAndWireMaterial()
    {
        // Weak 1024-bit RSA must be rejected
        var weakRsa = BuildWireRsaOpenSshKey(128);
        var weakRes = SshKeyConverter.ParseAndNormalizeKey(weakRsa);
        weakRes.IsSuccess.Should().BeFalse();
        weakRes.ErrorMessage.Should().Contain("2048-bit");

        // Strong 2048-bit RSA must be accepted
        var strongRsa = BuildWireRsaOpenSshKey(256);
        var strongRes = SshKeyConverter.ParseAndNormalizeKey(strongRsa);
        strongRes.IsSuccess.Should().BeTrue();

        // Truncated Ed25519 payload (!= 32 bytes) must be rejected
        using (var ms = new MemoryStream())
        using (var w = new BinaryWriter(ms))
        {
            WriteRfc4251Field(w, Encoding.ASCII.GetBytes("ssh-ed25519"));
            WriteRfc4251Field(w, new byte[16]);
            var truncEd = $"ssh-ed25519 {Convert.ToBase64String(ms.ToArray())} trunc@ed";
            SshKeyConverter.ParseAndNormalizeKey(truncEd).IsSuccess.Should().BeFalse();
        }

        // Valid 32-byte Ed25519 must succeed
        using (var ms = new MemoryStream())
        using (var w = new BinaryWriter(ms))
        {
            WriteRfc4251Field(w, Encoding.ASCII.GetBytes("ssh-ed25519"));
            var pub = new byte[32];
            pub[0] = 0xAB;
            pub[31] = 0xCD;
            WriteRfc4251Field(w, pub);
            var validEd = $"ssh-ed25519 {Convert.ToBase64String(ms.ToArray())} ok@ed";
            SshKeyConverter.ParseAndNormalizeKey(validEd).IsSuccess.Should().BeTrue();
        }

        // Mismatched ECDSA inner curve identifier must be rejected
        using (var ms = new MemoryStream())
        using (var w = new BinaryWriter(ms))
        {
            WriteRfc4251Field(w, Encoding.ASCII.GetBytes("ecdsa-sha2-nistp256"));
            WriteRfc4251Field(w, Encoding.ASCII.GetBytes("nistp384"));
            WriteRfc4251Field(w, new byte[49]);
            var mismatchEc = $"ecdsa-sha2-nistp256 {Convert.ToBase64String(ms.ToArray())} bad@ec";
            SshKeyConverter.ParseAndNormalizeKey(mismatchEc).IsSuccess.Should().BeFalse();
        }
    }

    [Fact]
    public void SecurityValidator_CanonicalAdminAndLdapHost_ShouldRejectBypassPatterns()
    {
        SecurityValidator.ExtractCanonicalUsername(@"CORP\alice\").Should().Be("alice");
        SecurityValidator.ExtractCanonicalUsername("@bob@corp.local").Should().Be("bob");
        SecurityValidator.ExtractCanonicalUsername(@"CORP\\charlie").Should().Be("charlie");

        SecurityValidator.IsValidAdminUsername("ab").Should().BeFalse();
        SecurityValidator.IsValidAdminUsername("bad admin").Should().BeFalse();
        SecurityValidator.IsValidAdminUsername("bad/admin").Should().BeFalse();
        SecurityValidator.IsValidAdminUsername(new string('a', 65)).Should().BeFalse();
        SecurityValidator.IsValidAdminUsername("sec.admin_01").Should().BeTrue();

        SecurityValidator.ValidateLdapHost("169.254.169.254", 389).IsValid.Should().BeFalse();
        SecurityValidator.ValidateLdapHost("dc01.corp.local\n", 389).IsValid.Should().BeFalse();
    }

    [Fact]
    public async Task LdapAuthService_TestConnectionAsync_WhenHostOrPortDiffersFromDb_ShouldNotDecryptStoredBindPassword()
    {
        var protection = Substitute.For<IProtectionService>();
        protection.Unprotect("ENC_SECRET").Returns("PlainBindSecret!");

        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int openPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var acceptLoop = Task.Run(async () =>
        {
            try
            {
                while (!cts.IsCancellationRequested)
                {
                    using var client = await listener.AcceptTcpClientAsync(cts.Token);
                    await Task.Delay(30, cts.Token);
                }
            }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException) { }
            catch (SocketException) { }
        });

        try
        {
            await using (var db = new AppDbContext(_dbOptions))
            {
                db.LdapConfigs.Add(new LdapConfig
                {
                    Id = 1,
                    Server = "127.0.0.1",
                    Port = openPort + 1, // Different port stored in DB than probed target
                    Domain = "corp.local",
                    BaseDn = "DC=corp,DC=local",
                    EncryptedBindDn = "cn=bind,dc=corp,dc=local",
                    EncryptedBindPassword = "ENC_SECRET"
                });
                await db.SaveChangesAsync();
            }

            var ldapSvc = new LdapAuthService(_dbFactory, protection, NullLogger<LdapAuthService>.Instance);

            var probeConfig = new LdapConfig
            {
                Id = 1,
                Server = "127.0.0.1",
                Port = openPort,
                Domain = "corp.local",
                BaseDn = "DC=corp,DC=local",
                EncryptedBindDn = "cn=bind,dc=corp,dc=local",
                EncryptedBindPassword = "ENC_SECRET"
            };

            await ldapSvc.TestConnectionAsync(probeConfig, plainBindPassword: null);

            protection.DidNotReceive().Unprotect("ENC_SECRET");
        }
        finally
        {
            cts.Cancel();
            listener.Stop();
            try { await acceptLoop; } catch { }
        }
    }

    [Fact]
    public async Task LdapAuthService_Step2Fallback_WhenActiveLocalSuperAdminExists_ShouldBeBlocked()
    {
        const string recoveryUser = "recovery_super";
        LdapAuthService.ResetLockoutForUser(recoveryUser);
        try
        {
            await using (var db = new AppDbContext(_dbOptions))
            {
                db.LdapConfigs.Add(new LdapConfig
                {
                    Id = 1,
                    IsLdapEnabled = false,
                    FallbackAdminUsername = recoveryUser,
                    FallbackAdminPasswordHash = PasswordHasher.HashPassword("RecoveryPass@2026")
                });
                db.WebAdminUsers.Add(new WebAdminUser
                {
                    Username = "primary_super",
                    AccountType = WebAdminType.Local,
                    Role = WebAdminRole.SuperAdmin,
                    IsActive = true,
                    PasswordHash = PasswordHasher.HashPassword("PrimarySuper@2026")
                });
                await db.SaveChangesAsync();
            }

            var ldapSvc = new LdapAuthService(_dbFactory, Substitute.For<IProtectionService>(), NullLogger<LdapAuthService>.Instance);
            var auth = await ldapSvc.AuthenticateAsync(recoveryUser, "RecoveryPass@2026");

            auth.IsSuccess.Should().BeFalse("disaster recovery fallback must be blocked when an active local SuperAdmin already exists.");
        }
        finally
        {
            LdapAuthService.ResetLockoutForUser(recoveryUser);
        }
    }

    [Fact]
    public async Task LdapAuthService_SaveConfigAsync_ShouldValidateFallbackUsernameAndRejectAdCollision()
    {
        await using (var db = new AppDbContext(_dbOptions))
        {
            db.WebAdminUsers.Add(new WebAdminUser
            {
                Username = "ad_collide",
                AccountType = WebAdminType.ActiveDirectory,
                Role = WebAdminRole.Operator,
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        var ldapSvc = new LdapAuthService(_dbFactory, Substitute.For<IProtectionService>(), NullLogger<LdapAuthService>.Instance);

        var badNameCfg = new LdapConfig { FallbackAdminUsername = "bad/name" };
        var badNameErr = await Assert.ThrowsAsync<ArgumentException>(() => ldapSvc.SaveConfigAsync(badNameCfg));
        badNameErr.Message.Should().Contain("3-50 characters");

        var collideCfg = new LdapConfig { FallbackAdminUsername = @"CORP\ad_collide" };
        var collideErr = await Assert.ThrowsAsync<ArgumentException>(() => ldapSvc.SaveConfigAsync(collideCfg));
        collideErr.Message.Should().Contain("conflicts with an existing Active Directory Web Admin");
    }

    [Fact]
    public async Task WebAdminService_ResetPasswordAsync_ShouldRevokeTargetActiveSessions()
    {
        UserSessionState.ClearAllOverrides();
        try
        {
            await using (var db = new AppDbContext(_dbOptions))
            {
                db.WebAdminUsers.Add(new WebAdminUser
                {
                    Id = 42,
                    Username = "op_target",
                    AccountType = WebAdminType.Local,
                    Role = WebAdminRole.Operator,
                    IsActive = true,
                    PasswordHash = PasswordHasher.HashPassword("OldPass!123")
                });
                await db.SaveChangesAsync();
            }

            var targetSession = new UserSessionState();
            targetSession.SetUser("op_target", "Target Operator", true, WebAdminRole.Operator);
            targetSession.EnsureAuthenticated().Should().BeTrue();

            var webAdminSvc = new WebAdminService(
                _dbFactory,
                Substitute.For<IAuditService>(),
                NullLogger<WebAdminService>.Instance);

            var res = await webAdminSvc.ResetPasswordAsync(42, "NewStrongPass!99", "super_admin");
            res.Success.Should().BeTrue();

            targetSession.EnsureAuthenticated().Should().BeFalse("resetting another admin's password must revoke their active UI sessions.");
        }
        finally
        {
            UserSessionState.ClearAllOverrides();
        }
    }

    [Fact]
    public void BoundedConcurrentCaches_UnderParallelLoad_ShouldStayBoundedWithoutThrowing()
    {
        UserSessionState.ClearAllOverrides();
        LdapAuthService.ClearAllLoginAttempts();
        try
        {
            var sessionSvc = new SftpSessionService(NullLogger<SftpSessionService>.Instance, Substitute.For<IAuditService>());
            var setCacheMethod = typeof(SftpSessionService).GetMethod("SetSessionCacheEntry", BindingFlags.NonPublic | BindingFlags.Instance);
            setCacheMethod.Should().NotBeNull();

            Parallel.For(0, 1500, i =>
            {
                UserSessionState.NotifyUserStatusChanged($"par_u_{i}", i % 2 == 0, WebAdminRole.Auditor);
                LdapAuthService.RecordFailedAttemptForTesting($"par_l_{i}", DateTime.UtcNow.AddSeconds(-i));
                setCacheMethod!.Invoke(sessionSvc, new object[]
                {
                    ($"10.1.{i / 256}.{i % 256}", 20000 + i),
                    ($"sftp_{i}", DateTime.UtcNow.AddSeconds(-i))
                });
            });

            UserSessionState.GetTrackedOverrideCount().Should().BeLessThanOrEqualTo(1000);
            LdapAuthService.GetTrackedAttemptCount().Should().BeLessThanOrEqualTo(1000);
            sessionSvc.SessionUserCache.Count.Should().BeLessThanOrEqualTo(1000);
        }
        finally
        {
            UserSessionState.ClearAllOverrides();
            LdapAuthService.ClearAllLoginAttempts();
        }
    }

    [Fact]
    public async Task SecureFileBrowserService_DirectChrootSubpath_AndJunctionContainment_ShouldBlockEscapes()
    {
        var missingRoot = Path.Combine(_tempDir, "MissingDirectRoot2");
        var userRoot = Path.Combine(_tempDir, "sftproot", "alice");
        var userFiles = Path.Combine(userRoot, "files");
        Directory.CreateDirectory(userFiles);

        var authGroupDir = Path.Combine(_tempDir, "Shares", "Finance");
        Directory.CreateDirectory(authGroupDir);
        await File.WriteAllTextAsync(Path.Combine(authGroupDir, "q1.txt"), "approved");

        var forbiddenOutsideDir = Path.Combine(_tempDir, "OutsideSecret");
        Directory.CreateDirectory(forbiddenOutsideDir);
        await File.WriteAllTextAsync(Path.Combine(forbiddenOutsideDir, "secret.txt"), "top-secret");

        await using (var db = new AppDbContext(_dbOptions))
        {
            var grp = new SftpGroup
            {
                Id = "grp-fin-2",
                Name = "Finance",
                RootPath = authGroupDir,
                AccessMode = SftpAccessMode.VirtualFolder
            };
            var alice = new SftpUser
            {
                Username = "alice",
                HomeDirectory = userRoot,
                AccessMode = SftpAccessMode.VirtualFolder
            };
            alice.UserGroups.Add(new SftpUserGroup { Username = "alice", GroupId = "grp-fin-2", Group = grp });

            db.SftpGroups.Add(grp);
            db.SftpUsers.Add(alice);
            db.SftpUsers.Add(new SftpUser
            {
                Username = "missing_dc",
                AccessMode = SftpAccessMode.DirectChroot,
                CustomRootPath = missingRoot
            });
            await db.SaveChangesAsync();
        }

        var acl = new NtfsAclService(NullLogger<NtfsAclService>.Instance);
        var browser = new SecureFileBrowserService(NullLogger<SecureFileBrowserService>.Instance, Path.Combine(_tempDir, "sftproot"), _dbFactory);

        // 1. Subpath under missing DirectChroot root must throw and create nothing
        await Assert.ThrowsAsync<DirectoryNotFoundException>(() => browser.ListItemsAsync("missing_dc", "nested/sub"));
        Directory.Exists(missingRoot).Should().BeFalse();

        // 2. Missing VirtualFolder subfolder returns empty without creating a directory
        var missingVirtual = await browser.ListItemsAsync("alice", "nonexistent_sub");
        missingVirtual.Should().BeEmpty();
        Directory.Exists(Path.Combine(userFiles, "nonexistent_sub")).Should().BeFalse();

        // 3. Deterministic link-target authorization matrix (blocks cross-tenant/external escapes in user & group modes)
        var authLinkMethod = typeof(SecureFileBrowserService).GetMethod("IsAuthorizedLinkDestination", BindingFlags.NonPublic | BindingFlags.Instance);
        authLinkMethod.Should().NotBeNull();

        ((bool)authLinkMethod!.Invoke(browser, new object[] { userFiles, forbiddenOutsideDir, "alice", false })!).Should().BeFalse();
        ((bool)authLinkMethod.Invoke(browser, new object[] { userFiles, authGroupDir, "alice", false })!).Should().BeTrue();
        ((bool)authLinkMethod.Invoke(browser, new object[] { userFiles, Path.Combine(userFiles, "sub"), "alice", false })!).Should().BeTrue();
        ((bool)authLinkMethod.Invoke(browser, new object[] { authGroupDir, forbiddenOutsideDir, "Finance", true })!).Should().BeFalse();
        ((bool)authLinkMethod.Invoke(browser, new object[] { authGroupDir, userFiles, "Finance", true })!).Should().BeFalse();
        ((bool)authLinkMethod.Invoke(browser, new object[] { authGroupDir, Path.Combine(authGroupDir, "sub"), "Finance", true })!).Should().BeTrue();

        // 4. Real on-disk NTFS junction containment when host/token permits mklink /J
        var evilUserJunction = Path.Combine(userFiles, "EvilLink");
        var validGroupJunction = Path.Combine(userFiles, "Finance");
        var groupEscapeJunction = Path.Combine(authGroupDir, "EscapeLink");
        var folderWithNestedJunction = Path.Combine(userFiles, "WrapperFolder");
        Directory.CreateDirectory(folderWithNestedJunction);
        var nestedJunction = Path.Combine(folderWithNestedJunction, "NestedFinance");

        try
        {
            if (acl.CreateDirectoryJunction(evilUserJunction, forbiddenOutsideDir))
            {
                acl.CreateDirectoryJunction(validGroupJunction, authGroupDir).Should().BeTrue();
                acl.CreateDirectoryJunction(groupEscapeJunction, forbiddenOutsideDir).Should().BeTrue();
                acl.CreateDirectoryJunction(nestedJunction, authGroupDir).Should().BeTrue();

                await Assert.ThrowsAsync<SecurityException>(() => browser.ListItemsAsync("alice", "EvilLink"));
                var financeItems = await browser.ListItemsAsync("alice", "Finance");
                financeItems.Should().Contain(i => i.Name == "q1.txt");

                await Assert.ThrowsAsync<SecurityException>(() => browser.ListGroupItemsAsync("Finance", "EscapeLink"));

                await Assert.ThrowsAsync<InvalidOperationException>(() => browser.DeleteItemAsync("alice", "WrapperFolder"));
                File.Exists(Path.Combine(authGroupDir, "q1.txt")).Should().BeTrue();
            }
        }
        finally
        {
            acl.RemoveDirectoryJunction(evilUserJunction);
            acl.RemoveDirectoryJunction(validGroupJunction);
            acl.RemoveDirectoryJunction(groupEscapeJunction);
            acl.RemoveDirectoryJunction(nestedJunction);
        }
    }

    [Fact]
    public async Task SftpUserService_And_SftpGroupService_ShouldEnforceKeyValidation_PrivilegedBlocks_AndAdDisable()
    {
        var acl = Substitute.For<INativeAclProvisioner>();
        var winMgr = Substitute.For<IWindowsUserManager>();
        var sshMgr = Substitute.For<IOpenSshServiceManager>();
        var audit = Substitute.For<IAuditService>();
        var keyGen = Substitute.For<ISshKeyGenerator>();
        var sessionSvc = Substitute.For<ISftpSessionService>();

        var sftpRoot = Path.Combine(_tempDir, "sftproot_lifecycle");
        var keysRoot = Path.Combine(_tempDir, "keys_lifecycle");
        var customDcRoot = Path.Combine(_tempDir, "dc_partner_root");
        sshMgr.SftpRoot.Returns(sftpRoot);
        sshMgr.KeysPath.Returns(keysRoot);

        var groupService = new SftpGroupService(_dbFactory, winMgr, acl, sshMgr, audit, NullLogger<SftpGroupService>.Instance);
        var userService = new SftpUserService(_dbFactory, acl, winMgr, sshMgr, groupService, audit, keyGen, NullLogger<SftpUserService>.Instance, sessionSvc);

        // 1. Invalid initial SSH key must reject upfront before OS user or directory provisioning
        var badKeyRes = await userService.CreateUserAsync(new CreateUserRequest
        {
            Username = "badkey_user",
            AccountType = SftpAccountType.LocalWindows,
            Password = "Password!123",
            SshPublicKey = "ssh-ed25519 invalid_payload!"
        });
        badKeyRes.Success.Should().BeFalse();
        winMgr.DidNotReceiveWithAnyArgs().CreateOrUpdateLocalUser(default!, default!, default);

        // 2. Privileged local account / pre-existing Windows account must be blocked
        winMgr.IsPrivilegedLocalAccount("Administrator").Returns(true);
        var privRes = await userService.CreateUserAsync(new CreateUserRequest
        {
            Username = "Administrator",
            AccountType = SftpAccountType.LocalWindows,
            Password = "Password!123"
        });
        privRes.Success.Should().BeFalse();

        winMgr.IsPrivilegedLocalAccount("existing_os").Returns(false);
        winMgr.LocalUserExists("existing_os").Returns(true);
        var hijackRes = await userService.CreateUserAsync(new CreateUserRequest
        {
            Username = "existing_os",
            AccountType = SftpAccountType.LocalWindows,
            Password = "Password!123"
        });
        hijackRes.Success.Should().BeFalse();

        // 3. Seed active AD DirectChroot user in a group with a key, then disable and verify full lifecycle
        await using (var db = new AppDbContext(_dbOptions))
        {
            var grp = new SftpGroup { Id = "grp-ad", Name = "Partners", RootPath = Path.Combine(_tempDir, "partners_share"), AccessMode = SftpAccessMode.VirtualFolder };
            var u = new SftpUser
            {
                Username = "ad_partner",
                AccountType = SftpAccountType.ActiveDirectory,
                AccessMode = SftpAccessMode.DirectChroot,
                CustomRootPath = customDcRoot,
                IsActive = true
            };
            u.UserGroups.Add(new SftpUserGroup { Username = "ad_partner", GroupId = "grp-ad", Group = grp });
            u.PublicKeys.Add(new SshPublicKey
            {
                Username = "ad_partner",
                KeyType = "ssh-rsa",
                FingerprintSha256 = "SHA256:dummy1",
                RawPublicKey = BuildWireRsaOpenSshKey(256)
            });
            db.SftpGroups.Add(grp);
            db.SftpUsers.Add(u);
            await db.SaveChangesAsync();
        }

        var disableRes = await userService.UpdateUserStatusAsync("ad_partner", isActive: false, "super_admin");
        disableRes.Success.Should().BeTrue();

        winMgr.Received(1).RemoveUserFromLocalGroup("SFTP-Users", "ad_partner");
        winMgr.Received(1).RemoveUserFromLocalGroup("SFTP-Partners", "ad_partner");
        acl.Received().WriteUserKeysFile(keysRoot, "ad_partner", Arg.Is<IEnumerable<string>>(k => !k.Any()));
        await sessionSvc.Received(1).TerminateUserSessionsAsync("ad_partner", "super_admin");
        await sshMgr.Received().SyncManagedConfigAsync(
            Arg.Is<IEnumerable<DirectChrootRule>>(r => !r.Any(rule => rule.Identifier == "ad_partner")),
            Arg.Any<bool>());

        // 4. Adding a public key while disabled saves to DB but skips writing active key to disk
        acl.ClearReceivedCalls();
        string secondKey;
        using (var ms = new MemoryStream())
        using (var w = new BinaryWriter(ms))
        {
            WriteRfc4251Field(w, Encoding.ASCII.GetBytes("ssh-ed25519"));
            var pub = new byte[32];
            pub[0] = 0x55;
            WriteRfc4251Field(w, pub);
            secondKey = $"ssh-ed25519 {Convert.ToBase64String(ms.ToArray())} second@ed";
        }
        var addDisabledKey = await userService.AddPublicKeyAsync("ad_partner", secondKey);
        addDisabledKey.Success.Should().BeTrue();
        acl.DidNotReceiveWithAnyArgs().WriteUserKeysFile(default!, default!, default!);
    }

    [Fact]
    public async Task SshdHardeningAndCsvTests_ShouldEnforceServiceAllowlist_Directives_AndCsvEscaping()
    {
        // 1. Service name allowlist blocks arbitrary Windows services
        var svcMgr = new OpenSshServiceManager(NullLogger<OpenSshServiceManager>.Instance);
        var (okStart, startMsg) = await svcMgr.StartServiceAsync("Spooler");
        okStart.Should().BeFalse();
        startMsg.Should().Contain("not permitted");

        // 2. Managed sshd block disables Tunnel, AgentForwarding, and TTY
        var block = svcMgr.GenerateManagedBlock(new List<DirectChrootRule>(), @"C:\SFTPRoot", @"C:\ProgramData\ssh\keys");
        block.Should().Contain("PermitTunnel no");
        block.Should().Contain("AllowAgentForwarding no");
        block.Should().Contain("PermitTTY no");

        // 3. GlobalOnlyDirectives extracts LoginGraceTime out of Match blocks into GlobalLines
        var configSvc = new SshdConfigService(NullLogger<SshdConfigService>.Instance);
        var parsed = configSvc.Parse("Port 22\nMatch Group SFTP-Users\n    LoginGraceTime 30\n    ChrootDirectory C:\\SFTPRoot\\%u\n");
        parsed.GlobalLines.Should().Contain(l => l.Contains("LoginGraceTime 30"));
        parsed.MatchBlocks.Should().ContainSingle();
        parsed.MatchBlocks[0].Directives.Should().NotContain(d => d.Key.Equals("LoginGraceTime", StringComparison.OrdinalIgnoreCase));

        // 4. CSV Escaping handles pipe, vertical tab, form feed, and leading newline
        SshEventLogService.EscapeCsv("|calc").Should().StartWith("\"'");
        SshEventLogService.EscapeCsv("\v=1+1").Should().StartWith("\"'");
        SshEventLogService.EscapeCsv("\f+2").Should().StartWith("\"'");
        SshEventLogService.EscapeCsv("\n=cmd").Should().StartWith("\"'");
    }
}
