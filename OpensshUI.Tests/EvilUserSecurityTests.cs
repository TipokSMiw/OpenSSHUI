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
}
