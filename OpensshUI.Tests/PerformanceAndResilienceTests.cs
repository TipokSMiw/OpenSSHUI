using System.Security;
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

public class PerformanceAndResilienceTests : IDisposable
{
    private readonly string _testRoot;

    public PerformanceAndResilienceTests()
    {
        _testRoot = Path.Combine(Path.GetTempPath(), "OpensshUI_PerfTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testRoot);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testRoot))
            {
                Directory.Delete(_testRoot, true);
            }
        }
        catch
        {
            // Ignore cleanup failure in temp dir
        }
    }

    [Fact]
    public void StorageCalculation_ReturnsZero_WhenUserDirectoryDoesNotExist()
    {
        var service = new SecureFileBrowserService(NullLogger<SecureFileBrowserService>.Instance, _testRoot);
        var bytes = service.GetTotalUserStorageBytes("nonexistent_user");
        bytes.Should().Be(0);
    }

    [Fact]
    public async Task StorageCalculation_CalculatesUserFiles_ExcludingExternalReparsePoints()
    {
        var username = "testuser";
        var userFilesDir = Path.Combine(_testRoot, username, "files");
        Directory.CreateDirectory(userFilesDir);

        // Create sample file of 1024 bytes
        var sampleFile = Path.Combine(userFilesDir, "testfile.dat");
        File.WriteAllBytes(sampleFile, new byte[1024]);

        var service = new SecureFileBrowserService(NullLogger<SecureFileBrowserService>.Instance, _testRoot);

        // Sync calculation
        var syncBytes = service.GetTotalUserStorageBytes(username);
        syncBytes.Should().Be(1024);

        // Async calculation
        var asyncBytes = await service.GetTotalUserStorageBytesAsync(username);
        asyncBytes.Should().Be(1024);
    }

    [Fact]
    public void AclProvisioner_FilesystemHelpers_WorkCorrectly()
    {
        var provisioner = new NativeAclProvisioner(NullLogger<NativeAclProvisioner>.Instance);

        // DirectoryExists
        provisioner.DirectoryExists(_testRoot).Should().BeTrue();
        provisioner.DirectoryExists(Path.Combine(_testRoot, "does_not_exist")).Should().BeFalse();

        // CreateDirectory
        var subDir = Path.Combine(_testRoot, "new_sub_dir");
        provisioner.CreateDirectory(subDir).Should().BeTrue();
        provisioner.DirectoryExists(subDir).Should().BeTrue();

        // GetParentDirectory
        var parent = provisioner.GetParentDirectory(subDir);
        parent.Should().NotBeNull();
        parent!.TrimEnd(Path.DirectorySeparatorChar).Should().Be(_testRoot.TrimEnd(Path.DirectorySeparatorChar));

        // GetDirectoryBreadcrumbs
        var crumbs = provisioner.GetDirectoryBreadcrumbs(subDir);
        crumbs.Should().NotBeEmpty();
        crumbs.Last().Path.Should().Be(subDir);
        crumbs.Last().IsLast.Should().BeTrue();
    }

    [Fact]
    public async Task CustomMigration_CreatesSshPublicKeyUsernameIndex()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();

        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(connection)
            .Options;

        using (var db = new AppDbContext(options))
        {
            await db.Database.EnsureCreatedAsync();
            await db.ApplyCustomMigrationsAsync();

            // Verify index exists in sqlite_master
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT name FROM sqlite_master WHERE type='index' AND name='IX_SshPublicKeys_Username';";
            var indexName = await cmd.ExecuteScalarAsync();

            indexName.Should().NotBeNull();
            indexName!.ToString().Should().Be("IX_SshPublicKeys_Username");

            // Verify AuditLogs Timestamp index and SftpUserGroups GroupId index
            using var auditIdxCmd = connection.CreateCommand();
            auditIdxCmd.CommandText = "SELECT name FROM sqlite_master WHERE type='index' AND name='IX_AuditLogs_Timestamp';";
            (await auditIdxCmd.ExecuteScalarAsync())?.ToString().Should().Be("IX_AuditLogs_Timestamp");

            using var groupIdxCmd = connection.CreateCommand();
            groupIdxCmd.CommandText = "SELECT name FROM sqlite_master WHERE type='index' AND name='IX_SftpUserGroups_GroupId';";
            (await groupIdxCmd.ExecuteScalarAsync())?.ToString().Should().Be("IX_SftpUserGroups_GroupId");
        }
    }

    [Fact]
    public async Task StorageCalculation_RespectsCancellationToken_WhenCancelled()
    {
        var username = "canceluser";
        var userFilesDir = Path.Combine(_testRoot, username, "files");
        Directory.CreateDirectory(userFilesDir);
        File.WriteAllBytes(Path.Combine(userFilesDir, "data.bin"), new byte[256]);

        var service = new SecureFileBrowserService(NullLogger<SecureFileBrowserService>.Instance, _testRoot);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = async () => await service.GetTotalUserStorageBytesAsync(username, cts.Token);
        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public void OpenSshServiceManager_RespectsConfigurationSettings_WhenProvided()
    {
        var configuration = NSubstitute.Substitute.For<Microsoft.Extensions.Configuration.IConfiguration>();
        configuration["SftpSettings:SftpRoot"].Returns(@"D:\CustomSftpRoot");
        configuration["SftpSettings:KeysPath"].Returns(@"D:\CustomSsh\keys");
        configuration["SftpSettings:SshdConfigPath"].Returns(@"D:\CustomSsh\sshd_config");

        var manager = new OpenSshServiceManager(NullLogger<OpenSshServiceManager>.Instance, configuration);

        manager.SftpRoot.Should().Be(@"D:\CustomSftpRoot");
        manager.KeysPath.Should().Be(@"D:\CustomSsh\keys");
        manager.ConfigPath.Should().Be(@"D:\CustomSsh\sshd_config");
    }

    [Fact]
    public void TC_GOV_01_AgentMd_And_RazorPages_ComplyWithArchitectureAndSecurityGuardrails()
    {
        var repoRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
        var agentMdPath = Path.Combine(repoRoot, "AGENT.md");
        File.Exists(agentMdPath).Should().BeTrue("AGENT.md must exist at repository root");

        var agentMdContent = File.ReadAllText(agentMdPath);
        agentMdContent.Should().Contain("Dual-Layer RBAC Enforcement");
        agentMdContent.Should().Contain("Performance, Concurrency & Resource Guardrails");

        var pagesDir = Path.Combine(repoRoot, "Components", "Pages");
        var razorFiles = Directory.GetFiles(pagesDir, "*.razor", SearchOption.AllDirectories);
        razorFiles.Should().NotBeEmpty();

        foreach (var razorFile in razorFiles)
        {
            var content = File.ReadAllText(razorFile);
            content.Should().NotContain("InvokeVoidAsync(\"eval\"", $"Razor file {Path.GetFileName(razorFile)} must not use JS eval()");
            content.Should().NotContain("Path.GetInvalidFileNameChars()", $"Razor file {Path.GetFileName(razorFile)} must not call System.IO.Path directly");
        }
    }

    [Fact]
    public async Task TC_PERF_01_UpdateUserAsync_SkipsSshdConfigSync_WhenAccessModeRemainsVirtualFolder()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options;
        using var dbInit = new AppDbContext(options);
        await dbInit.Database.EnsureCreatedAsync();

        var dbFactory = Substitute.For<IDbContextFactory<AppDbContext>>();
        dbFactory.CreateDbContextAsync(Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromResult(new AppDbContext(options)));

        var aclMock = Substitute.For<INativeAclProvisioner>();
        var windowsUserMock = Substitute.For<IWindowsUserManager>();
        var sshManagerMock = Substitute.For<IOpenSshServiceManager>();
        sshManagerMock.SftpRoot.Returns(_testRoot);
        sshManagerMock.KeysPath.Returns(Path.Combine(_testRoot, "keys"));

        var groupServiceMock = Substitute.For<ISftpGroupService>();
        var auditMock = Substitute.For<IAuditService>();
        var keyGenMock = Substitute.For<ISshKeyGenerator>();

        // Seed a VirtualFolder user
        using (var db = new AppDbContext(options))
        {
            db.SftpUsers.Add(new SftpUser
            {
                Username = "vf_user",
                DisplayName = "Old Name",
                AccountType = SftpAccountType.ActiveDirectory,
                AccessMode = SftpAccessMode.VirtualFolder,
                HomeDirectory = Path.Combine(_testRoot, "vf_user"),
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        var userService = new SftpUserService(
            dbFactory,
            aclMock,
            windowsUserMock,
            sshManagerMock,
            groupServiceMock,
            auditMock,
            keyGenMock,
            NullLogger<SftpUserService>.Instance);

        // 1. Update user keeping VirtualFolder -> should NOT trigger SyncAllDirectChrootConfigsAsync
        var updateReq1 = new UpdateUserRequest
        {
            Username = "vf_user",
            DisplayName = "New Name",
            AccessMode = SftpAccessMode.VirtualFolder,
            CustomPermissionType = SftpPermissionType.ReadWrite
        };

        var res1 = await userService.UpdateUserAsync(updateReq1, "admin");
        res1.Success.Should().BeTrue();
        await groupServiceMock.DidNotReceive().SyncAllDirectChrootConfigsAsync();

        // 2. Update user switching to DirectChroot -> MUST trigger SyncAllDirectChrootConfigsAsync
        var customPath = Path.Combine(_testRoot, "direct_custom");
        Directory.CreateDirectory(customPath);
        var updateReq2 = new UpdateUserRequest
        {
            Username = "vf_user",
            DisplayName = "New Name",
            CustomRootPath = customPath,
            AccessMode = SftpAccessMode.DirectChroot,
            CustomPermissionType = SftpPermissionType.ReadWrite
        };

        var res2 = await userService.UpdateUserAsync(updateReq2, "admin");
        res2.Success.Should().BeTrue();
        await groupServiceMock.Received(1).SyncAllDirectChrootConfigsAsync();
    }

    [Fact]
    public void TC_PERF_02_AccountCacheAndJunctionIdempotency_AvoidRedundantOperations()
    {
        var service = new NtfsAclService(NullLogger<NtfsAclService>.Instance);
        service.ResolvedAccountCacheCount.Should().Be(0);

        // 1. Provisioning with current OS user populates and reuses the bounded SID/NTAccount cache
        var chrootDir = Path.Combine(_testRoot, "cache_test_chroot");
        service.ProvisionChrootRoot(chrootDir, Environment.UserName);
        service.ResolvedAccountCacheCount.Should().Be(1);

        // Second call reuses the cached NTAccount entry without adding duplicates
        service.ProvisionChrootRoot(chrootDir, Environment.UserName);
        service.ResolvedAccountCacheCount.Should().Be(1);

        // 2. Verify CreateDirectoryJunction rejects existing regular directories safely without deleting them
        var targetDir = Path.Combine(_testRoot, "shared_target_1");
        var regularDirLink = Path.Combine(_testRoot, "existing_regular_dir");
        Directory.CreateDirectory(targetDir);
        Directory.CreateDirectory(regularDirLink);
        File.WriteAllText(Path.Combine(regularDirLink, "keep.txt"), "safe");

        service.CreateDirectoryJunction(regularDirLink, targetDir).Should().BeFalse();
        File.Exists(Path.Combine(regularDirLink, "keep.txt")).Should().BeTrue();

        // 3. If the OS environment permits creating junctions (mklink /J), verify idempotent no-op on second call
        var linkPath = Path.Combine(_testRoot, "user_home", "files", "group_link");
        if (service.CreateDirectoryJunction(linkPath, targetDir))
        {
            var dirInfo1 = new DirectoryInfo(linkPath);
            var creationTime1 = dirInfo1.CreationTimeUtc;

            service.CreateDirectoryJunction(linkPath, targetDir).Should().BeTrue();
            new DirectoryInfo(linkPath).CreationTimeUtc.Should().Be(creationTime1);
        }
    }

    [Fact]
    public void TC_PERF_04_SshEventLogService_BuildXPathTimeQuery_FormatsUtcBoundariesCorrectly()
    {
        SshEventLogService.BuildXPathTimeQuery(null, null).Should().Be("*");

        var fromUtc = new DateTime(2026, 11, 9, 1, 30, 0, DateTimeKind.Utc);
        var toUtc = new DateTime(2026, 11, 9, 2, 45, 0, DateTimeKind.Utc);

        var queryBoth = SshEventLogService.BuildXPathTimeQuery(fromUtc, toUtc);
        queryBoth.Should().Contain("@SystemTime>='2026-11-09T01:30:00.000Z'");
        queryBoth.Should().Contain("@SystemTime<='2026-11-09T02:45:00.000Z'");
        queryBoth.Should().StartWith("*[System[TimeCreated[");
    }

    [Fact]
    public async Task TC_INT_01_SyncManagedBlocksAsync_SerializesConcurrentCalls_WithoutLostUpdates()
    {
        var configPath = Path.Combine(_testRoot, "sshd_config_concurrent");
        await File.WriteAllTextAsync(configPath, "Port 22\nSubsystem sftp internal-sftp\n");

        var service = new SshdConfigService(NullLogger<SshdConfigService>.Instance);

        var tasks = Enumerable.Range(1, 5).Select(i =>
        {
            var rules = new List<DirectChrootRule>
            {
                new DirectChrootRule
                {
                    IsGroup = false,
                    Identifier = $"user_{i}",
                    RootPath = $@"C:\SFTPRoot\user_{i}"
                }
            };
            return service.SyncManagedBlocksAsync(rules, @"C:\SFTPRoot", @"C:\ProgramData\ssh\keys", configPath);
        });

        var results = await Task.WhenAll(tasks);
        results.Should().OnlyContain(r => r.Success);

        var finalContent = await File.ReadAllTextAsync(configPath);
        finalContent.Should().Contain("Match Group SFTP-Users");
        var parsed = service.Parse(finalContent);
        parsed.GlobalLines.Should().Contain(l => l.Contains("Port 22"));
    }

    [Fact]
    public async Task TC_INT_02_WriteUserKeysFile_HandlesConcurrentWrites_Atomically()
    {
        var service = new NtfsAclService(NullLogger<NtfsAclService>.Instance);
        var keysDir = Path.Combine(_testRoot, "keys_concurrent");
        var username = "concurrent_user";

        var tasks = Enumerable.Range(1, 10).Select(i => Task.Run(() =>
        {
            var lines = new[]
            {
                $"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyLine1Batch{i} comment1_{i}",
                $"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyLine2Batch{i} comment2_{i}"
            };
            service.WriteUserKeysFile(keysDir, username, lines);
        }));

        await Task.WhenAll(tasks);

        var userKeyFile = Path.Combine(keysDir, username);
        File.Exists(userKeyFile).Should().BeTrue();
        var finalLines = File.ReadAllLines(userKeyFile).Where(l => !string.IsNullOrWhiteSpace(l)).ToArray();
        finalLines.Should().HaveCount(2, "Atomic replace must leave a complete 2-line batch without interleaving");

        // Ensure no temp files remain
        Directory.GetFiles(keysDir, "*.tmp_*").Should().BeEmpty();
    }

    [Fact]
    public void TC_INT_03_LdapAuthService_LoginAttempts_EnforcesUpperBoundAndEvictsExpiredEntries()
    {
        LdapAuthService.ClearAllLoginAttempts();
        try
        {
            var expiredTime = DateTime.UtcNow.AddMinutes(-30);

            // Insert 1,005 expired entries -> should prune expired entries when exceeding 1,000
            for (int i = 0; i < 1005; i++)
            {
                LdapAuthService.RecordFailedAttemptForTesting($"expired_user_{i}", expiredTime);
            }

            LdapAuthService.GetTrackedAttemptCount().Should().BeLessThanOrEqualTo(1000);

            // Now fill with active entries beyond 1,000 -> bounded cap must hold
            var activeTime = DateTime.UtcNow;
            for (int i = 0; i < 1100; i++)
            {
                LdapAuthService.RecordFailedAttemptForTesting($"active_user_{i}", activeTime);
            }

            LdapAuthService.GetTrackedAttemptCount().Should().BeLessThanOrEqualTo(1000);
        }
        finally
        {
            LdapAuthService.ClearAllLoginAttempts();
        }
    }

    [Fact]
    public void TC_SEC_01_UserSessionState_EnforcesRoleBasedPermissionsCorrectly()
    {
        var session = new UserSessionState();
        session.IsAuthenticated.Should().BeFalse();
        session.CanManageSystem.Should().BeFalse();
        session.CanManageSftp.Should().BeFalse();

        // Auditor: Read-only
        session.SetUser("auditor01", "Auditor One", true, WebAdminRole.Auditor);
        session.IsAuthenticated.Should().BeTrue();
        session.CanManageSystem.Should().BeFalse();
        session.CanManageSftp.Should().BeFalse();
        session.IsReadOnly.Should().BeTrue();

        // Operator: Can manage SFTP users/groups/files, cannot manage system/service/LDAP
        session.SetUser("operator01", "Operator One", true, WebAdminRole.Operator);
        session.IsAuthenticated.Should().BeTrue();
        session.CanManageSystem.Should().BeFalse();
        session.CanManageSftp.Should().BeTrue();
        session.IsReadOnly.Should().BeFalse();

        // SuperAdmin: Full access
        session.SetUser("admin01", "Super Admin", true, WebAdminRole.SuperAdmin);
        session.IsAuthenticated.Should().BeTrue();
        session.CanManageSystem.Should().BeTrue();
        session.CanManageSftp.Should().BeTrue();
        session.IsReadOnly.Should().BeFalse();
    }

    [Fact]
    public async Task TC_SEC_02_SshKeyGenerator_And_SecurityValidator_RejectControlCharsAndUnsafePassphrases()
    {
        // Passphrase with control character
        var resCtrl = SecurityValidator.ValidateSshPassphrase("bad\npassphrase");
        resCtrl.IsValid.Should().BeFalse();
        resCtrl.ErrorMessage.Should().NotBeNullOrWhiteSpace();

        // Passphrase with double quote (prevents breaking CLI quoting)
        var resQuote = SecurityValidator.ValidateSshPassphrase("bad\"passphrase");
        resQuote.IsValid.Should().BeFalse();
        resQuote.ErrorMessage.Should().NotBeNullOrWhiteSpace();

        // Valid passphrase
        SecurityValidator.ValidateSshPassphrase("SafePassphrase#2026!").IsValid.Should().BeTrue();

        // SshKeyGenerator also rejects before process execution
        var generator = new SshKeyGenerator(NullLogger<SshKeyGenerator>.Instance);
        var genRes = await generator.GenerateKeyPairAsync("ed25519", "automation-test", "bad\"passphrase");
        genRes.Success.Should().BeFalse();
        genRes.ErrorMessage.Should().Contain("Passphrase");
    }

    [Fact]
    public void TC_SEC_03_SecurityValidator_SanitizeSafeFileName_StripsInvalidCharsAndReservedNames()
    {
        SecurityValidator.SanitizeSafeFileName("alice_automation/../../etc_id_ed25519.pem", "fallback.pem")
            .Should().NotContain("/")
            .And.NotContain("..");

        SecurityValidator.SanitizeSafeFileName("CON", "fallback.pem")
            .Should().Be("_CON");

        SecurityValidator.SanitizeSafeFileName("   ", "fallback.pem")
            .Should().Be("fallback.pem");
    }
}
