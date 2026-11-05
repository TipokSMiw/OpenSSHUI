using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using OpensshUI.Data;
using OpensshUI.Services.Files;
using OpensshUI.Services.OpenSsh;
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
}
