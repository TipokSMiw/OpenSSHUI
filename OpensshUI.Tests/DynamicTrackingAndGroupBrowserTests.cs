using System.Security;
using System.Text;
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using OpensshUI.Data;
using OpensshUI.Models;
using OpensshUI.Services.Files;
using OpensshUI.Services.OpenSsh;

namespace OpensshUI.Tests;

public class DynamicTrackingAndGroupBrowserTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<AppDbContext> _dbOptions;
    private readonly List<string> _tempDirs = new();

    public DynamicTrackingAndGroupBrowserTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        _dbOptions = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .Options;

        using var db = new AppDbContext(_dbOptions);
        db.Database.EnsureCreated();
    }

    private string CreateTempDir(string prefix)
    {
        var path = Path.Combine(Path.GetTempPath(), $"{prefix}_{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        _tempDirs.Add(path);
        return path;
    }

    public void Dispose()
    {
        _connection.Dispose();
        foreach (var dir in _tempDirs)
        {
            try
            {
                if (Directory.Exists(dir))
                {
                    Directory.Delete(dir, true);
                }
            }
            catch { }
        }
    }

    [Fact]
    public void OpenSshServiceManager_DynamicConfiguration_ShouldUpdateSftpRootImmediately()
    {
        var inMemorySettings = new Dictionary<string, string?>
        {
            { "SftpSettings:SftpRoot", @"D:\OriginalRoot" },
            { "SftpSettings:KeysPath", @"C:\ProgramData\ssh\keys" },
            { "SftpSettings:SshdConfigPath", @"C:\ProgramData\ssh\sshd_config" }
        };

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(inMemorySettings)
            .Build();

        var manager = new OpenSshServiceManager(NullLogger<OpenSshServiceManager>.Instance, config);
        manager.SftpRoot.Should().Be(@"D:\OriginalRoot");

        // Simulate runtime modification in configuration
        config["SftpSettings:SftpRoot"] = @"E:\ModifiedSftpRoot";
        manager.SftpRoot.Should().Be(@"E:\ModifiedSftpRoot");
    }

    [Fact]
    public async Task SecureFileBrowserService_DirectChrootUser_ShouldBrowseFilesFromCustomPath()
    {
        var tempCustomPath = CreateTempDir("UserCustomRoot");
        var testFilePath = Path.Combine(tempCustomPath, "custom_doc.txt");
        await File.WriteAllTextAsync(testFilePath, "Hello from custom direct chroot!");

        var dbFactory = new TestDbContextFactory(_dbOptions);
        using (var db = dbFactory.CreateDbContext())
        {
            db.SftpUsers.Add(new SftpUser
            {
                Username = "custom_user",
                DisplayName = "Custom Path User",
                AccessMode = SftpAccessMode.DirectChroot,
                CustomRootPath = tempCustomPath
            });
            await db.SaveChangesAsync();
        }

        var service = new SecureFileBrowserService(
            NullLogger<SecureFileBrowserService>.Instance,
            @"C:\FallbackRoot",
            dbFactory);

        var items = await service.ListItemsAsync("custom_user");
        items.Should().ContainSingle(i => i.Name == "custom_doc.txt" && !i.IsDirectory);

        var resolvedPath = await service.ResolveUserPhysicalPathAsync("custom_user");
        resolvedPath.Should().Be(tempCustomPath);
    }

    [Fact]
    public async Task SecureFileBrowserService_GroupBrowsing_ShouldPerformFullCrudOperations()
    {
        var tempGroupPath = CreateTempDir("GroupSharedRoot");

        var dbFactory = new TestDbContextFactory(_dbOptions);
        using (var db = dbFactory.CreateDbContext())
        {
            db.SftpGroups.Add(new SftpGroup
            {
                Id = "grp-finance-1",
                Name = "Finance",
                RootPath = tempGroupPath,
                PermissionType = SftpPermissionType.ReadWrite,
                AccessMode = SftpAccessMode.VirtualFolder
            });
            await db.SaveChangesAsync();
        }

        var service = new SecureFileBrowserService(
            NullLogger<SecureFileBrowserService>.Instance,
            @"C:\FallbackRoot",
            dbFactory);

        // 1. Create subfolder inside group
        await service.CreateGroupDirectoryAsync("Finance", "", "Reports2026");
        var itemsAfterDir = await service.ListGroupItemsAsync("Finance");
        itemsAfterDir.Should().ContainSingle(i => i.Name == "Reports2026" && i.IsDirectory);

        // 2. Upload file into subfolder
        var fileContent = "Account,Amount\nAsset,50000";
        using (var uploadStream = new MemoryStream(Encoding.UTF8.GetBytes(fileContent)))
        {
            await service.UploadGroupFileAsync("Finance", "Reports2026", "q1_summary.csv", uploadStream);
        }

        // 3. List items inside subfolder
        var subItems = await service.ListGroupItemsAsync("Finance", "Reports2026");
        subItems.Should().ContainSingle(i => i.Name == "q1_summary.csv" && !i.IsDirectory);

        // 4. Read file stream back
        using (var readStream = await service.OpenGroupReadStreamAsync("Finance", "Reports2026/q1_summary.csv"))
        using (var reader = new StreamReader(readStream))
        {
            var content = await reader.ReadToEndAsync();
            content.Should().Be(fileContent);
        }

        // 5. Check Group Storage calculation
        var storageBytes = await service.GetTotalGroupStorageBytesAsync("Finance");
        storageBytes.Should().BeGreaterThan(0);

        // 6. Delete file
        await service.DeleteGroupItemAsync("Finance", "Reports2026/q1_summary.csv");
        var itemsAfterDelete = await service.ListGroupItemsAsync("Finance", "Reports2026");
        itemsAfterDelete.Should().BeEmpty();

        // 7. Verify physical path resolution
        var resolvedPath = await service.ResolveGroupPhysicalPathAsync("Finance");
        resolvedPath.Should().Be(tempGroupPath);
    }

    [Fact]
    public async Task SecureFileBrowserService_GroupBrowsing_ShouldBlockPathTraversal()
    {
        var tempGroupPath = CreateTempDir("GroupSafetyRoot");

        var dbFactory = new TestDbContextFactory(_dbOptions);
        using (var db = dbFactory.CreateDbContext())
        {
            db.SftpGroups.Add(new SftpGroup
            {
                Id = "grp-sec-1",
                Name = "SecurityTeam",
                RootPath = tempGroupPath
            });
            await db.SaveChangesAsync();
        }

        var service = new SecureFileBrowserService(
            NullLogger<SecureFileBrowserService>.Instance,
            @"C:\FallbackRoot",
            dbFactory);

        // Path traversal attempts must throw SecurityException
        var act1 = async () => await service.ListGroupItemsAsync("SecurityTeam", "../");
        await act1.Should().ThrowAsync<SecurityException>();

        var act2 = async () => await service.ListGroupItemsAsync("SecurityTeam", @"..\..\Windows");
        await act2.Should().ThrowAsync<SecurityException>();

        var act3 = async () => await service.CreateGroupDirectoryAsync("SecurityTeam", "", "../hacked");
        await act3.Should().ThrowAsync<SecurityException>();
    }

    private class TestDbContextFactory : IDbContextFactory<AppDbContext>
    {
        private readonly DbContextOptions<AppDbContext> _options;

        public TestDbContextFactory(DbContextOptions<AppDbContext> options)
        {
            _options = options;
        }

        public AppDbContext CreateDbContext()
        {
            return new AppDbContext(_options);
        }
    }
}
