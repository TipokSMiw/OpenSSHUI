using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using OpensshUI.Data;
using OpensshUI.Models;
using OpensshUI.Services.Audit;
using OpensshUI.Services.Groups;
using OpensshUI.Services.OpenSsh;
using Xunit;

namespace OpensshUI.Tests;

public class SftpGroupServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<AppDbContext> _dbOptions;
    private readonly IDbContextFactory<AppDbContext> _dbFactory;

    private readonly IWindowsUserManager _windowsUserManager = Substitute.For<IWindowsUserManager>();
    private readonly INativeAclProvisioner _aclProvisioner = Substitute.For<INativeAclProvisioner>();
    private readonly IOpenSshServiceManager _sshServiceManager = Substitute.For<IOpenSshServiceManager>();
    private readonly IAuditService _auditService = Substitute.For<IAuditService>();

    private readonly SftpGroupService _sut;

    public SftpGroupServiceTests()
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

        _sut = new SftpGroupService(
            _dbFactory,
            _windowsUserManager,
            _aclProvisioner,
            _sshServiceManager,
            _auditService,
            NullLogger<SftpGroupService>.Instance);
    }

    public void Dispose()
    {
        _connection.Dispose();
    }

    [Fact]
    public async Task CreateGroupAsync_CallsWindowsUserManagerAndAclProvisioner()
    {
        // Arrange
        var testPath = Path.Combine(Path.GetTempPath(), "test_sftp_group_" + Guid.NewGuid());
        Directory.CreateDirectory(testPath);

        try
        {
            var request = new CreateGroupRequest
            {
                Name = "Finance",
                Description = "Finance Department Shared Folder",
                RootPath = testPath,
                PermissionType = SftpPermissionType.ReadWrite,
                AccessMode = SftpAccessMode.VirtualFolder
            };

            // Act
            var (success, message, group) = await _sut.CreateGroupAsync(request);

            // Assert
            success.Should().BeTrue();
            group.Should().NotBeNull();
            group!.Name.Should().Be("Finance");

            _windowsUserManager.Received(1).EnsureLocalGroup("SFTP-Finance", Arg.Any<string?>());
            _aclProvisioner.Received(1).ProvisionPathAcl(
                Arg.Is<string>(p => p.Equals(testPath, StringComparison.OrdinalIgnoreCase)),
                "SFTP-Finance",
                SftpPermissionType.ReadWrite,
                isDirectChroot: false);

            await using var db = new AppDbContext(_dbOptions);
            var saved = await db.SftpGroups.FirstOrDefaultAsync(g => g.Name == "Finance");
            saved.Should().NotBeNull();
        }
        finally
        {
            if (Directory.Exists(testPath))
            {
                Directory.Delete(testPath, true);
            }
        }
    }

    [Fact]
    public async Task DeleteGroupAsync_RemovesGroupFromDbAndCallsOsGroupDeletion()
    {
        // Arrange
        var group = new SftpGroup
        {
            Id = "grp-123",
            Name = "Marketing",
            RootPath = @"C:\SFTPRoot\Marketing"
        };

        await using (var db = new AppDbContext(_dbOptions))
        {
            db.SftpGroups.Add(group);
            await db.SaveChangesAsync();
        }

        // Act
        var (success, message) = await _sut.DeleteGroupAsync("grp-123");

        // Assert
        success.Should().BeTrue();
        _aclProvisioner.Received(1).RemovePathAcl(@"C:\SFTPRoot\Marketing", "SFTP-Marketing");
        _windowsUserManager.Received(1).DeleteLocalGroup("SFTP-Marketing");

        await using var verifyDb = new AppDbContext(_dbOptions);
        var inDb = await verifyDb.SftpGroups.FindAsync("grp-123");
        inDb.Should().BeNull();
    }

    [Fact]
    public async Task UpdateGroupAsync_WhenRootPathChanges_RemovesAclFromOldPath()
    {
        // Arrange
        var oldPath = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "OldGroupShare_" + Guid.NewGuid()));
        var newPath = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "NewGroupShare_" + Guid.NewGuid()));

        try
        {
            await using (var db = new AppDbContext(_dbOptions))
            {
                db.SftpGroups.Add(new SftpGroup
                {
                    Id = "grp-upd",
                    Name = "Engineering",
                    RootPath = oldPath,
                    PermissionType = SftpPermissionType.ReadWrite,
                    AccessMode = SftpAccessMode.VirtualFolder
                });
                await db.SaveChangesAsync();
            }

            var req = new UpdateGroupRequest
            {
                Id = "grp-upd",
                Description = "Updated Path",
                RootPath = newPath,
                PermissionType = SftpPermissionType.ReadOnly,
                AccessMode = SftpAccessMode.VirtualFolder
            };

            // Act
            var (success, _) = await _sut.UpdateGroupAsync(req);

            // Assert
            success.Should().BeTrue();
            _aclProvisioner.Received(1).RemovePathAcl(oldPath, "SFTP-Engineering");
            _aclProvisioner.Received(1).ProvisionPathAcl(newPath, "SFTP-Engineering", SftpPermissionType.ReadOnly, false);
        }
        finally
        {
            if (Directory.Exists(oldPath)) Directory.Delete(oldPath, true);
            if (Directory.Exists(newPath)) Directory.Delete(newPath, true);
        }
    }

    [Fact]
    public async Task SyncUserJunctionsAsync_CreatesJunctionForUserCustomRootPath_InVirtualFolderMode()
    {
        // Arrange
        var tempSftpRoot = Path.Combine(Path.GetTempPath(), "TestSftpRoot_" + Guid.NewGuid());
        var customPath = Path.Combine(Path.GetTempPath(), "CustomProjectFolder");
        _sshServiceManager.SftpRoot.Returns(tempSftpRoot);

        try
        {
            await using (var db = new AppDbContext(_dbOptions))
            {
                db.SftpUsers.Add(new SftpUser
                {
                    Username = "alice",
                    AccountType = SftpAccountType.LocalWindows,
                    CustomRootPath = customPath,
                    AccessMode = SftpAccessMode.VirtualFolder
                });
                await db.SaveChangesAsync();
            }

            // Act
            await _sut.SyncUserJunctionsAsync("alice");

            // Assert
            var expectedLink = Path.Combine(tempSftpRoot, "alice", "files", "CustomProjectFolder");
            _aclProvisioner.Received(1).CreateDirectoryJunction(expectedLink, customPath);
        }
        finally
        {
            if (Directory.Exists(tempSftpRoot)) Directory.Delete(tempSftpRoot, true);
        }
    }

    [Fact]
    public async Task GetGroupAsync_ReturnsGroupWithMembers_WhenExists()
    {
        // Arrange
        string groupId;
        await using (var db = new AppDbContext(_dbOptions))
        {
            var grp = new SftpGroup
            {
                Name = "DevTeam",
                Description = "Developers Group",
                RootPath = @"C:\SFTPRoot\Groups\DevTeam",
                PermissionType = SftpPermissionType.ReadWrite,
                AccessMode = SftpAccessMode.VirtualFolder
            };
            db.SftpGroups.Add(grp);
            await db.SaveChangesAsync();
            groupId = grp.Id;
        }

        // Act
        var result = await _sut.GetGroupAsync(groupId);
        var nonExistent = await _sut.GetGroupAsync("missing_group_id");

        // Assert
        result.Should().NotBeNull();
        result!.Name.Should().Be("DevTeam");
        result.Members.Should().NotBeNull();
        nonExistent.Should().BeNull();
    }

    [Fact]
    public async Task AddUserToGroupAsync_AddsMemberAndCallsWindowsUserManager()
    {
        // Arrange
        string groupId;
        await using (var db = new AppDbContext(_dbOptions))
        {
            var grp = new SftpGroup
            {
                Name = "Marketing",
                RootPath = @"C:\SFTPRoot\Groups\Marketing",
                PermissionType = SftpPermissionType.ReadWrite,
                AccessMode = SftpAccessMode.VirtualFolder
            };
            var usr = new SftpUser
            {
                Username = "bob",
                AccountType = SftpAccountType.LocalWindows,
                AccessMode = SftpAccessMode.VirtualFolder
            };
            db.SftpGroups.Add(grp);
            db.SftpUsers.Add(usr);
            await db.SaveChangesAsync();
            groupId = grp.Id;
        }

        // Act
        var (success, msg) = await _sut.AddUserToGroupAsync(groupId, "bob", "admin");

        // Assert
        success.Should().BeTrue();
        _windowsUserManager.Received(1).AddUserToLocalGroup("SFTP-Marketing", "bob");

        await using (var db = new AppDbContext(_dbOptions))
        {
            var grp = await db.SftpGroups.Include(g => g.Members).FirstOrDefaultAsync(g => g.Id == groupId);
            grp.Should().NotBeNull();
            grp!.Members.Should().Contain(m => m.Username == "bob");
        }
    }

    [Fact]
    public async Task AddUserToGroupAsync_ReturnsError_WhenUserOrGroupNotFound()
    {
        // Act
        var (notFoundGroup, _) = await _sut.AddUserToGroupAsync("invalid_id", "alice", "admin");
        
        string groupId;
        await using (var db = new AppDbContext(_dbOptions))
        {
            var grp = new SftpGroup
            {
                Name = "Sales",
                RootPath = @"C:\SFTPRoot\Groups\Sales",
                PermissionType = SftpPermissionType.ReadOnly,
                AccessMode = SftpAccessMode.VirtualFolder
            };
            db.SftpGroups.Add(grp);
            await db.SaveChangesAsync();
            groupId = grp.Id;
        }

        var (notFoundUser, _) = await _sut.AddUserToGroupAsync(groupId, "ghostuser", "admin");

        // Assert
        notFoundGroup.Should().BeFalse();
        notFoundUser.Should().BeFalse();
    }

    [Fact]
    public async Task RemoveUserFromGroupAsync_RemovesMemberAndCallsWindowsUserManager()
    {
        // Arrange
        string groupId;
        await using (var db = new AppDbContext(_dbOptions))
        {
            var grp = new SftpGroup
            {
                Name = "HR",
                RootPath = @"C:\SFTPRoot\Groups\HR",
                PermissionType = SftpPermissionType.ReadWrite,
                AccessMode = SftpAccessMode.VirtualFolder
            };
            var usr = new SftpUser
            {
                Username = "charlie",
                AccountType = SftpAccountType.LocalWindows,
                AccessMode = SftpAccessMode.VirtualFolder
            };
            grp.Members.Add(new SftpUserGroup { Username = "charlie", GroupId = grp.Id });
            db.SftpGroups.Add(grp);
            db.SftpUsers.Add(usr);
            await db.SaveChangesAsync();
            groupId = grp.Id;
        }

        // Act
        var (success, msg) = await _sut.RemoveUserFromGroupAsync(groupId, "charlie", "admin");

        // Assert
        success.Should().BeTrue();
        _windowsUserManager.Received(1).RemoveUserFromLocalGroup("SFTP-HR", "charlie");

        await using (var db = new AppDbContext(_dbOptions))
        {
            var grp = await db.SftpGroups.Include(g => g.Members).FirstOrDefaultAsync(g => g.Id == groupId);
            grp.Should().NotBeNull();
            grp!.Members.Should().NotContain(m => m.Username == "charlie");
        }
    }
}
