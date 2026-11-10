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
using OpensshUI.Services.Users;
using Xunit;

namespace OpensshUI.Tests;

public class SftpUserServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<AppDbContext> _dbOptions;
    private readonly IDbContextFactory<AppDbContext> _dbFactory;

    private readonly INativeAclProvisioner _aclProvisioner = Substitute.For<INativeAclProvisioner>();
    private readonly IWindowsUserManager _windowsUserManager = Substitute.For<IWindowsUserManager>();
    private readonly IOpenSshServiceManager _sshServiceManager = Substitute.For<IOpenSshServiceManager>();
    private readonly ISftpGroupService _groupService = Substitute.For<ISftpGroupService>();
    private readonly IAuditService _auditService = Substitute.For<IAuditService>();
    private readonly ISshKeyGenerator _sshKeyGenerator = Substitute.For<ISshKeyGenerator>();

    private readonly SftpUserService _sut;

    public SftpUserServiceTests()
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

        _sshServiceManager.SftpRoot.Returns(@"C:\SFTPRoot");
        _sshServiceManager.KeysPath.Returns(@"C:\ProgramData\ssh\keys");

        _sut = new SftpUserService(
            _dbFactory,
            _aclProvisioner,
            _windowsUserManager,
            _sshServiceManager,
            _groupService,
            _auditService,
            _sshKeyGenerator,
            NullLogger<SftpUserService>.Instance);
    }

    public void Dispose()
    {
        _connection.Dispose();
    }

    [Fact]
    public async Task CreateUserAsync_LocalWindows_CallsWindowsUserManagerAndAclProvisioner()
    {
        // Arrange
        _windowsUserManager.CreateOrUpdateLocalUser("john_doe", "SecretPass123!", true).Returns(true);

        var request = new CreateUserRequest
        {
            Username = "john_doe",
            DisplayName = "John Doe",
            AccountType = SftpAccountType.LocalWindows,
            Password = "SecretPass123!"
        };

        // Act
        var result = await _sut.CreateUserAsync(request);

        // Assert
        result.Success.Should().BeTrue();
        _windowsUserManager.Received(1).CreateOrUpdateLocalUser("john_doe", "SecretPass123!", true);
        _aclProvisioner.Received(1).ProvisionUserChroot(@"C:\SFTPRoot", "john_doe");

        await using var db = new AppDbContext(_dbOptions);
        var userInDb = await db.SftpUsers.FirstOrDefaultAsync(u => u.Username == "john_doe");
        userInDb.Should().NotBeNull();
        userInDb!.DisplayName.Should().Be("John Doe");
        userInDb.IsActive.Should().BeTrue();
    }

    [Fact]
    public async Task CreateUserAsync_ActiveDirectory_AddsToSftpUsersLocalGroupAndDoesNotCallCreateLocalUser()
    {
        // Arrange
        var request = new CreateUserRequest
        {
            Username = "ad_user1",
            DisplayName = "AD User One",
            AccountType = SftpAccountType.ActiveDirectory
        };

        // Act
        var result = await _sut.CreateUserAsync(request);

        // Assert
        result.Success.Should().BeTrue();
        // Should NOT create local windows user account with password
        _windowsUserManager.DidNotReceiveWithAnyArgs().CreateOrUpdateLocalUser(default!, default!, default);
        // MUST add user to SFTP-Users local group for OpenSSH chroot rules
        _windowsUserManager.Received(1).AddUserToLocalGroup("SFTP-Users", "ad_user1");
        _aclProvisioner.Received(1).ProvisionUserChroot(@"C:\SFTPRoot", "ad_user1");

        await using var db = new AppDbContext(_dbOptions);
        var userInDb = await db.SftpUsers.FirstOrDefaultAsync(u => u.Username == "ad_user1");
        userInDb.Should().NotBeNull();
        userInDb!.DisplayName.Should().Be("AD User One");
        userInDb.AccountType.Should().Be(SftpAccountType.ActiveDirectory);
        userInDb.IsActive.Should().BeTrue();
    }

    [Fact]
    public async Task CreateUserAsync_ActiveDirectory_WithGroups_AddsToBothSftpUsersAndAssignedGroups()
    {
        // Arrange
        await using (var db = new AppDbContext(_dbOptions))
        {
            db.SftpGroups.Add(new SftpGroup { Id = "grp-dev", Name = "Developers", RootPath = @"C:\SFTPRoot\shared\dev" });
            await db.SaveChangesAsync();
        }

        var request = new CreateUserRequest
        {
            Username = "ad_dev_user",
            DisplayName = "AD Developer",
            AccountType = SftpAccountType.ActiveDirectory,
            GroupIds = new List<string> { "grp-dev" }
        };

        // Act
        var result = await _sut.CreateUserAsync(request);

        // Assert
        result.Success.Should().BeTrue();
        _windowsUserManager.Received(1).AddUserToLocalGroup("SFTP-Users", "ad_dev_user");
        _windowsUserManager.Received(1).AddUserToLocalGroup("SFTP-Developers", "ad_dev_user");
        await _groupService.Received(1).SyncUserJunctionsAsync("ad_dev_user");
    }

    [Fact]
    public async Task DeleteUserAsync_ActiveDirectory_RemovesFromSftpUsersGroupAndDoesNotDeleteLocalAccount()
    {
        // Arrange
        await using (var db = new AppDbContext(_dbOptions))
        {
            db.SftpUsers.Add(new SftpUser
            {
                Username = "ad_user_delete",
                AccountType = SftpAccountType.ActiveDirectory,
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        // Act
        var result = await _sut.DeleteUserAsync("ad_user_delete", deleteFiles: false);

        // Assert
        result.Success.Should().BeTrue();
        // Should NOT attempt deleting local Windows user
        _windowsUserManager.DidNotReceive().DeleteLocalUser("ad_user_delete");
        // MUST remove from SFTP-Users local group
        _windowsUserManager.Received(1).RemoveUserFromLocalGroup("SFTP-Users", "ad_user_delete");

        await using var verifyDb = new AppDbContext(_dbOptions);
        var user = await verifyDb.SftpUsers.FindAsync("ad_user_delete");
        user.Should().BeNull();
    }

    [Fact]
    public async Task CreateUserAsync_WhenUserAlreadyExists_ReturnsFailureWithoutCallingOs()
    {
        // Arrange
        await using (var db = new AppDbContext(_dbOptions))
        {
            db.SftpUsers.Add(new SftpUser { Username = "existing_user" });
            await db.SaveChangesAsync();
        }

        var request = new CreateUserRequest
        {
            Username = "existing_user",
            AccountType = SftpAccountType.LocalWindows,
            Password = "SecretPass123!"
        };

        // Act
        var result = await _sut.CreateUserAsync(request);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("already exists");
        _windowsUserManager.DidNotReceiveWithAnyArgs().CreateOrUpdateLocalUser(default!, default!, default);
        _aclProvisioner.DidNotReceiveWithAnyArgs().ProvisionUserChroot(default!, default!);
    }

    [Fact]
    public async Task UpdateUserStatusAsync_UpdatesDatabaseAndCallsWindowsUserManager()
    {
        // Arrange
        await using (var db = new AppDbContext(_dbOptions))
        {
            db.SftpUsers.Add(new SftpUser
            {
                Username = "active_user",
                AccountType = SftpAccountType.LocalWindows,
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        // Act
        var result = await _sut.UpdateUserStatusAsync("active_user", false);

        // Assert
        result.Success.Should().BeTrue();
        _windowsUserManager.Received(1).CreateOrUpdateLocalUser("active_user", "", false);

        await using var verifyDb = new AppDbContext(_dbOptions);
        var user = await verifyDb.SftpUsers.FindAsync("active_user");
        user!.IsActive.Should().BeFalse();
    }

    [Fact]
    public async Task DeleteUserAsync_RemovesUserFromDbAndCallsOsDeletion()
    {
        // Arrange
        await using (var db = new AppDbContext(_dbOptions))
        {
            db.SftpUsers.Add(new SftpUser
            {
                Username = "delete_me",
                AccountType = SftpAccountType.LocalWindows,
                IsActive = true
            });
            await db.SaveChangesAsync();
        }

        // Act
        var result = await _sut.DeleteUserAsync("delete_me", deleteFiles: false);

        // Assert
        result.Success.Should().BeTrue();
        _windowsUserManager.Received(1).DeleteLocalUser("delete_me");

        await using var verifyDb = new AppDbContext(_dbOptions);
        var user = await verifyDb.SftpUsers.FindAsync("delete_me");
        user.Should().BeNull();
    }

    [Fact]
    public async Task AddPublicKeyAsync_WhenDuplicateFingerprintAdded_ReturnsFailure()
    {
        // Arrange
        const string sampleKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@host";
        await using (var db = new AppDbContext(_dbOptions))
        {
            db.SftpUsers.Add(new SftpUser { Username = "key_user", AccountType = SftpAccountType.LocalWindows });
            await db.SaveChangesAsync();
        }

        // Act
        var first = await _sut.AddPublicKeyAsync("key_user", sampleKey);
        var second = await _sut.AddPublicKeyAsync("key_user", sampleKey);

        // Assert
        first.Success.Should().BeTrue();
        second.Success.Should().BeFalse();
        second.Message.Should().Contain("already exists");
    }

    [Fact]
    public async Task UpdateUserAsync_WhenCustomRootPathChanges_RemovesAclFromOldPath()
    {
        // Arrange
        var oldPath = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "OldUserCustomPath"));
        var newPath = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "NewUserCustomPath"));

        await using (var db = new AppDbContext(_dbOptions))
        {
            db.SftpUsers.Add(new SftpUser
            {
                Username = "custom_user",
                AccountType = SftpAccountType.LocalWindows,
                CustomRootPath = oldPath,
                AccessMode = SftpAccessMode.VirtualFolder
            });
            await db.SaveChangesAsync();
        }

        var updateReq = new UpdateUserRequest
        {
            Username = "custom_user",
            DisplayName = "Custom User",
            CustomRootPath = newPath,
            CustomPermissionType = SftpPermissionType.ReadOnly,
            AccessMode = SftpAccessMode.VirtualFolder
        };

        // Act
        var result = await _sut.UpdateUserAsync(updateReq);

        // Assert
        result.Success.Should().BeTrue();
        _aclProvisioner.Received(1).RemovePathAcl(oldPath, "custom_user");
        _aclProvisioner.Received(1).ProvisionPathAcl(newPath, "custom_user", SftpPermissionType.ReadOnly, false);
    }

    [Fact]
    public async Task DeleteUserAsync_WhenUserHasCustomRootPath_RemovesAclFromCustomPath()
    {
        // Arrange
        var customPath = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "DeleteUserCustomPath"));
        await using (var db = new AppDbContext(_dbOptions))
        {
            db.SftpUsers.Add(new SftpUser
            {
                Username = "del_custom_user",
                AccountType = SftpAccountType.LocalWindows,
                CustomRootPath = customPath
            });
            await db.SaveChangesAsync();
        }

        // Act
        var result = await _sut.DeleteUserAsync("del_custom_user", deleteFiles: false);

        // Assert
        result.Success.Should().BeTrue();
        _aclProvisioner.Received(1).RemovePathAcl(customPath, "del_custom_user");
    }

    [Fact]
    public async Task GenerateAutomationKeyAsync_ValidRequest_RegistersPublicKeyAndReturnsPrivateKey()
    {
        // Arrange
        var username = "auto_user_1";
        await using (var db = new AppDbContext(_dbOptions))
        {
            db.SftpUsers.Add(new SftpUser { Username = username, AccountType = SftpAccountType.LocalWindows });
            await db.SaveChangesAsync();
        }

        var mockResult = new SshKeyGenerateResult
        {
            Success = true,
            KeyType = "ssh-ed25519",
            PublicKeyOpenSsh = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGenFakeKey auto_user_1",
            PrivateKeyPem = "-----BEGIN OPENSSH PRIVATE KEY-----\nFakePrivateKey\n-----END OPENSSH PRIVATE KEY-----",
            FingerprintSha256 = "SHA256:TestFingerprint12345",
            Comment = "automation-etl-task"
        };

        _sshKeyGenerator.GenerateKeyPairAsync("ed25519", "automation-etl-task", null)
            .Returns(Task.FromResult(mockResult));

        // Act
        var (success, message, result) = await _sut.GenerateAutomationKeyAsync(new GenerateAutomationKeyRequest
        {
            Username = username,
            KeyType = "ed25519",
            Comment = "automation-etl-task"
        });

        // Assert
        success.Should().BeTrue();
        result.Should().NotBeNull();
        result!.PrivateKeyPem.Should().Contain("FakePrivateKey");

        // Verify Public Key is in Database
        await using (var db = new AppDbContext(_dbOptions))
        {
            var user = await db.SftpUsers.Include(u => u.PublicKeys).FirstOrDefaultAsync(u => u.Username == username);
            user.Should().NotBeNull();
            user!.PublicKeys.Should().ContainSingle();
            var savedKey = user.PublicKeys.First();
            savedKey.KeyType.Should().Be("ssh-ed25519");
            savedKey.FingerprintSha256.Should().Be("SHA256:TestFingerprint12345");
            savedKey.Comment.Should().Be("automation-etl-task");
        }

        // Verify WriteUserKeysFile was called with the public key
        _aclProvisioner.Received(1).WriteUserKeysFile(@"C:\ProgramData\ssh\keys", username, Arg.Is<List<string>>(l => l.Contains(mockResult.PublicKeyOpenSsh)));
        await _auditService.Received(1).LogAsync("KEY_GENERATE", Arg.Any<string>(), true, "admin");
    }

    [Fact]
    public async Task GenerateAutomationKeyAsync_UserNotFound_ReturnsError()
    {
        var (success, message, result) = await _sut.GenerateAutomationKeyAsync(new GenerateAutomationKeyRequest
        {
            Username = "nonexistent_user",
            KeyType = "ed25519"
        });

        success.Should().BeFalse();
        message.Should().Contain("not found");
        result.Should().BeNull();
    }

    [Fact]
    public async Task GenerateAutomationKeyAsync_GeneratorFails_LogsAuditAndReturnsError()
    {
        // Arrange
        var username = "auto_user_fail";
        await using (var db = new AppDbContext(_dbOptions))
        {
            db.SftpUsers.Add(new SftpUser { Username = username, AccountType = SftpAccountType.LocalWindows });
            await db.SaveChangesAsync();
        }

        _sshKeyGenerator.GenerateKeyPairAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(Task.FromResult(new SshKeyGenerateResult { Success = false, ErrorMessage = "OS error occurred" }));

        // Act
        var (success, message, result) = await _sut.GenerateAutomationKeyAsync(new GenerateAutomationKeyRequest
        {
            Username = username,
            KeyType = "ed25519"
        });

        // Assert
        success.Should().BeFalse();
        message.Should().Be("OS error occurred");
        result.Should().BeNull();
        await _auditService.Received(1).LogAsync("KEY_GENERATE_FAIL", Arg.Any<string>(), false, "admin");
    }

    [Fact]
    public async Task GenerateAutomationKeyAsync_ZeroKnowledge_NeverStoresPrivateKeyInDatabase()
    {
        // Arrange
        var username = "zk_user";
        await using (var db = new AppDbContext(_dbOptions))
        {
            db.SftpUsers.Add(new SftpUser { Username = username, AccountType = SftpAccountType.LocalWindows });
            await db.SaveChangesAsync();
        }

        var secretPrivateData = "SUPER_SECRET_PRIVATE_KEY_NEVER_PERSIST";
        var mockResult = new SshKeyGenerateResult
        {
            Success = true,
            KeyType = "ssh-ed25519",
            PublicKeyOpenSsh = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIZkKey zk_user",
            PrivateKeyPem = $"-----BEGIN OPENSSH PRIVATE KEY-----\n{secretPrivateData}\n-----END OPENSSH PRIVATE KEY-----",
            FingerprintSha256 = "SHA256:ZKTestFingerprint",
            Comment = "zk-test"
        };

        _sshKeyGenerator.GenerateKeyPairAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(Task.FromResult(mockResult));

        // Act
        var (success, _, result) = await _sut.GenerateAutomationKeyAsync(new GenerateAutomationKeyRequest
        {
            Username = username,
            KeyType = "ed25519"
        });

        // Assert
        success.Should().BeTrue();

        // Query the entire SQLite database to verify the secret private key was NEVER stored in any field
        await using (var db = new AppDbContext(_dbOptions))
        {
            var allKeys = await db.SshPublicKeys.ToListAsync();
            foreach (var key in allKeys)
            {
                key.RawPublicKey.Should().NotContain(secretPrivateData);
                key.FingerprintSha256.Should().NotContain(secretPrivateData);
                (key.Comment ?? "").Should().NotContain(secretPrivateData);
            }
        }
    }

    [Fact]
    public async Task GetUserAsync_ReturnsUserWithDetails_WhenExists()
    {
        // Arrange
        await using (var db = new AppDbContext(_dbOptions))
        {
            var user = new SftpUser
            {
                Username = "dave",
                AccountType = SftpAccountType.LocalWindows,
                AccessMode = SftpAccessMode.VirtualFolder,
                PublicKeys = new List<SshPublicKey>
                {
                    new SshPublicKey
                    {
                        KeyType = "ssh-ed25519",
                        RawPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDaveKey dave",
                        FingerprintSha256 = "SHA256:DaveFingerprint"
                    }
                }
            };
            db.SftpUsers.Add(user);
            await db.SaveChangesAsync();
        }

        // Act
        var result = await _sut.GetUserAsync("dave");
        var nonExistent = await _sut.GetUserAsync("non_existent_user");

        // Assert
        result.Should().NotBeNull();
        result!.Username.Should().Be("dave");
        result.PublicKeys.Should().HaveCount(1);
        nonExistent.Should().BeNull();
    }
}
