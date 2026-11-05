using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using OpensshUI.Data;
using OpensshUI.Models;
using OpensshUI.Services.OpenSsh;

namespace OpensshUI.Tests;

public class GroupAndJunctionTests
{
    [Fact]
    public void OpenSshServiceManager_ShouldGenerateCorrectManagedBlockWithRules()
    {
        var manager = new OpenSshServiceManager(NullLogger<OpenSshServiceManager>.Instance);

        var rules = new List<DirectChrootRule>
        {
            new DirectChrootRule
            {
                IsGroup = false,
                Identifier = "alice",
                RootPath = @"D:\SFTP_Alice"
            },
            new DirectChrootRule
            {
                IsGroup = true,
                Identifier = "SFTP-Marketing",
                RootPath = @"D:\SFTPShare\Marketing"
            }
        };

        var block = manager.GenerateManagedBlock(rules, @"C:\SFTPRoot", @"C:\ProgramData\ssh\keys");

        Assert.Contains(OpenSshServiceManager.BlockHeader, block);
        Assert.Contains(OpenSshServiceManager.BlockFooter, block);

        // Verify Match User alice comes first
        Assert.Contains("Match User alice", block);
        Assert.Contains(@"ChrootDirectory D:\SFTP_Alice", block);

        // Verify Match Group SFTP-Marketing comes next
        Assert.Contains("Match Group SFTP-Marketing", block);
        Assert.Contains(@"ChrootDirectory D:\SFTPShare\Marketing", block);

        // Verify generic Match Group SFTP-Users comes last
        Assert.Contains("Match Group SFTP-Users", block);
        Assert.Contains(@"ChrootDirectory C:\SFTPRoot\%u", block);

        // Ensure ordering: Match User before Match Group SFTP-Marketing before Match Group SFTP-Users
        int userIndex = block.IndexOf("Match User alice");
        int groupIndex = block.IndexOf("Match Group SFTP-Marketing");
        int genericIndex = block.IndexOf("Match Group SFTP-Users");

        Assert.True(userIndex < groupIndex, "Specific user match should appear before group match");
        Assert.True(groupIndex < genericIndex, "Specific group match should appear before generic SFTP-Users match");
    }

    [Fact]
    public void WindowsUserManager_ShouldFormatOsGroupNameProperly()
    {
        Assert.Equal("SFTP-Marketing", WindowsUserManager.ToOsGroupName("Marketing"));
        Assert.Equal("SFTP-Dev_Team", WindowsUserManager.ToOsGroupName("Dev Team"));
        Assert.Equal("SFTP-Finance", WindowsUserManager.ToOsGroupName("SFTP-Finance"));
    }

    [Fact]
    public void NativeAclProvisioner_ShouldCreateAndSafelyRemoveDirectoryJunction_WhenPermitted()
    {
        var provisioner = new NativeAclProvisioner(NullLogger<NativeAclProvisioner>.Instance);

        var tempBase = Path.Combine(Path.GetTempPath(), "JunctionTest_" + Guid.NewGuid().ToString("N"));
        var targetDir = Path.Combine(tempBase, "OriginalData");
        var linkDir = Path.Combine(tempBase, "UserHome", "files", "LinkedShare");

        try
        {
            Directory.CreateDirectory(targetDir);
            var testFilePath = Path.Combine(targetDir, "important_doc.txt");
            File.WriteAllText(testFilePath, "Confidential Project Data");

            // Attempt Junction creation
            bool created = provisioner.CreateDirectoryJunction(linkDir, targetDir);
            
            if (created)
            {
                Assert.True(Directory.Exists(linkDir), "Junction link directory should exist");

                // Verify file is accessible through the link
                var linkedFilePath = Path.Combine(linkDir, "important_doc.txt");
                Assert.True(File.Exists(linkedFilePath), "Target file must be accessible through junction link");
                Assert.Equal("Confidential Project Data", File.ReadAllText(linkedFilePath));

                // Delete Junction safely
                bool removed = provisioner.RemoveDirectoryJunction(linkDir);
                Assert.True(removed, "Junction removal should succeed");
                Assert.False(Directory.Exists(linkDir), "Junction link should no longer exist");

                // CRITICAL: Verify Target data is 100% PRESERVED!
                Assert.True(Directory.Exists(targetDir), "Target original directory must still exist!");
                Assert.True(File.Exists(testFilePath), "Target file must still exist and never be deleted!");
                Assert.Equal("Confidential Project Data", File.ReadAllText(testFilePath));
            }
            else
            {
                // In unprivileged sandboxes or environments where mklink /J is restricted,
                // verify that target data was not damaged
                Assert.True(Directory.Exists(targetDir));
                Assert.True(File.Exists(testFilePath));
            }
        }
        finally
        {
            if (Directory.Exists(tempBase))
            {
                try { Directory.Delete(tempBase, true); } catch { }
            }
        }
    }

    [Fact]
    public async Task AppDbContext_ShouldPersistGroupsAndMembersWithMigrations()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();

        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(connection)
            .Options;

        // Initialize and apply custom migrations
        using (var db = new AppDbContext(options))
        {
            await db.Database.EnsureCreatedAsync();
            await db.ApplyCustomMigrationsAsync();

            // Create user
            var user = new SftpUser
            {
                Username = "bob",
                DisplayName = "Bob Builder",
                AccountType = SftpAccountType.LocalWindows,
                HomeDirectory = @"C:\SFTPRoot\bob",
                CustomRootPath = @"D:\SFTPShare\BobSpecial",
                CustomPermissionType = SftpPermissionType.ReadWrite,
                AccessMode = SftpAccessMode.VirtualFolder
            };
            db.SftpUsers.Add(user);

            // Create group
            var group = new SftpGroup
            {
                Name = "DevOps",
                Description = "Engineering Operations",
                RootPath = @"D:\Projects\DevOps",
                PermissionType = SftpPermissionType.ReadWrite,
                AccessMode = SftpAccessMode.VirtualFolder
            };
            db.SftpGroups.Add(group);

            // Add member
            group.Members.Add(new SftpUserGroup
            {
                Username = "bob",
                GroupId = group.Id
            });

            await db.SaveChangesAsync();
        }

        // Query back in new context instance using the same open connection
        using (var db2 = new AppDbContext(options))
        {
            var loadedGroup = await db2.SftpGroups
                .Include(g => g.Members)
                .ThenInclude(m => m.User)
                .FirstOrDefaultAsync(g => g.Name == "DevOps");

            Assert.NotNull(loadedGroup);
            Assert.Equal(@"D:\Projects\DevOps", loadedGroup.RootPath);
            Assert.Single(loadedGroup.Members);
            Assert.Equal("bob", loadedGroup.Members[0].Username);
            Assert.Equal(@"D:\SFTPShare\BobSpecial", loadedGroup.Members[0].User?.CustomRootPath);
        }
    }
}
