using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using OpensshUI.Data;
using OpensshUI.Models;
using OpensshUI.Services.Audit;
using OpensshUI.Services.Auth;
using OpensshUI.Services.Security;
using Xunit;

namespace OpensshUI.Tests;

public class WebAdminServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<AppDbContext> _dbOptions;
    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly IAuditService _auditService = Substitute.For<IAuditService>();
    private readonly WebAdminService _sut;

    public WebAdminServiceTests()
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

        _sut = new WebAdminService(_dbFactory, _auditService, NullLogger<WebAdminService>.Instance);
    }

    public void Dispose()
    {
        _connection.Dispose();
    }

    [Fact]
    public async Task CreateLocalAdminAsync_ShouldCreateUser_WhenValid()
    {
        // Act
        var result = await _sut.CreateLocalAdminAsync(
            "sec_admin",
            "Security Admin",
            "sec@corp.local",
            "StrongPassword@123",
            WebAdminRole.SuperAdmin,
            "operator1");

        // Assert
        result.Success.Should().BeTrue();
        result.Message.Should().Contain("sec_admin");

        var user = await _sut.GetAdminByUsernameAsync("sec_admin");
        user.Should().NotBeNull();
        user!.DisplayName.Should().Be("Security Admin");
        user.AccountType.Should().Be(WebAdminType.Local);
        user.Role.Should().Be(WebAdminRole.SuperAdmin);
        user.PasswordHash.Should().NotBeNullOrEmpty();
        PasswordHasher.VerifyPassword("StrongPassword@123", user.PasswordHash!).Should().BeTrue();

        await _auditService.Received(1).LogAsync(
            "CREATE_WEB_ADMIN",
            Arg.Is<string>(s => s.Contains("sec_admin")),
            true,
            "operator1");
    }

    [Fact]
    public async Task CreateLocalAdminAsync_ShouldFail_WhenUsernameTooShort()
    {
        var result = await _sut.CreateLocalAdminAsync(
            "ab",
            "Short User",
            null,
            "Password123",
            WebAdminRole.Operator,
            "admin");

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("ความยาวระหว่าง 3 ถึง 50");
    }

    [Fact]
    public async Task CreateLocalAdminAsync_ShouldFail_WhenPasswordTooShort()
    {
        var result = await _sut.CreateLocalAdminAsync(
            "validuser",
            "Valid User",
            null,
            "12345",
            WebAdminRole.Operator,
            "admin");

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("อย่างน้อย 8 ตัวอักษร");
    }

    [Fact]
    public async Task CreateLocalAdminAsync_ShouldFail_WhenUsernameAlreadyExists()
    {
        await _sut.CreateLocalAdminAsync("dupe_user", "First", null, "Password123", WebAdminRole.Operator, "admin");

        var result = await _sut.CreateLocalAdminAsync("dupe_user", "Second", null, "Password123", WebAdminRole.Operator, "admin");

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("มีอยู่ในระบบแล้ว");
    }

    [Fact]
    public async Task CreateAdAdminAsync_ShouldCreateUserWithoutPasswordHash()
    {
        var result = await _sut.CreateAdAdminAsync(
            "domain_user",
            "Domain User",
            "user@domain.com",
            WebAdminRole.Operator,
            "admin");

        result.Success.Should().BeTrue();
        var user = await _sut.GetAdminByUsernameAsync("domain_user");
        user.Should().NotBeNull();
        user!.AccountType.Should().Be(WebAdminType.ActiveDirectory);
        user.PasswordHash.Should().BeNull();
        user.Role.Should().Be(WebAdminRole.Operator);
    }

    [Fact]
    public async Task UpdateRoleAsync_ShouldPreventDemotingLastActiveSuperAdmin()
    {
        // Setup: Only 1 SuperAdmin
        await _sut.CreateLocalAdminAsync("only_super", "Super", null, "Password123", WebAdminRole.SuperAdmin, "admin");
        var admin = await _sut.GetAdminByUsernameAsync("only_super");

        // Act: Try to demote to Auditor
        var result = await _sut.UpdateRoleAsync(admin!.Id, WebAdminRole.Auditor, "only_super");

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("Super Admin คนสุดท้าย");
    }

    [Fact]
    public async Task UpdateRoleAsync_ShouldSucceed_WhenAnotherSuperAdminExists()
    {
        // Setup: 2 SuperAdmins
        await _sut.CreateLocalAdminAsync("super1", "Super 1", null, "Password123", WebAdminRole.SuperAdmin, "admin");
        await _sut.CreateLocalAdminAsync("super2", "Super 2", null, "Password123", WebAdminRole.SuperAdmin, "admin");
        var admin2 = await _sut.GetAdminByUsernameAsync("super2");

        // Act: Demote super2
        var result = await _sut.UpdateRoleAsync(admin2!.Id, WebAdminRole.Operator, "super1");

        // Assert
        result.Success.Should().BeTrue();
        var updated = await _sut.GetAdminByIdAsync(admin2.Id);
        updated!.Role.Should().Be(WebAdminRole.Operator);
    }

    [Fact]
    public async Task ResetPasswordAsync_ShouldRejectForActiveDirectoryUser()
    {
        await _sut.CreateAdAdminAsync("ad_user", "AD User", null, WebAdminRole.Operator, "admin");
        var user = await _sut.GetAdminByUsernameAsync("ad_user");

        var result = await _sut.ResetPasswordAsync(user!.Id, "NewPassword123", "admin");

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("Active Directory");
    }

    [Fact]
    public async Task ResetPasswordAsync_ShouldSucceedForLocalUser()
    {
        await _sut.CreateLocalAdminAsync("local_usr", "Local", null, "OldPassword123", WebAdminRole.Operator, "admin");
        var user = await _sut.GetAdminByUsernameAsync("local_usr");

        var result = await _sut.ResetPasswordAsync(user!.Id, "NewPassword123", "admin");

        result.Success.Should().BeTrue();
        var updated = await _sut.GetAdminByIdAsync(user.Id);
        PasswordHasher.VerifyPassword("NewPassword123", updated!.PasswordHash!).Should().BeTrue();
    }

    [Fact]
    public async Task ToggleStatusAsync_ShouldPreventDeactivatingSelf()
    {
        await _sut.CreateLocalAdminAsync("self_admin", "Self", null, "Password123", WebAdminRole.SuperAdmin, "admin");
        var user = await _sut.GetAdminByUsernameAsync("self_admin");

        var result = await _sut.ToggleStatusAsync(user!.Id, "self_admin");

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("บัญชีของตนเอง");
    }

    [Fact]
    public async Task ToggleStatusAsync_ShouldPreventDeactivatingLastSuperAdmin()
    {
        await _sut.CreateLocalAdminAsync("sole_super", "Sole", null, "Password123", WebAdminRole.SuperAdmin, "admin");
        var user = await _sut.GetAdminByUsernameAsync("sole_super");

        var result = await _sut.ToggleStatusAsync(user!.Id, "other_operator");

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("Super Admin บัญชีสุดท้าย");
    }

    [Fact]
    public async Task DeleteAdminAsync_ShouldPreventDeletingSelf()
    {
        await _sut.CreateLocalAdminAsync("admin_me", "Me", null, "Password123", WebAdminRole.SuperAdmin, "admin");
        var user = await _sut.GetAdminByUsernameAsync("admin_me");

        var result = await _sut.DeleteAdminAsync(user!.Id, "admin_me");

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("บัญชีของตนเอง");
    }

    [Fact]
    public async Task DeleteAdminAsync_ShouldPreventDeletingLastSuperAdmin()
    {
        await _sut.CreateLocalAdminAsync("last_super", "Last", null, "Password123", WebAdminRole.SuperAdmin, "admin");
        var user = await _sut.GetAdminByUsernameAsync("last_super");

        var result = await _sut.DeleteAdminAsync(user!.Id, "someone_else");

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("Super Admin บัญชีสุดท้าย");
    }

    [Fact]
    public async Task DeleteAdminAsync_ShouldSucceed_ForSecondaryUser()
    {
        await _sut.CreateLocalAdminAsync("master_admin", "Master", null, "Password123", WebAdminRole.SuperAdmin, "system");
        await _sut.CreateLocalAdminAsync("temp_admin", "Temp", null, "Password123", WebAdminRole.Operator, "master_admin");
        var tempUser = await _sut.GetAdminByUsernameAsync("temp_admin");

        var result = await _sut.DeleteAdminAsync(tempUser!.Id, "master_admin");

        result.Success.Should().BeTrue();
        var check = await _sut.GetAdminByIdAsync(tempUser.Id);
        check.Should().BeNull();
    }

    [Fact]
    public void UserSessionState_ShouldReflectRolesAccurately()
    {
        var session = new UserSessionState();

        // 1. SuperAdmin
        session.SetUser("boss", "Boss Admin", true, WebAdminRole.SuperAdmin);
        session.CanManageSystem.Should().BeTrue();
        session.CanManageSftp.Should().BeTrue();
        session.IsReadOnly.Should().BeFalse();

        // 2. Operator
        session.SetUser("op", "Operator Person", true, WebAdminRole.Operator);
        session.CanManageSystem.Should().BeFalse();
        session.CanManageSftp.Should().BeTrue();
        session.IsReadOnly.Should().BeFalse();

        // 3. Auditor
        session.SetUser("audit", "External Auditor", true, WebAdminRole.Auditor);
        session.CanManageSystem.Should().BeFalse();
        session.CanManageSftp.Should().BeFalse();
        session.IsReadOnly.Should().BeTrue();
    }

    [Fact]
    public async Task LdapAuthService_ShouldAuthenticateLocalWebAdmin_WithCorrectRole()
    {
        var protection = Substitute.For<IProtectionService>();
        var authService = new LdapAuthService(_dbFactory, protection, NullLogger<LdapAuthService>.Instance);

        // Create an Operator local admin
        await _sut.CreateLocalAdminAsync("op_user", "Operator User", null, "ValidPassword@123", WebAdminRole.Operator, "admin");

        // Act
        var result = await authService.AuthenticateAsync("op_user", "ValidPassword@123");

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Username.Should().Be("op_user");
        result.Role.Should().Be(WebAdminRole.Operator);
        result.IsAdmin.Should().BeTrue();
    }

    [Fact]
    public async Task LdapAuthService_ShouldRejectDeactivatedWebAdmin()
    {
        var protection = Substitute.For<IProtectionService>();
        var authService = new LdapAuthService(_dbFactory, protection, NullLogger<LdapAuthService>.Instance);

        // Create and deactivate an admin
        await _sut.CreateLocalAdminAsync("banned_user", "Banned", null, "ValidPassword@123", WebAdminRole.Operator, "admin");
        var user = await _sut.GetAdminByUsernameAsync("banned_user");
        await _sut.ToggleStatusAsync(user!.Id, "admin");

        // Act
        var result = await authService.AuthenticateAsync("banned_user", "ValidPassword@123");

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.ErrorMessage.Should().Contain("ระงับการใช้งาน");
    }
}
