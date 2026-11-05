using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using OpensshUI.Data;
using OpensshUI.Models;
using OpensshUI.Services.Auth;
using OpensshUI.Services.Security;
using Xunit;

namespace OpensshUI.Tests;

public class LdapSearchTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<AppDbContext> _dbOptions;
    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly IProtectionService _protectionService = Substitute.For<IProtectionService>();
    private readonly LdapAuthService _sut;

    public LdapSearchTests()
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

        _sut = new LdapAuthService(_dbFactory, _protectionService, NullLogger<LdapAuthService>.Instance);
    }

    public void Dispose()
    {
        _connection.Dispose();
    }

    [Fact]
    public async Task SearchAdUsersAsync_WhenLdapDisabled_ReturnsFailureWithHelpfulMessage()
    {
        // Arrange: By default LdapConfig.IsLdapEnabled is false
        // Act
        var result = await _sut.SearchAdUsersAsync("john");

        // Assert
        result.Should().NotBeNull();
        result.Success.Should().BeFalse();
        result.Users.Should().BeEmpty();
        result.Message.Should().Contain("ยังไม่ได้เปิดใช้งาน");
    }

    [Fact]
    public async Task SearchAdUsersAsync_WhenServerNotConfigured_ReturnsFailure()
    {
        // Arrange
        await using (var db = new AppDbContext(_dbOptions))
        {
            var cfg = await db.LdapConfigs.FirstOrDefaultAsync(c => c.Id == 1);
            if (cfg == null)
            {
                cfg = new LdapConfig { Id = 1, Server = "", IsLdapEnabled = true };
                db.LdapConfigs.Add(cfg);
            }
            else
            {
                cfg.Server = "";
                cfg.IsLdapEnabled = true;
            }
            await db.SaveChangesAsync();
        }

        // Act
        var result = await _sut.SearchAdUsersAsync("john");

        // Assert
        result.Should().NotBeNull();
        result.Success.Should().BeFalse();
        result.Users.Should().BeEmpty();
        result.Message.Should().Contain("ยังไม่ได้ระบุ Server");
    }

    [Fact]
    public void AdSearchResult_Defaults_AreSafeAndInitialized()
    {
        var model = new AdSearchResult();
        model.Success.Should().BeFalse();
        model.Message.Should().BeEmpty();
        model.Users.Should().NotBeNull();
        model.Users.Should().BeEmpty();
    }

    [Fact]
    public async Task TestConnectionAsync_WhenServerEmpty_ReturnsImmediateFailure()
    {
        // Arrange
        var config = new LdapConfig
        {
            Server = "",
            Port = 389
        };

        // Act
        var result = await _sut.TestConnectionAsync(config);

        // Assert
        result.Should().NotBeNull();
        result.Success.Should().BeFalse();
        result.HostReachable.Should().BeFalse();
        result.Message.Should().Contain("ระบุ LDAP Server");
    }

    [Fact]
    public async Task TestConnectionAsync_WhenPortInvalid_ReturnsImmediateFailure()
    {
        // Arrange
        var config = new LdapConfig
        {
            Server = "127.0.0.1",
            Port = 0
        };

        // Act
        var result = await _sut.TestConnectionAsync(config);

        // Assert
        result.Should().NotBeNull();
        result.Success.Should().BeFalse();
        result.HostReachable.Should().BeFalse();
        result.Message.Should().Contain("พอร์ต");
    }

    [Fact]
    public void LdapConnectionTestResult_Defaults_AreSafeAndInitialized()
    {
        var model = new LdapConnectionTestResult();
        model.Success.Should().BeFalse();
        model.HostReachable.Should().BeFalse();
        model.BindSuccessful.Should().BeFalse();
        model.BaseDnVerified.Should().BeNull();
        model.AdminGroupVerified.Should().BeNull();
        model.Details.Should().NotBeNull();
        model.Details.Should().BeEmpty();
    }

    [Fact]
    public async Task SaveConfigAsync_PreservesTrustSslCertificatesSetting()
    {
        // Arrange
        var cfg = new LdapConfig
        {
            Id = 1,
            Server = "dc01.corp.local",
            Port = 636,
            UseSsl = true,
            TrustSslCertificates = true,
            Domain = "corp.local",
            BaseDn = "DC=corp,DC=local",
            AdminGroup = "SFTP-Admins"
        };

        // Act
        await _sut.SaveConfigAsync(cfg);
        var reloaded = await _sut.GetConfigAsync();

        // Assert
        reloaded.TrustSslCertificates.Should().BeTrue();
        reloaded.UseSsl.Should().BeTrue();
        reloaded.Server.Should().Be("dc01.corp.local");
    }
}
