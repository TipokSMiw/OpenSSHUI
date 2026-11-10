using System.Diagnostics;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using NSubstitute;
using OpensshUI.Models;
using OpensshUI.Services.Audit;
using OpensshUI.Services.OpenSsh;
using Xunit;

namespace OpensshUI.Tests;

public class SftpSessionServiceTests
{
    private readonly ILogger<SftpSessionService> _logger = Substitute.For<ILogger<SftpSessionService>>();
    private readonly IAuditService _auditService = Substitute.For<IAuditService>();
    private readonly IConfiguration _configuration;
    private readonly SftpSessionService _sut;

    public SftpSessionServiceTests()
    {
        var configValues = new Dictionary<string, string?>
        {
            ["SftpSettings:Port"] = "22"
        };
        _configuration = new ConfigurationBuilder().AddInMemoryCollection(configValues).Build();
        _sut = new SftpSessionService(_logger, _auditService, _configuration)
        {
            IsDemoMode = true // Start in Demo Mode for isolated deterministic testing
        };
    }

    [Fact]
    public async Task GetActiveSessionsAsync_InDemoMode_ReturnsMockSessionsWithCorrectCounts()
    {
        // Act
        var overview = await _sut.GetActiveSessionsAsync();

        // Assert
        overview.Should().NotBeNull();
        overview.TotalActiveSessions.Should().Be(8);
        overview.UniqueUsersCount.Should().Be(3);
        overview.Sessions.Should().HaveCount(8);
        overview.IsLiveWin32Available.Should().BeTrue();
        overview.StatusNote.Should().Contain("Demo Mock Mode");

        var first = overview.Sessions.First();
        first.Duration.Should().BeGreaterThan(TimeSpan.Zero);
        first.RemoteIp.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task GetActiveSessionsAsync_MarksExcessiveSessions_WhenUserHasMoreThan5Sessions()
    {
        // Act
        var overview = await _sut.GetActiveSessionsAsync();

        // Assert
        // corp_transfer has 6 sessions in mock data, should be flagged
        var corpSessions = overview.Sessions.Where(s => s.Username == "corp_transfer").ToList();
        corpSessions.Should().HaveCount(6);
        corpSessions.Should().OnlyContain(s => s.IsExcessiveConnection);

        // finance_audit and deploy_bot have 1 session each, should not be excessive
        var normalSessions = overview.Sessions.Where(s => s.Username != "corp_transfer").ToList();
        normalSessions.Should().HaveCount(2);
        normalSessions.Should().OnlyContain(s => !s.IsExcessiveConnection);
    }

    [Fact]
    public async Task TerminateSessionAsync_InDemoMode_RemovesTargetSessionAndLogsAudit()
    {
        // Arrange
        const int targetPid = 10420; // finance_audit

        // Act
        var (ok, msg) = await _sut.TerminateSessionAsync(targetPid, "operator1");
        var overview = await _sut.GetActiveSessionsAsync();

        // Assert
        ok.Should().BeTrue();
        msg.Should().Contain("10420");
        overview.Sessions.Should().NotContain(s => s.ProcessId == targetPid);
        overview.TotalActiveSessions.Should().Be(7);

        await _auditService.Received(1).LogAsync(
            "SFTP_SESSION_TERMINATED",
            Arg.Is<string>(m => m.Contains("10420")),
            true,
            "operator1");
    }

    [Fact]
    public async Task TerminateUserSessionsAsync_InDemoMode_RemovesAllSessionsForCanonicalUserAndLogsAudit()
    {
        // Arrange
        // Test canonical username normalization (e.g. DOMAIN\corp_transfer or corp_transfer)
        const string targetUserWithDomain = @"CORP\corp_transfer";

        // Act
        var (ok, msg) = await _sut.TerminateUserSessionsAsync(targetUserWithDomain, "superadmin");
        var overview = await _sut.GetActiveSessionsAsync();

        // Assert
        ok.Should().BeTrue();
        msg.Should().Contain("6");
        overview.Sessions.Should().NotContain(s => s.Username.Equals("corp_transfer", StringComparison.OrdinalIgnoreCase));
        overview.TotalActiveSessions.Should().Be(2);

        await _auditService.Received(1).LogAsync(
            "SFTP_USER_SESSIONS_TERMINATED",
            Arg.Is<string>(m => m.Contains("corp_transfer") && m.Contains("6")),
            true,
            "superadmin");
    }

    [Fact]
    public async Task TerminateUserSessionsAsync_WhenUserNotFound_ReturnsFalse()
    {
        // Act
        var (ok, msg) = await _sut.TerminateUserSessionsAsync("non_existent_user", "admin");

        // Assert
        ok.Should().BeFalse();
        msg.Should().Contain("ไม่พบเซสชัน");
    }

    [Fact]
    public async Task TerminateSessionAsync_LiveSafetyGuard_RejectsNonExistentPid()
    {
        // Arrange: Switch to Live Mode
        _sut.IsDemoMode = false;

        // Act: Attempt to kill a non-existent PID (e.g. 99999999)
        var (ok, msg) = await _sut.TerminateSessionAsync(99999999, "operator");

        // Assert
        ok.Should().BeFalse();
        msg.Should().Contain("ไม่พบโพรเซส");
    }

    [Fact]
    public async Task TerminateSessionAsync_LiveSafetyGuard_RejectsNonOpenSshProcess()
    {
        // Arrange: Switch to Live Mode and target current process (testhost / dotnet)
        _sut.IsDemoMode = false;
        var currentPid = Process.GetCurrentProcess().Id;

        // Act: Attempt to terminate current process
        var (ok, msg) = await _sut.TerminateSessionAsync(currentPid, "operator");

        // Assert: Safety Guard MUST block and reject killing non-sshd processes!
        ok.Should().BeFalse();
        msg.Should().Contain("Safety Guard");
        msg.Should().Contain("ไม่ใช่โพรเซส OpenSSH");

        await _auditService.Received(1).LogAsync(
            "SFTP_SESSION_TERMINATE_BLOCKED",
            Arg.Is<string>(m => m.Contains("Safety Guard")),
            false,
            "operator");
    }

    [Fact]
    public void ToggleDemoMode_FlipsModeAndResetsMockSessions()
    {
        // Arrange: Start in Demo Mode (true)
        _sut.IsDemoMode.Should().BeTrue();

        // Act & Assert 1: Toggle to false
        _sut.ToggleDemoMode();
        _sut.IsDemoMode.Should().BeFalse();

        // Act & Assert 2: Toggle back to true
        _sut.ToggleDemoMode();
        _sut.IsDemoMode.Should().BeTrue();
    }
}
