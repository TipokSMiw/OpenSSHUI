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

    [Fact]
    public async Task TerminateSessionAsync_WithSessionInfo_CallsTcpResetSuccessfullyAndProtectsMasterService()
    {
        // Arrange
        var testService = new TestableSftpSessionService(_logger, _auditService, _configuration)
        {
            IsDemoMode = false,
            MockServicePid = 6112
        };

        var session = new SftpSessionInfo
        {
            SessionId = "sess-6112-20633",
            ProcessId = 6112,
            ProcessName = "sshd",
            Username = "TipokS",
            RemoteIp = "172.16.232.19",
            RemotePort = 20633,
            LocalPort = 22,
            RawLocalAddr = 0x0100007F, // 127.0.0.1
            RawLocalPort = 22,
            RawRemoteAddr = 0x13E810AC, // 172.16.232.19
            RawRemotePort = 20633,
            IsMasterServiceProcess = true
        };

        // Act
        var (ok, msg) = await testService.TerminateSessionAsync(session, "superadmin");

        // Assert
        ok.Should().BeTrue();
        msg.Should().Contain("TipokS");
        msg.Should().Contain("ได้รับการคุ้มกัน");
        testService.TcpResetCalled.Should().BeTrue();

        await _auditService.Received(1).LogAsync(
            "SFTP_SESSION_TERMINATED",
            Arg.Is<string>(m => m.Contains("TipokS") && m.Contains("ได้รับการคุ้มกัน")),
            true,
            "superadmin");
    }

    [Fact]
    public async Task TerminateSessionAsync_BySessionId_InDemoMode_TerminatesTargetSession()
    {
        // Arrange: Start in Demo Mode
        _sut.IsDemoMode = true;
        const string targetSessionId = "demo-sess-1001"; // finance_audit

        // Act
        var (ok, msg) = await _sut.TerminateSessionAsync(targetSessionId, "operator1");
        var overview = await _sut.GetActiveSessionsAsync();

        // Assert
        ok.Should().BeTrue();
        overview.Sessions.Should().NotContain(s => s.SessionId == targetSessionId);
    }

    [Fact]
    public async Task TerminateSessionAsync_BySessionId_WhenNotFound_ReturnsFalse()
    {
        // Arrange
        _sut.IsDemoMode = true;

        // Act
        var (ok, msg) = await _sut.TerminateSessionAsync("non_existent_session_id", "operator1");

        // Assert
        ok.Should().BeFalse();
        msg.Should().Contain("ไม่พบเซสชัน");
    }

    [Fact]
    public async Task TerminateSessionAsync_WithSessionInfo_WhenInPreAuth_DisplaysAuthenticatingInAudit()
    {
        // Arrange
        var testService = new TestableSftpSessionService(_logger, _auditService, _configuration)
        {
            IsDemoMode = false,
            MockServicePid = 6112
        };

        var preAuthSession = new SftpSessionInfo
        {
            SessionId = "sess-6112-40112",
            ProcessId = 6112,
            ProcessName = "sshd",
            Username = "กำลังตรวจสอบสิทธิ์ (Authenticating...)",
            RemoteIp = "10.0.0.5",
            RemotePort = 40112,
            LocalPort = 22,
            RawLocalAddr = 0x0100007F,
            RawLocalPort = 22,
            RawRemoteAddr = 0x0500000A,
            RawRemotePort = 40112,
            IsMasterServiceProcess = true,
            IsAuthenticating = true
        };

        // Act
        var (ok, msg) = await testService.TerminateSessionAsync(preAuthSession, "admin");

        // Assert
        ok.Should().BeTrue();
        testService.TcpResetCalled.Should().BeTrue();
        msg.Should().Contain("Authenticating");
        msg.Should().Contain("ได้รับการคุ้มกัน");

        await _auditService.Received(1).LogAsync(
            "SFTP_SESSION_TERMINATED",
            Arg.Is<string>(m => m.Contains("Authenticating") && m.Contains("ได้รับการคุ้มกัน")),
            true,
            "admin");
    }

    [Fact]
    public async Task GetActiveSessionsAsync_LiveWin32_WithCacheHit_ResolvesUsernameInstantly()
    {
        // Arrange
        var mockEventLog = Substitute.For<ISshEventLogService>();
        var testService = new TestableSftpSessionService(_logger, _auditService, _configuration, mockEventLog)
        {
            IsDemoMode = false,
            MockServicePid = 1000
        };

        const string clientIp = "172.16.232.19";
        const int clientPort = 60849;

        testService.MockTcpConnections = new List<SftpSessionService.TcpConnectionEntry>
        {
            new()
            {
                OwningPid = 1000, // Master sshd
                LocalPort = 22,
                RemoteAddress = clientIp,
                RemotePort = clientPort,
                State = 5 // ESTABLISHED
            }
        };

        testService.MockProcessDetails[1000] = ("sshd", DateTime.Now.AddMinutes(-10), 10_000_000);

        // Prepopulate cache with domain user
        testService.SessionUserCache[(clientIp, clientPort)] = (@"bitec\tipoks", DateTime.Now.AddMinutes(-10));

        // Act
        var overview = await testService.GetActiveSessionsAsync(forceMock: false);

        // Assert
        overview.Should().NotBeNull();
        overview.TotalActiveSessions.Should().Be(1);
        var session = overview.Sessions.Single();
        session.Username.Should().Be("tipoks"); // Canonical username extracted!
        session.IsAuthenticating.Should().BeFalse();
        session.RemoteIp.Should().Be(clientIp);
        session.RemotePort.Should().Be(clientPort);

        // Event log service should NOT be called because it hit cache
        await mockEventLog.DidNotReceiveWithAnyArgs().GetLogsAsync(default!);
    }

    [Fact]
    public async Task GetActiveSessionsAsync_LiveWin32_WithEventLogCorrelation_PopulatesCacheAndCanonicalizesUser()
    {
        // Arrange
        var mockEventLog = Substitute.For<ISshEventLogService>();
        var testService = new TestableSftpSessionService(_logger, _auditService, _configuration, mockEventLog)
        {
            IsDemoMode = false,
            MockServicePid = 1000
        };

        const string clientIp = "172.16.232.19";
        const int clientPort = 60849;

        testService.MockTcpConnections = new List<SftpSessionService.TcpConnectionEntry>
        {
            new()
            {
                OwningPid = 1000,
                LocalPort = 22,
                RemoteAddress = clientIp,
                RemotePort = clientPort,
                State = 5
            }
        };

        testService.MockProcessDetails[1000] = ("sshd", DateTime.Now.AddMinutes(-5), 10_000_000);

        // Mock EventLog returning Starting session log
        mockEventLog.GetLogsAsync(Arg.Any<SshLogFilter>()).Returns(Task.FromResult(new OpenSshLogQueryResult
        {
            IsSuccess = true,
            Entries = new List<OpenSshLogEntry>
            {
                new()
                {
                    EventType = SshEventType.AuthSuccess,
                    Username = @"bitec\tipoks",
                    ClientIp = clientIp,
                    Port = clientPort,
                    Timestamp = DateTime.Now.AddMinutes(-5)
                }
            }
        }));

        // Act
        var overview = await testService.GetActiveSessionsAsync(forceMock: false);

        // Assert
        overview.Should().NotBeNull();
        overview.TotalActiveSessions.Should().Be(1);
        var session = overview.Sessions.Single();
        session.Username.Should().Be("tipoks");
        session.IsAuthenticating.Should().BeFalse();

        // Verify cache is now populated
        testService.SessionUserCache.Should().ContainKey((clientIp, clientPort));
        testService.SessionUserCache[(clientIp, clientPort)].Username.Should().Be(@"bitec\tipoks");
    }

    [Fact]
    public async Task GetActiveSessionsAsync_LiveWin32_AutoPrunesDisconnectedSessionsFromCache()
    {
        // Arrange
        var mockEventLog = Substitute.For<ISshEventLogService>();
        var testService = new TestableSftpSessionService(_logger, _auditService, _configuration, mockEventLog)
        {
            IsDemoMode = false,
            MockServicePid = 1000
        };

        // Cache contains old session
        testService.SessionUserCache[("192.168.1.50", 54321)] = ("olduser", DateTime.Now.AddHours(-1));
        testService.SessionUserCache[("172.16.232.19", 60849)] = ("tipoks", DateTime.Now.AddMinutes(-5));

        // Active TCP only has 172.16.232.19:60849
        testService.MockTcpConnections = new List<SftpSessionService.TcpConnectionEntry>
        {
            new()
            {
                OwningPid = 1000,
                LocalPort = 22,
                RemoteAddress = "172.16.232.19",
                RemotePort = 60849,
                State = 5
            }
        };
        testService.MockProcessDetails[1000] = ("sshd", DateTime.Now.AddMinutes(-5), 10_000_000);

        // Act
        var overview = await testService.GetActiveSessionsAsync(forceMock: false);

        // Assert
        overview.TotalActiveSessions.Should().Be(1);
        testService.SessionUserCache.Should().NotContainKey(("192.168.1.50", 54321));
        testService.SessionUserCache.Should().ContainKey(("172.16.232.19", 60849));
    }

    [Fact]
    public async Task GetActiveSessionsAsync_LiveWin32_ProcessScanFallback_WhenEventLogMissing()
    {
        // Arrange
        var mockEventLog = Substitute.For<ISshEventLogService>();
        var testService = new TestableSftpSessionService(_logger, _auditService, _configuration, mockEventLog)
        {
            IsDemoMode = false,
            MockServicePid = 1000
        };

        const string clientIp = "172.16.232.19";
        const int clientPort = 60849;

        testService.MockTcpConnections = new List<SftpSessionService.TcpConnectionEntry>
        {
            new()
            {
                OwningPid = 1000,
                LocalPort = 22,
                RemoteAddress = clientIp,
                RemotePort = clientPort,
                State = 5
            }
        };
        testService.MockProcessDetails[1000] = ("sshd", DateTime.Now.AddMinutes(-2), 10_000_000);

        // EventLog returns empty
        mockEventLog.GetLogsAsync(Arg.Any<SshLogFilter>()).Returns(Task.FromResult(new OpenSshLogQueryResult
        {
            IsSuccess = true,
            Entries = new List<OpenSshLogEntry>()
        }));

        // Running session process returns user
        testService.MockRunningSessionUsers = new List<(int Pid, string Username, DateTime StartTime)>
        {
            (2148, "tipoks", DateTime.Now.AddMinutes(-2))
        };

        // Act
        var overview = await testService.GetActiveSessionsAsync(forceMock: false);

        // Assert
        overview.TotalActiveSessions.Should().Be(1);
        var session = overview.Sessions.Single();
        session.Username.Should().Be("tipoks");
        session.IsAuthenticating.Should().BeFalse();
    }

    private class TestableSftpSessionService : SftpSessionService
    {
        public int MockServicePid { get; set; }
        public bool TcpResetCalled { get; private set; }
        public List<TcpConnectionEntry>? MockTcpConnections { get; set; }
        public List<(int Pid, string Username, DateTime StartTime)>? MockRunningSessionUsers { get; set; }
        public Dictionary<int, (string ProcessName, DateTime StartTime, long WorkingSet)> MockProcessDetails { get; } = new();
        public Dictionary<int, string> MockProcessUsernames { get; } = new();

        public TestableSftpSessionService(
            ILogger<SftpSessionService> logger,
            IAuditService auditService,
            IConfiguration? configuration = null,
            ISshEventLogService? eventLogService = null)
            : base(logger, auditService, configuration, eventLogService)
        {
        }

        public override int GetSshdServicePid()
        {
            return MockServicePid > 0 ? MockServicePid : base.GetSshdServicePid();
        }

        public override bool CloseTcpConnectionWin32(uint localAddr, uint localPort, uint remoteAddr, uint remotePort)
        {
            TcpResetCalled = true;
            return true;
        }

        protected internal override List<TcpConnectionEntry> GetTcpConnectionsWin32()
        {
            return MockTcpConnections ?? base.GetTcpConnectionsWin32();
        }

        protected internal override bool TryGetProcessDetails(int pid, out string processName, out DateTime startTime, out long workingSet)
        {
            if (MockProcessDetails.TryGetValue(pid, out var details))
            {
                processName = details.ProcessName;
                startTime = details.StartTime;
                workingSet = details.WorkingSet;
                return true;
            }
            return base.TryGetProcessDetails(pid, out processName, out startTime, out workingSet);
        }

        protected internal override string GetProcessUsername(int pid)
        {
            if (MockProcessUsernames.TryGetValue(pid, out var user))
            {
                return user;
            }
            return base.GetProcessUsername(pid);
        }

        protected internal override List<(int Pid, string Username, DateTime StartTime)> FindRunningSessionUsers(int masterPid)
        {
            return MockRunningSessionUsers ?? base.FindRunningSessionUsers(masterPid);
        }
    }
}
