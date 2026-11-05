using System.Security;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using OpensshUI.Models;
using OpensshUI.Services.OpenSsh;
using OpensshUI.Services.Security;
using Xunit;

namespace OpensshUI.Tests;

public class ProductionHardeningAndSecurityTests : IDisposable
{
    private readonly string _tempTestDir;

    public ProductionHardeningAndSecurityTests()
    {
        _tempTestDir = Path.Combine(Path.GetTempPath(), $"OpensshUI_AuditTest_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempTestDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempTestDir))
            {
                Directory.Delete(_tempTestDir, recursive: true);
            }
        }
        catch { }
    }

    #region Domain 1: sshd_config Parser, Hierarchy & Atomic Write Tests

    [Fact]
    public void Parser_PreservesGlobalDirectivesAtTop_AndAppendsMatchBlocksAtBottom()
    {
        var rawConfig = @"# System-wide OpenSSH configuration file
Port 2222
ListenAddress 0.0.0.0
# Admin note regarding auth
PasswordAuthentication yes

Match Group SFTP-Users
    ChrootDirectory C:\SFTPRoot\%u
    ForceCommand internal-sftp

# Stray global directive after match block
Subsystem sftp internal-sftp
";
        var service = new SshdConfigService(NullLogger<SshdConfigService>.Instance);
        var parsed = service.Parse(rawConfig);

        // Subsystem and Port must be in GlobalLines, not inside the Match block
        parsed.GlobalLines.Should().Contain(l => l.Contains("Port 2222"));
        parsed.GlobalLines.Should().Contain(l => l.Contains("ListenAddress 0.0.0.0"));
        parsed.GlobalLines.Should().Contain(l => l.Contains("Subsystem sftp internal-sftp"));
        parsed.GlobalLines.Should().Contain(l => l.Contains("# Admin note regarding auth"));

        var serialized = service.Serialize(parsed);

        // Verify serializing places Global Directives strictly before Match blocks
        var matchIndex = serialized.IndexOf("Match Group SFTP-Users", StringComparison.OrdinalIgnoreCase);
        var portIndex = serialized.IndexOf("Port 2222", StringComparison.OrdinalIgnoreCase);
        var subsystemIndex = serialized.IndexOf("Subsystem sftp internal-sftp", StringComparison.OrdinalIgnoreCase);

        portIndex.Should().BeLessThan(matchIndex, "Port must precede all Match blocks to prevent directive bleeding.");
        subsystemIndex.Should().BeLessThan(matchIndex, "Subsystem must precede all Match blocks to prevent directive bleeding.");
    }

    [Fact]
    public void Parser_PreservesAdministratorCommentsVerbatim()
    {
        var rawConfig = @"# Custom Security Rule: Admin Alice 2026-11-05
# Do not change the line below without SecOps approval
MaxAuthTries 3
LogLevel VERBOSE
";
        var service = new SshdConfigService(NullLogger<SshdConfigService>.Instance);
        var parsed = service.Parse(rawConfig);
        var serialized = service.Serialize(parsed);

        serialized.Should().Contain("# Custom Security Rule: Admin Alice 2026-11-05");
        serialized.Should().Contain("# Do not change the line below without SecOps approval");
        serialized.Should().Contain("MaxAuthTries 3");
        serialized.Should().Contain("LogLevel VERBOSE");
    }

    [Fact]
    public async Task AtomicWrite_CreatesBackup_AndRotatesToKeepLast5()
    {
        var configPath = Path.Combine(_tempTestDir, "sshd_config");
        var initialContent = "Port 22\nSubsystem sftp internal-sftp\n";
        await File.WriteAllTextAsync(configPath, initialContent);

        var service = new SshdConfigService(NullLogger<SshdConfigService>.Instance);

        // Perform 7 successive atomic writes
        for (int i = 1; i <= 7; i++)
        {
            var newContent = $"Port 22\n# Update {i}\nSubsystem sftp internal-sftp\n";
            var result = await service.AtomicWriteAndApplyAsync(newContent, configPath);
            result.Success.Should().BeTrue();
            // Small pause to guarantee distinct timestamps for backups
            await Task.Delay(20);
        }

        // Verify live content is the latest
        var liveContent = await File.ReadAllTextAsync(configPath);
        liveContent.Should().Contain("# Update 7");

        // Verify backup rotation strictly kept at most 5 backups
        var backups = Directory.GetFiles(_tempTestDir, "sshd_config.bak_*");
        backups.Length.Should().BeInRange(1, 5, "Backup rotation must prune old backups and keep at most 5.");
    }

    [Fact]
    public async Task AtomicWrite_RejectsInvalidSyntax_AndPreservesOriginalFile()
    {
        var configPath = Path.Combine(_tempTestDir, "sshd_config_invalid_test");
        var originalContent = "Port 22\nSubsystem sftp internal-sftp\n";
        await File.WriteAllTextAsync(configPath, originalContent);

        var service = new SshdConfigService(NullLogger<SshdConfigService>.Instance);

        var invalidContent = "Port 22\nBadDirectiveXYZ 9999\nSubsystem sftp internal-sftp\n";
        var result = await service.AtomicWriteAndApplyAsync(invalidContent, configPath);

        // Validation must fail
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("syntax");

        // Original file must remain 100% untouched
        var currentFileContent = await File.ReadAllTextAsync(configPath);
        currentFileContent.Should().Be(originalContent);

        // Temp file must be cleaned up
        var tempFiles = Directory.GetFiles(_tempTestDir, "*.tmp_*");
        tempFiles.Should().BeEmpty("Temporary test file must be cleaned up on failure.");
    }

    [Fact]
    public void Parser_HoistsGlobalDirectives_WhenAccidentallyPlacedBetweenMatchBlocks()
    {
        var raw = @"Port 22
Match User alice
    ChrootDirectory C:\SFTPRoot\alice

# Accidentally placed global directive
HostKey C:\ProgramData\ssh\ssh_host_ed25519_key

Match Group SFTP-Users
    ChrootDirectory C:\SFTPRoot\%u
";
        var service = new SshdConfigService(NullLogger<SshdConfigService>.Instance);
        var parsed = service.Parse(raw);

        // HostKey should be captured as a global directive line
        parsed.GlobalLines.Should().Contain(l => l.Contains("HostKey"));

        var serialized = service.Serialize(parsed);
        var hostKeyPos = serialized.IndexOf("HostKey", StringComparison.OrdinalIgnoreCase);
        var matchAlicePos = serialized.IndexOf("Match User alice", StringComparison.OrdinalIgnoreCase);

        // HostKey must be positioned before match blocks
        hostKeyPos.Should().BeLessThan(matchAlicePos);
    }

    [Fact]
    public void Parser_BlankLinesInsideMatchBlock_DoNotCauseDirectivesToBleedIntoGlobalLines()
    {
        var raw = @"Port 22
Subsystem sftp sftp-server.exe

Match Group administrators
    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys

    # Blank line above should NOT terminate Match Group administrators
    AllowTcpForwarding yes
";
        var service = new SshdConfigService(NullLogger<SshdConfigService>.Instance);
        var parsed = service.Parse(raw);

        // AllowTcpForwarding yes MUST stay inside Match Group administrators, NOT hoisted to GlobalLines
        parsed.GlobalLines.Should().NotContain(l => l.Contains("AllowTcpForwarding"));
        var adminBlock = parsed.MatchBlocks.Should().ContainSingle(b => b.Pattern == "administrators").Subject;
        adminBlock.Directives.Should().Contain(d => d.Key == "AllowTcpForwarding" && d.Value == "yes");
    }

    [Fact]
    public void ParserAndSerializer_AreStrictlyIdempotent_AcrossMultipleCycles()
    {
        var raw = @"# Global comment
Port 22
Subsystem sftp internal-sftp

# Admin custom block comment
Match Group administrators
    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
";
        var service = new SshdConfigService(NullLogger<SshdConfigService>.Instance);

        var pass1 = service.Serialize(service.Parse(raw));
        var pass2 = service.Serialize(service.Parse(pass1));
        var pass3 = service.Serialize(service.Parse(pass2));

        pass2.Should().Be(pass1, "Repeated Parse -> Serialize cycles must be 100% idempotent without blank-line drift.");
        pass3.Should().Be(pass1);
    }

    [Fact]
    public async Task SyncManagedBlocks_ReturnsError_WhenConfigFileDoesNotExist()
    {
        var nonExistentPath = Path.Combine(_tempTestDir, "missing_sshd_config");
        var service = new SshdConfigService(NullLogger<SshdConfigService>.Instance);

        var (success, message) = await service.SyncManagedBlocksAsync(
            new List<DirectChrootRule>(),
            @"C:\SFTPRoot",
            @"C:\ProgramData\ssh\keys",
            nonExistentPath);

        success.Should().BeFalse();
        message.Should().Contain("not found");
    }

    #endregion

    #region Domain 2: NTFS ACL Provisioning & Path Traversal Guards

    [Fact]
    public void ValidatePathSafety_RejectsPathTraversalAndParentEscapes()
    {
        var service = new NtfsAclService(NullLogger<NtfsAclService>.Instance);
        var baseRoot = @"C:\SFTPRoot\alice";

        service.ValidatePathSafety(baseRoot, "files").Should().BeTrue();
        service.ValidatePathSafety(baseRoot, "files/uploads").Should().BeTrue();
        service.ValidatePathSafety(baseRoot, @"files\subfolder\document.pdf").Should().BeTrue();

        // Path Traversal attacks
        service.ValidatePathSafety(baseRoot, "../").Should().BeFalse();
        service.ValidatePathSafety(baseRoot, @"..\bob").Should().BeFalse();
        service.ValidatePathSafety(baseRoot, @"files\..\..\..\Windows\System32").Should().BeFalse();
        service.ValidatePathSafety(baseRoot, "/etc/passwd").Should().BeFalse();
        service.ValidatePathSafety(baseRoot, @"C:\Windows\explorer.exe").Should().BeFalse();
    }

    [Fact]
    public void JunctionCreation_RejectsRestrictedSystemTargets()
    {
        var service = new NtfsAclService(NullLogger<NtfsAclService>.Instance);
        var userFilesDir = Path.Combine(_tempTestDir, "alice", "files");
        Directory.CreateDirectory(userFilesDir);

        var linkPath = Path.Combine(userFilesDir, "win_link");
        var dangerousTarget = @"C:\Windows\System32";

        // SecurityValidator should reject C:\Windows\System32
        var success = service.CreateDirectoryJunction(linkPath, dangerousTarget);
        success.Should().BeFalse("Junction to restricted Windows directory must be rejected.");
    }

    [Fact]
    public void ProvisionChrootRoot_BreaksInheritance_AndProtectsAccessRules()
    {
        var service = new NtfsAclService(NullLogger<NtfsAclService>.Instance);
        var chrootPath = Path.Combine(_tempTestDir, "test_chroot");

        service.ProvisionChrootRoot(chrootPath, Environment.UserName);

        var dirInfo = new DirectoryInfo(chrootPath);
        var security = dirInfo.GetAccessControl();

        // Must be protected (inheritance broken)
        security.AreAccessRulesProtected.Should().BeTrue("Chroot root directory must break ACL inheritance to prevent inherited write access.");
    }

    [Fact]
    public void ProvisionUserChroot_ForUnresolvedMockUser_CompletesWithoutIdentityNotMappedException()
    {
        var service = new NtfsAclService(NullLogger<NtfsAclService>.Instance);
        var mockUser = "nonexistent_sftp_user_99";

        var act = () => service.ProvisionUserChroot(_tempTestDir, mockUser);
        act.Should().NotThrow("Unresolved local/domain accounts in dev/mock environments should secure folder for SYSTEM/Administrators without throwing IdentityNotMappedException.");

        Directory.Exists(Path.Combine(_tempTestDir, mockUser, "files")).Should().BeTrue();
    }

    [Fact]
    public void ProvisionUserChroot_DetectsUsernameTraversal()
    {
        var service = new NtfsAclService(NullLogger<NtfsAclService>.Instance);

        var act = () => service.ProvisionUserChroot(_tempTestDir, @"..\admin");
        act.Should().Throw<SecurityException>();

        var act2 = () => service.ProvisionUserChroot(_tempTestDir, "user;rm -rf");
        act2.Should().Throw<SecurityException>();
    }

    #endregion

    #region Domain 3: Windows Event Log Parser & Auth Status Extraction

    [Fact]
    public void LogParser_CorrectlyExtracts_AuthSuccess_ForPublickey()
    {
        var msg = "Accepted publickey for alice from 192.168.1.50 port 53210 ssh2: RSA SHA256:7uKj49xZ...";
        var entry = SshLogParser.Parse(msg, DateTime.UtcNow, 1000);

        entry.EventType.Should().Be(SshEventType.AuthSuccess);
        entry.AuthStatus.Should().Be(SshAuthStatus.Success);
        entry.AuthMethod.Should().Be("publickey");
        entry.Username.Should().Be("alice");
        entry.ClientIp.Should().Be("192.168.1.50");
        entry.Port.Should().Be(53210);
    }

    [Fact]
    public void LogParser_CorrectlyExtracts_FailedKey()
    {
        var msg = "Failed publickey for bob from 10.0.0.22 port 44120 ssh2: RSA SHA256:deadbeef...";
        var entry = SshLogParser.Parse(msg, DateTime.UtcNow, 1000);

        entry.EventType.Should().Be(SshEventType.AuthFailed);
        entry.AuthStatus.Should().Be(SshAuthStatus.FailedKey);
        entry.AuthMethod.Should().Be("publickey");
        entry.Username.Should().Be("bob");
        entry.ClientIp.Should().Be("10.0.0.22");
        entry.Port.Should().Be(44120);
    }

    [Fact]
    public void LogParser_CorrectlyExtracts_InvalidUser_FromFailedAuth()
    {
        var msg = "Failed password for invalid user malicious_user from 203.0.113.15 port 61234 ssh2";
        var entry = SshLogParser.Parse(msg, DateTime.UtcNow, 1000);

        entry.EventType.Should().Be(SshEventType.AuthFailed);
        entry.AuthStatus.Should().Be(SshAuthStatus.InvalidUser);
        entry.Username.Should().Be("malicious_user");
        entry.ClientIp.Should().Be("203.0.113.15");
        entry.Port.Should().Be(61234);
    }

    [Fact]
    public void LogParser_CorrectlyExtracts_DirectInvalidUserEvent()
    {
        var msg = "Invalid user hacker_root from 198.51.100.80 port 49152";
        var entry = SshLogParser.Parse(msg, DateTime.UtcNow, 1000);

        entry.EventType.Should().Be(SshEventType.AuthFailed);
        entry.AuthStatus.Should().Be(SshAuthStatus.InvalidUser);
        entry.Username.Should().Be("hacker_root");
        entry.ClientIp.Should().Be("198.51.100.80");
        entry.Port.Should().Be(49152);
    }

    [Fact]
    public void LogParser_CorrectlyExtracts_Ipv6ClientAddress()
    {
        var msg = "Accepted publickey for devops from [2001:db8:85a3::8a2e:370:7334] port 61200 ssh2: ECDSA SHA256:e3b0c44...";
        var entry = SshLogParser.Parse(msg, DateTime.UtcNow, 1000);

        entry.EventType.Should().Be(SshEventType.AuthSuccess);
        entry.AuthStatus.Should().Be(SshAuthStatus.Success);
        entry.Username.Should().Be("devops");
        entry.ClientIp.Should().Be("2001:db8:85a3::8a2e:370:7334");
        entry.Port.Should().Be(61200);
    }

    [Fact]
    public void LogParser_CorrectlyExtracts_ConnectionClosed()
    {
        var msg = "Connection closed by 192.168.1.105 port 54322";
        var entry = SshLogParser.Parse(msg, DateTime.UtcNow, 1002);

        entry.EventType.Should().Be(SshEventType.ConnectionClosed);
        entry.AuthStatus.Should().Be(SshAuthStatus.Disconnected);
        entry.ClientIp.Should().Be("192.168.1.105");
        entry.Port.Should().Be(54322);
    }

    #endregion

    #region Domain 4: Service Controller Handling & Fallback

    [Fact]
    public void ServiceManager_QueriesBothSshd_AndSshAgent_SafelyWithoutCrashing()
    {
        var manager = new OpenSshServiceManager(NullLogger<OpenSshServiceManager>.Instance);

        var sshdStatus = manager.GetStatus();
        sshdStatus.Should().NotBeNull();
        sshdStatus.ServiceName.Should().Be("sshd");

        var agentStatus = manager.GetAgentStatus();
        agentStatus.Should().NotBeNull();
        agentStatus.ServiceName.Should().Be("ssh-agent");
    }

    #endregion
}
