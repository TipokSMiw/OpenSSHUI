using System.Text;
using OpensshUI.Models;
using OpensshUI.Services.OpenSsh;
using Xunit;

namespace OpensshUI.Tests;

public class OpenSshLogParserTests
{
    [Fact]
    public void TC_PARSE_01_AcceptedPublicKey_Rsa_ShouldParseSuccessfully()
    {
        var raw = "Accepted publickey for deployuser from 192.168.1.100 port 51234 ssh2: RSA SHA256:abc123xyz";
        var time = new DateTime(2026, 11, 5, 8, 0, 0, DateTimeKind.Utc);

        var entry = SshLogParser.Parse(raw, time, eventId: 1000, level: "Information", recordId: 101);

        Assert.Equal(SshEventType.AuthSuccess, entry.EventType);
        Assert.Equal("deployuser", entry.Username);
        Assert.Equal("192.168.1.100", entry.ClientIp);
        Assert.Equal(51234, entry.Port);
        Assert.Equal(1000, entry.EventId);
        Assert.Equal("Information", entry.Level);
        Assert.Equal(101, entry.RecordId);
        Assert.Contains("เข้าสู่ระบบสำเร็จ", entry.SummaryMessage);
        Assert.Contains("publickey", entry.SummaryMessage);
    }

    [Fact]
    public void TC_PARSE_02_AcceptedPublicKey_Ed25519_ShouldParseSuccessfully()
    {
        var raw = "Accepted publickey for admin from 10.0.0.5 port 2222 ssh2: ED25519 SHA256:def456uvw";
        var time = DateTime.UtcNow;

        var entry = SshLogParser.Parse(raw, time);

        Assert.Equal(SshEventType.AuthSuccess, entry.EventType);
        Assert.Equal("admin", entry.Username);
        Assert.Equal("10.0.0.5", entry.ClientIp);
        Assert.Equal(2222, entry.Port);
    }

    [Fact]
    public void TC_PARSE_03_AcceptedPassword_ShouldParseSuccessfully()
    {
        var raw = "Accepted password for root from 172.16.0.2 port 43210 ssh2";
        var time = DateTime.UtcNow;

        var entry = SshLogParser.Parse(raw, time);

        Assert.Equal(SshEventType.AuthSuccess, entry.EventType);
        Assert.Equal("root", entry.Username);
        Assert.Equal("172.16.0.2", entry.ClientIp);
        Assert.Equal(43210, entry.Port);
        Assert.Contains("password", entry.SummaryMessage);
    }

    [Fact]
    public void TC_PARSE_04_FailedPassword_ExistingUser_ShouldParseSuccessfully()
    {
        var raw = "Failed password for testuser from 203.0.113.10 port 60000 ssh2";
        var time = DateTime.UtcNow;

        var entry = SshLogParser.Parse(raw, time);

        Assert.Equal(SshEventType.AuthFailed, entry.EventType);
        Assert.Equal("testuser", entry.Username);
        Assert.Equal("203.0.113.10", entry.ClientIp);
        Assert.Equal(60000, entry.Port);
        Assert.Contains("ยืนยันตัวตนล้มเหลว", entry.SummaryMessage);
    }

    [Fact]
    public void TC_PARSE_05_FailedAuth_InvalidUser_ShouldParseSuccessfully()
    {
        var raw = "Failed none for invalid user hacker from 198.51.100.50 port 55555 ssh2";
        var time = DateTime.UtcNow;

        var entry = SshLogParser.Parse(raw, time);

        Assert.Equal(SshEventType.AuthFailed, entry.EventType);
        Assert.Equal("hacker", entry.Username);
        Assert.Equal("198.51.100.50", entry.ClientIp);
        Assert.Equal(55555, entry.Port);
    }

    [Fact]
    public void TC_PARSE_06_ConnectionClosed_Preauth_ShouldParseSuccessfully()
    {
        var raw = "Connection closed by 192.168.1.50 port 54321 [preauth]";
        var time = DateTime.UtcNow;

        var entry = SshLogParser.Parse(raw, time);

        Assert.Equal(SshEventType.ConnectionClosed, entry.EventType);
        Assert.Null(entry.Username);
        Assert.Equal("192.168.1.50", entry.ClientIp);
        Assert.Equal(54321, entry.Port);
        Assert.Contains("ตัดการเชื่อมต่อ", entry.SummaryMessage);
    }

    [Fact]
    public void TC_PARSE_07_DisconnectedFromUser_ShouldParseSuccessfully()
    {
        var raw = "Disconnected from user testuser 10.10.10.10 port 49152";
        var time = DateTime.UtcNow;

        var entry = SshLogParser.Parse(raw, time);

        Assert.Equal(SshEventType.ConnectionClosed, entry.EventType);
        Assert.Equal("testuser", entry.Username);
        Assert.Equal("10.10.10.10", entry.ClientIp);
        Assert.Equal(49152, entry.Port);
    }

    [Fact]
    public void TC_PARSE_08_SftpSubsystemRequest_ShouldParseSuccessfully()
    {
        var raw = "subsystem request for sftp by user finance_user";
        var time = DateTime.UtcNow;

        var entry = SshLogParser.Parse(raw, time);

        Assert.Equal(SshEventType.SftpActivity, entry.EventType);
        Assert.Equal("finance_user", entry.Username);
        Assert.Contains("SFTP Subsystem", entry.SummaryMessage);
    }

    [Fact]
    public void TC_PARSE_09_Ipv6Address_ShouldParseSuccessfully()
    {
        var raw = "Accepted publickey for dev from [2001:db8::1] port 34567 ssh2";
        var time = DateTime.UtcNow;

        var entry = SshLogParser.Parse(raw, time);

        Assert.Equal(SshEventType.AuthSuccess, entry.EventType);
        Assert.Equal("dev", entry.Username);
        Assert.Equal("2001:db8::1", entry.ClientIp);
        Assert.Equal(34567, entry.Port);
    }

    [Fact]
    public void TC_PARSE_10_SystemInfoFallback_ShouldParseSuccessfully()
    {
        var raw = "Server listening on 0.0.0.0 port 22.";
        var time = DateTime.UtcNow;

        var entry = SshLogParser.Parse(raw, time);

        Assert.Equal(SshEventType.SystemInfo, entry.EventType);
        Assert.Null(entry.Username);
        Assert.Null(entry.ClientIp);
        Assert.Equal("Server listening on 0.0.0.0 port 22.", entry.SummaryMessage);
    }

    [Fact]
    public void TC_PARSE_11_EmptyOrNullRawMessage_ShouldNotThrow()
    {
        var emptyEntry = SshLogParser.Parse("", DateTime.UtcNow);
        Assert.Equal(SshEventType.SystemInfo, emptyEntry.EventType);
        Assert.Equal("No details", emptyEntry.SummaryMessage);

        var nullEntry = SshLogParser.Parse(null, DateTime.UtcNow);
        Assert.Equal(SshEventType.SystemInfo, nullEntry.EventType);
        Assert.Equal("No details", nullEntry.SummaryMessage);
    }

    [Fact]
    public void TC_CSV_01_FormulaInjection_ShouldBeSanitized()
    {
        var dangerousValue1 = "=1+1";
        var dangerousValue2 = "+SUM(A1:A10)";
        var dangerousValue3 = "-2+3";
        var dangerousValue4 = "@evil.com";

        var escaped1 = OpenSshLogService.EscapeCsv(dangerousValue1);
        var escaped2 = OpenSshLogService.EscapeCsv(dangerousValue2);
        var escaped3 = OpenSshLogService.EscapeCsv(dangerousValue3);
        var escaped4 = OpenSshLogService.EscapeCsv(dangerousValue4);

        Assert.StartsWith("\"'=", escaped1);
        Assert.StartsWith("\"'+", escaped2);
        Assert.StartsWith("\"'-", escaped3);
        Assert.StartsWith("\"'@", escaped4);
    }

    [Fact]
    public void TC_CSV_02_ExportCsv_ShouldGenerateValidCsvHeaderAndRows()
    {
        var entries = new List<OpenSshLogEntry>
        {
            new()
            {
                Timestamp = new DateTime(2026, 11, 5, 12, 0, 0, DateTimeKind.Utc),
                EventId = 1000,
                Level = "Information",
                EventType = SshEventType.AuthSuccess,
                Username = "testuser",
                ClientIp = "192.168.1.10",
                Port = 22,
                SummaryMessage = "เข้าสู่ระบบสำเร็จ",
                RawMessage = "Accepted publickey for testuser from 192.168.1.10 port 22"
            }
        };

        var service = new OpenSshLogService(new Microsoft.Extensions.Logging.Abstractions.NullLogger<OpenSshLogService>());
        var csvBytes = service.ExportCsv(entries);
        var csvText = Encoding.UTF8.GetString(csvBytes);

        Assert.Contains("Timestamp (Local),Event ID,Level,Type,Username,Client IP,Port,Summary,Raw Message", csvText);
        Assert.Contains("testuser", csvText);
        Assert.Contains("192.168.1.10", csvText);
        Assert.Contains("AuthSuccess", csvText);
    }

    [Fact]
    public void TC_MOCK_01_GetMockLogs_ShouldReturnPopulatedEntries()
    {
        var service = new OpenSshLogService(new Microsoft.Extensions.Logging.Abstractions.NullLogger<OpenSshLogService>());
        var filter = new SshLogFilter { TimePreset = SshTimePreset.Today, MaxRecords = 100 };

        var result = service.GetMockLogs(filter);

        Assert.True(result.IsSuccess);
        Assert.NotEmpty(result.Entries);
        Assert.Contains(result.Entries, e => e.EventType == SshEventType.AuthSuccess);
        Assert.Contains(result.Entries, e => e.EventType == SshEventType.AuthFailed);
    }

    [Fact]
    public void TC_MOCK_02_GetMockLogs_WithCategoryAndKeyword_ShouldFilterAccurately()
    {
        var service = new OpenSshLogService(new Microsoft.Extensions.Logging.Abstractions.NullLogger<OpenSshLogService>());
        var filter = new SshLogFilter
        {
            TimePreset = SshTimePreset.Today,
            Category = SshEventType.AuthFailed,
            Keyword = "hacker"
        };

        var result = service.GetMockLogs(filter);

        Assert.True(result.IsSuccess);
        Assert.All(result.Entries, e => Assert.Equal(SshEventType.AuthFailed, e.EventType));
        Assert.Contains(result.Entries, e => e.Username == "hacker");
    }

    [Fact]
    public void TC_PARSE_16_SessionStarted_ShouldParseUsernameEndpointAndAuthSuccess()
    {
        // Production log format from OpenSSH/Operational:
        // sshd: Starting session: forced-command (config) 'internal-sftp' for bitec\tipoks from 172.16.232.19 port 60849 id 0
        var raw = "sshd: Starting session: forced-command (config) 'internal-sftp' for bitec\\tipoks from 172.16.232.19 port 60849 id 0";
        var time = DateTime.UtcNow;

        var entry = SshLogParser.Parse(raw, time, eventId: 1000, level: "Information");

        Assert.Equal(SshEventType.AuthSuccess, entry.EventType);
        Assert.Equal(SshAuthStatus.Success, entry.AuthStatus);
        Assert.Equal("bitec\\tipoks", entry.Username);
        Assert.Equal("172.16.232.19", entry.ClientIp);
        Assert.Equal(60849, entry.Port);
        Assert.Equal("session", entry.AuthMethod);
        Assert.Contains("bitec\\tipoks", entry.SummaryMessage);
    }

    private readonly Xunit.Abstractions.ITestOutputHelper _output;

    public OpenSshLogParserTests(Xunit.Abstractions.ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public async Task TC_LIVE_01_CheckLiveEventLogOnMachine()
    {
        var service = new OpenSshLogService(new Microsoft.Extensions.Logging.Abstractions.NullLogger<OpenSshLogService>());
        var filter = new SshLogFilter
        {
            TimePreset = SshTimePreset.Last7Days,
            MaxRecords = 50
        };

        var result = await service.GetLogsAsync(filter);
        _output.WriteLine($"Result Success: {result.IsSuccess}");
        _output.WriteLine($"Error: {result.ErrorMessage}");
        _output.WriteLine($"Total Entries Found: {result.Entries.Count}");
        foreach (var entry in result.Entries)
        {
            _output.WriteLine($"--> [{entry.Timestamp.ToLocalTime()}] {entry.EventType} | User: {entry.Username} | IP: {entry.ClientIp}:{entry.Port} | {entry.SummaryMessage}");
            _output.WriteLine($"    Raw: {entry.RawMessage}");
        }
    }
}
