using System.Text.RegularExpressions;
using OpensshUI.Models;

namespace OpensshUI.Services.OpenSsh;

public static class SshLogParser
{
    private static readonly Regex AcceptedAuthRegex = new(
        @"Accepted\s+(?<method>publickey|password)\s+for\s+(?<user>[^\s]+)\s+from\s+(?<ip>[^\s]+)\s+port\s+(?<port>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex FailedAuthRegex = new(
        @"Failed\s+(?<method>password|publickey|none)\s+for\s+(?:invalid\s+user\s+)?(?<user>[^\s]+)\s+from\s+(?<ip>[^\s]+)\s+port\s+(?<port>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex ClosedConnectionRegex = new(
        @"(?:Connection\s+closed\s+by|Disconnected\s+from)\s+(?:(?:authenticating\s+|invalid\s+)?user\s+(?<user>[^\s]+)\s+)?(?<ip>[^\s]+)\s+port\s+(?<port>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex SftpSubsystemRegex = new(
        @"subsystem\s+request\s+for\s+sftp(?:\s+by\s+user\s+(?<user>[^\s]+))?",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static OpenSshLogEntry Parse(string? rawMessage, DateTime timestamp, int eventId = 0, string level = "Information", long? recordId = null)
    {
        var entry = new OpenSshLogEntry
        {
            RecordId = recordId,
            Timestamp = timestamp,
            EventId = eventId,
            Level = string.IsNullOrWhiteSpace(level) ? "Information" : level,
            RawMessage = rawMessage?.Trim() ?? string.Empty
        };

        if (string.IsNullOrWhiteSpace(rawMessage))
        {
            entry.SummaryMessage = "No details";
            return entry;
        }

        var matchAccepted = AcceptedAuthRegex.Match(rawMessage);
        if (matchAccepted.Success)
        {
            entry.EventType = SshEventType.AuthSuccess;
            entry.Username = matchAccepted.Groups["user"].Value;
            entry.ClientIp = CleanIp(matchAccepted.Groups["ip"].Value);
            if (int.TryParse(matchAccepted.Groups["port"].Value, out var port)) entry.Port = port;
            entry.SummaryMessage = $"เข้าสู่ระบบสำเร็จ ({matchAccepted.Groups["method"].Value}) - ผู้ใช้: {entry.Username}";
            return entry;
        }

        var matchFailed = FailedAuthRegex.Match(rawMessage);
        if (matchFailed.Success)
        {
            entry.EventType = SshEventType.AuthFailed;
            entry.Username = matchFailed.Groups["user"].Value;
            entry.ClientIp = CleanIp(matchFailed.Groups["ip"].Value);
            if (int.TryParse(matchFailed.Groups["port"].Value, out var port)) entry.Port = port;
            entry.SummaryMessage = $"ยืนยันตัวตนล้มเหลว ({matchFailed.Groups["method"].Value}) - ผู้ใช้: {entry.Username}";
            return entry;
        }

        var matchClosed = ClosedConnectionRegex.Match(rawMessage);
        if (matchClosed.Success)
        {
            entry.EventType = SshEventType.ConnectionClosed;
            if (matchClosed.Groups["user"].Success) entry.Username = matchClosed.Groups["user"].Value;
            entry.ClientIp = CleanIp(matchClosed.Groups["ip"].Value);
            if (int.TryParse(matchClosed.Groups["port"].Value, out var port)) entry.Port = port;
            entry.SummaryMessage = string.IsNullOrEmpty(entry.Username)
                ? $"ตัดการเชื่อมต่อ - IP: {entry.ClientIp}:{entry.Port}"
                : $"ตัดการเชื่อมต่อ - ผู้ใช้: {entry.Username} ({entry.ClientIp}:{entry.Port})";
            return entry;
        }

        var matchSftp = SftpSubsystemRegex.Match(rawMessage);
        if (matchSftp.Success)
        {
            entry.EventType = SshEventType.SftpActivity;
            if (matchSftp.Groups["user"].Success) entry.Username = matchSftp.Groups["user"].Value;
            entry.SummaryMessage = "เริ่มเซสชัน SFTP Subsystem" + (!string.IsNullOrEmpty(entry.Username) ? $" โดย {entry.Username}" : "");
            return entry;
        }

        entry.EventType = SshEventType.SystemInfo;
        entry.SummaryMessage = rawMessage.Length > 120 ? rawMessage[..117] + "..." : rawMessage;
        return entry;
    }

    private static string CleanIp(string ip) => ip.Trim('[', ']', ' ', '\t');
}
