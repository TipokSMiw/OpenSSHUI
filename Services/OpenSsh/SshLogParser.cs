using System.Text.RegularExpressions;
using OpensshUI.Models;
using OpensshUI.Services.Localization;

namespace OpensshUI.Services.OpenSsh;

public static class SshLogParser
{
    private static readonly TimeSpan RegexMatchTimeout = TimeSpan.FromMilliseconds(200);

    private static readonly Regex AcceptedAuthRegex = new(
        @"Accepted\s+(?<method>publickey|password)\s+for\s+(?<user>[^\s]+)\s+from\s+(?<ip>[^\s]+)\s+port\s+(?<port>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        RegexMatchTimeout);

    private static readonly Regex FailedAuthRegex = new(
        @"Failed\s+(?<method>password|publickey|none)\s+for\s+(?<invalid>invalid\s+user\s+)?(?<user>[^\s]+)\s+from\s+(?<ip>[^\s]+)\s+port\s+(?<port>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        RegexMatchTimeout);

    private static readonly Regex DirectInvalidUserRegex = new(
        @"Invalid\s+user\s+(?<user>[^\s]+)\s+from\s+(?<ip>[^\s]+)\s+port\s+(?<port>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        RegexMatchTimeout);

    private static readonly Regex ClosedConnectionRegex = new(
        @"(?:Connection\s+(?:closed|reset)\s+by|Disconnected\s+from|Received\s+disconnect\s+from)\s+(?:(?:authenticating\s+|invalid\s+)?user\s+(?<user>[^\s]+)\s+)?(?<ip>[^\s]+)\s+port\s+(?<port>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        RegexMatchTimeout);

    private static readonly Regex SftpSubsystemRegex = new(
        @"subsystem\s+request\s+for\s+sftp(?:\s+by\s+user\s+(?<user>[^\s]+))?",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        RegexMatchTimeout);

    private static readonly Regex SessionStartedRegex = new(
        @"Starting\s+session:\s+.*?\s+for\s+(?<user>[^\s]+)\s+from\s+(?<ip>[^\s]+)\s+port\s+(?<port>\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        RegexMatchTimeout);

    public static OpenSshLogEntry Parse(string? rawMessage, DateTime timestamp, int eventId = 0, string level = "Information", long? recordId = null, string language = AppStrings.DefaultLanguage)
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

        try
        {
            // 1. Accepted Authentication
            var matchAccepted = AcceptedAuthRegex.Match(rawMessage);
            if (matchAccepted.Success)
            {
                var method = matchAccepted.Groups["method"].Value.ToLowerInvariant();
                entry.EventType = SshEventType.AuthSuccess;
                entry.AuthStatus = SshAuthStatus.Success;
                entry.AuthMethod = method;
                entry.Username = matchAccepted.Groups["user"].Value;
                entry.ClientIp = CleanIp(matchAccepted.Groups["ip"].Value);
                if (int.TryParse(matchAccepted.Groups["port"].Value, out var port)) entry.Port = port;
                entry.SummaryMessage = AppStrings.Format("Svc.Log.AcceptedAuth", language, method, entry.Username);
                return entry;
            }

            // 1.1 Session Started Event (e.g. Starting session: forced-command ... for <user> from <ip> port <port>)
            var matchSession = SessionStartedRegex.Match(rawMessage);
            if (matchSession.Success)
            {
                entry.EventType = SshEventType.AuthSuccess;
                entry.AuthStatus = SshAuthStatus.Success;
                entry.AuthMethod = "session";
                entry.Username = matchSession.Groups["user"].Value;
                entry.ClientIp = CleanIp(matchSession.Groups["ip"].Value);
                if (int.TryParse(matchSession.Groups["port"].Value, out var port)) entry.Port = port;
                entry.SummaryMessage = AppStrings.Format("Svc.Log.SessionStarted", language, entry.Username, entry.ClientIp, entry.Port?.ToString() ?? "");
                return entry;
            }

            // 2. Failed Authentication (Password, Publickey, None)
            var matchFailed = FailedAuthRegex.Match(rawMessage);
            if (matchFailed.Success)
            {
                var method = matchFailed.Groups["method"].Value.ToLowerInvariant();
                var isInvalid = matchFailed.Groups["invalid"].Success;
                entry.EventType = SshEventType.AuthFailed;
                entry.AuthMethod = method;
                entry.Username = matchFailed.Groups["user"].Value;
                entry.ClientIp = CleanIp(matchFailed.Groups["ip"].Value);
                if (int.TryParse(matchFailed.Groups["port"].Value, out var port)) entry.Port = port;

                if (isInvalid)
                {
                    entry.AuthStatus = SshAuthStatus.InvalidUser;
                    entry.SummaryMessage = AppStrings.Format("Svc.Log.FailedInvalidUser", language, entry.Username, entry.ClientIp);
                }
                else if (method == "publickey")
                {
                    entry.AuthStatus = SshAuthStatus.FailedKey;
                    entry.SummaryMessage = AppStrings.Format("Svc.Log.FailedKey", language, entry.Username);
                }
                else
                {
                    entry.AuthStatus = SshAuthStatus.FailedPassword;
                    entry.SummaryMessage = AppStrings.Format("Svc.Log.FailedMethod", language, method, entry.Username);
                }
                return entry;
            }

            // 3. Direct Invalid User Event
            var matchDirectInvalid = DirectInvalidUserRegex.Match(rawMessage);
            if (matchDirectInvalid.Success)
            {
                entry.EventType = SshEventType.AuthFailed;
                entry.AuthStatus = SshAuthStatus.InvalidUser;
                entry.Username = matchDirectInvalid.Groups["user"].Value;
                entry.ClientIp = CleanIp(matchDirectInvalid.Groups["ip"].Value);
                if (int.TryParse(matchDirectInvalid.Groups["port"].Value, out var port)) entry.Port = port;
                entry.SummaryMessage = AppStrings.Format("Svc.Log.DirectInvalidUser", language, entry.Username, entry.ClientIp);
                return entry;
            }

            // 4. Closed Connection
            var matchClosed = ClosedConnectionRegex.Match(rawMessage);
            if (matchClosed.Success)
            {
                entry.EventType = SshEventType.ConnectionClosed;
                entry.AuthStatus = SshAuthStatus.Disconnected;
                if (matchClosed.Groups["user"].Success) entry.Username = matchClosed.Groups["user"].Value;
                entry.ClientIp = CleanIp(matchClosed.Groups["ip"].Value);
                if (int.TryParse(matchClosed.Groups["port"].Value, out var port)) entry.Port = port;
                entry.SummaryMessage = string.IsNullOrEmpty(entry.Username)
                    ? AppStrings.Format("Svc.Log.ClosedIpOnly", language, entry.ClientIp, entry.Port?.ToString() ?? "")
                    : AppStrings.Format("Svc.Log.ClosedUser", language, entry.Username, entry.ClientIp, entry.Port?.ToString() ?? "");
                return entry;
            }

            // 5. SFTP Subsystem
            var matchSftp = SftpSubsystemRegex.Match(rawMessage);
            if (matchSftp.Success)
            {
                entry.EventType = SshEventType.SftpActivity;
                if (matchSftp.Groups["user"].Success) entry.Username = matchSftp.Groups["user"].Value;
                entry.SummaryMessage = string.IsNullOrEmpty(entry.Username)
                    ? AppStrings.Get("Svc.Log.SftpSubsystem", language)
                    : AppStrings.Format("Svc.Log.SftpSubsystemByUser", language, entry.Username);
                return entry;
            }
        }
        catch (RegexMatchTimeoutException)
        {
            // Fall back safely to SystemInfo if log line triggers regex timeout
        }

        entry.EventType = SshEventType.SystemInfo;
        entry.SummaryMessage = rawMessage.Length > 120 ? rawMessage[..117] + "..." : rawMessage;
        return entry;
    }

    private static string CleanIp(string ip) => ip.Trim('[', ']', ' ', '\t');
}
