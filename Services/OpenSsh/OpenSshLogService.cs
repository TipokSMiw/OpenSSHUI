using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using System.Text;
using OpensshUI.Models;

namespace OpensshUI.Services.OpenSsh;

[SupportedOSPlatform("windows")]
public class OpenSshLogService : IOpenSshLogService
{
    private const string LogChannel = "OpenSSH/Operational";
    private readonly ILogger<OpenSshLogService> _logger;

    public OpenSshLogService(ILogger<OpenSshLogService> logger)
    {
        _logger = logger;
    }

    public async Task<OpenSshLogQueryResult> GetLogsAsync(SshLogFilter filter)
    {
        return await Task.Run(() =>
        {
            var result = new OpenSshLogQueryResult();
            try
            {
                var (fromUtc, toUtc) = ResolveTimeRange(filter);

                // Use wildcard query for resilient reading across different Windows versions
                var eventQuery = new EventLogQuery(LogChannel, PathType.LogName, "*")
                {
                    ReverseDirection = true
                };

                using var reader = new EventLogReader(eventQuery);
                var parsedEntries = new List<OpenSshLogEntry>();

                for (var eventRecord = reader.ReadEvent(); eventRecord != null; eventRecord = reader.ReadEvent())
                {
                    using (eventRecord)
                    {
                        var time = eventRecord.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow;

                        // In-memory time filtering to avoid Windows XPath schema differences
                        if (fromUtc.HasValue && time < fromUtc.Value)
                            continue;
                        if (toUtc.HasValue && time > toUtc.Value)
                            continue;

                        var rawDesc = eventRecord.FormatDescription() ?? string.Empty;
                        var level = eventRecord.LevelDisplayName ?? "Information";

                        var entry = SshLogParser.Parse(rawDesc, time, eventRecord.Id, level, eventRecord.RecordId);

                        // Filtering by category
                        if (filter.Category.HasValue && entry.EventType != filter.Category.Value)
                            continue;

                        // Filtering by keyword
                        if (!string.IsNullOrWhiteSpace(filter.Keyword))
                        {
                            var kw = filter.Keyword.Trim();
                            var match = (entry.Username?.Contains(kw, StringComparison.OrdinalIgnoreCase) == true)
                                     || (entry.ClientIp?.Contains(kw, StringComparison.OrdinalIgnoreCase) == true)
                                     || (entry.SummaryMessage.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                     || (entry.RawMessage.Contains(kw, StringComparison.OrdinalIgnoreCase));
                            if (!match) continue;
                        }

                        parsedEntries.Add(entry);
                        if (parsedEntries.Count >= filter.MaxRecords)
                            break;
                    }
                }

                result.Entries = parsedEntries;
                result.TotalFound = parsedEntries.Count;
            }
            catch (EventLogNotFoundException ex)
            {
                _logger.LogWarning(ex, "Channel {Channel} not found on this machine.", LogChannel);
                result.IsSuccess = false;
                result.ErrorMessage = $"ไม่พบ Event Log Channel '{LogChannel}' บนเครื่องนี้ (อาจยังไม่ได้เปิดใช้งานหรือยังไม่ได้ติดตั้ง OpenSSH Feature)";
                result.RecommendedFixCommand = "wevtutil sl \"OpenSSH/Operational\" /e:true";
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogError(ex, "Access denied reading {Channel}.", LogChannel);
                result.IsSuccess = false;
                result.RequiresPermissionElevation = true;
                result.ErrorMessage = "ไม่มีสิทธิ์ในการเข้าถึง Windows Event Log (Access Denied)";
                result.RecommendedFixCommand = $"net localgroup \"Event Log Readers\" \"{Environment.UserName}\" /add\r\n# หรือสำหรับ IIS:\r\nnet localgroup \"Event Log Readers\" \"IIS AppPool\\OpensshUIPool\" /add";
            }
            catch (EventLogException ex) when (ex.Message.Contains("Access is denied", StringComparison.OrdinalIgnoreCase) || ex.HResult == -2147024891)
            {
                _logger.LogError(ex, "EventLogException access denied reading {Channel}.", LogChannel);
                result.IsSuccess = false;
                result.RequiresPermissionElevation = true;
                result.ErrorMessage = "ไม่มีสิทธิ์ในการเข้าถึง Windows Event Log (Access Denied)";
                result.RecommendedFixCommand = $"net localgroup \"Event Log Readers\" \"{Environment.UserName}\" /add\r\n# หรือสำหรับ IIS:\r\nnet localgroup \"Event Log Readers\" \"IIS AppPool\\OpensshUIPool\" /add";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error querying {Channel}.", LogChannel);
                result.IsSuccess = false;
                result.ErrorMessage = $"เกิดข้อผิดพลาดในการอ่าน Log: {ex.Message}";
                result.RecommendedFixCommand = "wevtutil sl \"OpenSSH/Operational\" /e:true";
            }

            return result;
        });
    }

    public OpenSshLogQueryResult GetMockLogs(SshLogFilter filter)
    {
        var now = DateTime.UtcNow;
        var rawSamples = new (string Msg, int MinutesAgo, int Id, string Level)[]
        {
            ("Accepted publickey for deployuser from 192.168.1.105 port 54322 ssh2: RSA SHA256:7uKj49xZ... test-key", 2, 1000, "Information"),
            ("subsystem request for sftp by user deployuser", 2, 1001, "Information"),
            ("Accepted password for backup_svc from 172.16.10.4 port 48120 ssh2", 15, 1000, "Information"),
            ("subsystem request for sftp by user backup_svc", 15, 1001, "Information"),
            ("Disconnected from user backup_svc 172.16.10.4 port 48120", 18, 1002, "Information"),
            ("Failed password for testuser from 203.0.113.88 port 59124 ssh2", 35, 1000, "Warning"),
            ("Failed password for testuser from 203.0.113.88 port 59124 ssh2", 36, 1000, "Warning"),
            ("Failed none for invalid user hacker from 198.51.100.22 port 51120 ssh2", 42, 1000, "Warning"),
            ("Connection closed by 198.51.100.22 port 51120 [preauth]", 43, 1002, "Information"),
            ("Accepted publickey for admin from 10.0.0.12 port 2222 ssh2: ED25519 SHA256:v8TW9z...", 65, 1000, "Information"),
            ("Accepted publickey for devops from [2001:db8:85a3::8a2e:370:7334] port 61200 ssh2: ECDSA SHA256:e3b0c44...", 120, 1000, "Information"),
            ("Failed password for invalid user root from 45.33.32.156 port 43912 ssh2", 180, 1000, "Warning"),
            ("Connection closed by 192.168.1.105 port 54322", 210, 1002, "Information"),
            ("Server listening on 0.0.0.0 port 22.", 360, 100, "Information"),
            ("Server listening on :: port 22.", 360, 100, "Information")
        };

        var (fromUtc, toUtc) = ResolveTimeRange(filter);
        var entries = new List<OpenSshLogEntry>();

        long recordId = 5000;
        foreach (var sample in rawSamples)
        {
            var eventTime = now.AddMinutes(-sample.MinutesAgo);

            if (fromUtc.HasValue && eventTime < fromUtc.Value)
                continue;
            if (toUtc.HasValue && eventTime > toUtc.Value)
                continue;

            var entry = SshLogParser.Parse(sample.Msg, eventTime, sample.Id, sample.Level, recordId++);

            if (filter.Category.HasValue && entry.EventType != filter.Category.Value)
                continue;

            if (!string.IsNullOrWhiteSpace(filter.Keyword))
            {
                var kw = filter.Keyword.Trim();
                var match = (entry.Username?.Contains(kw, StringComparison.OrdinalIgnoreCase) == true)
                         || (entry.ClientIp?.Contains(kw, StringComparison.OrdinalIgnoreCase) == true)
                         || (entry.SummaryMessage.Contains(kw, StringComparison.OrdinalIgnoreCase))
                         || (entry.RawMessage.Contains(kw, StringComparison.OrdinalIgnoreCase));
                if (!match) continue;
            }

            entries.Add(entry);
            if (entries.Count >= filter.MaxRecords)
                break;
        }

        return new OpenSshLogQueryResult
        {
            IsSuccess = true,
            Entries = entries,
            TotalFound = entries.Count
        };
    }

    public byte[] ExportCsv(IEnumerable<OpenSshLogEntry> entries)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Timestamp (Local),Event ID,Level,Type,Username,Client IP,Port,Summary,Raw Message");

        foreach (var e in entries)
        {
            var line = string.Join(",",
                EscapeCsv(e.Timestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")),
                e.EventId,
                EscapeCsv(e.Level),
                EscapeCsv(e.EventType.ToString()),
                EscapeCsv(e.Username ?? ""),
                EscapeCsv(e.ClientIp ?? ""),
                e.Port?.ToString() ?? "",
                EscapeCsv(e.SummaryMessage),
                EscapeCsv(e.RawMessage)
            );
            sb.AppendLine(line);
        }

        return Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(sb.ToString())).ToArray();
    }

    public static string EscapeCsv(string val)
    {
        if (string.IsNullOrEmpty(val)) return "\"\"";
        // Prevent CSV Formula Injection
        if (val.StartsWith('=') || val.StartsWith('+') || val.StartsWith('-') || val.StartsWith('@'))
            val = "'" + val;
        return "\"" + val.Replace("\"", "\"\"").Replace("\r", " ").Replace("\n", " ") + "\"";
    }

    private static (DateTime? from, DateTime? to) ResolveTimeRange(SshLogFilter filter)
    {
        var now = DateTime.UtcNow;
        return filter.TimePreset switch
        {
            SshTimePreset.Last1Hour => (now.AddHours(-1), null),
            SshTimePreset.Today => (DateTime.UtcNow.Date, null),
            SshTimePreset.Last7Days => (now.AddDays(-7), null),
            SshTimePreset.Custom => (filter.FromDate?.ToUniversalTime(), filter.ToDate?.ToUniversalTime().AddDays(1)),
            _ => (null, null)
        };
    }
}
