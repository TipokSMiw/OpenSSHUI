namespace OpensshUI.Models;

public enum SshEventType
{
    AuthSuccess,      // เข้าสู่ระบบสำเร็จ (Accepted password/publickey)
    AuthFailed,       // ยืนยันตัวตนล้มเหลว (Failed password/none)
    ConnectionClosed, // ตัดการเชื่อมต่อ / ปิด Session (Connection closed/disconnected)
    SftpActivity,     // กิจกรรม SFTP (subsystem request sftp)
    SystemInfo        // ข้อความระบบ / อื่นๆ
}

public enum SshAuthStatus
{
    None,
    Success,
    FailedKey,
    FailedPassword,
    InvalidUser,
    Disconnected
}

public class OpenSshLogEntry
{
    public long? RecordId { get; set; }
    public DateTime Timestamp { get; set; }
    public int EventId { get; set; }
    public string Level { get; set; } = "Information";
    public SshEventType EventType { get; set; } = SshEventType.SystemInfo;
    public SshAuthStatus AuthStatus { get; set; } = SshAuthStatus.None;
    public string? AuthMethod { get; set; }
    public string? Username { get; set; }
    public string? ClientIp { get; set; }
    public int? Port { get; set; }
    public string SummaryMessage { get; set; } = string.Empty;
    public string RawMessage { get; set; } = string.Empty;
}

public class OpenSshLogQueryResult
{
    public bool IsSuccess { get; set; } = true;
    public string? ErrorMessage { get; set; }
    public bool RequiresPermissionElevation { get; set; }
    public string? RecommendedFixCommand { get; set; }
    public List<OpenSshLogEntry> Entries { get; set; } = new();
    public int TotalFound { get; set; }
}
