namespace OpensshUI.Models;

public class AuditLog
{
    public int Id { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string Action { get; set; } = string.Empty;
    public string Operator { get; set; } = "system";
    public string? ClientIp { get; set; }
    public string Details { get; set; } = string.Empty;
    public bool IsSuccess { get; set; } = true;
}
