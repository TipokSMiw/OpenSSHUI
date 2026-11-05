using OpensshUI.Models;

namespace OpensshUI.Services.Audit;

public interface IAuditService
{
    Task LogAsync(string action, string details, bool isSuccess = true, string op = "admin", string? clientIp = null);
    Task<List<AuditLog>> GetRecentLogsAsync(int count = 50);
    Task<List<AuditLog>> QueryLogsAsync(string? action = null, string? op = null, DateTime? from = null, DateTime? to = null);
}
