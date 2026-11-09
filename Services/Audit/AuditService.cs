using Microsoft.EntityFrameworkCore;
using OpensshUI.Data;
using OpensshUI.Models;
using OpensshUI.Services.Security;

namespace OpensshUI.Services.Audit;

public class AuditService : IAuditService
{
    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly ILogger<AuditService> _logger;

    public AuditService(IDbContextFactory<AppDbContext> dbFactory, ILogger<AuditService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    public async Task LogAsync(string action, string details, bool isSuccess = true, string op = "admin", string? clientIp = null)
    {
        try
        {
            var safeAction = SecurityValidator.SanitizeSingleLine(action ?? string.Empty);
            var safeOp = SecurityValidator.SanitizeSingleLine(op ?? "system");
            var safeDetails = (details ?? string.Empty).Replace("\r", " ").Replace("\n", " ");

            await using var db = await _dbFactory.CreateDbContextAsync();
            var log = new AuditLog
            {
                Timestamp = DateTime.UtcNow,
                Action = safeAction,
                Operator = safeOp,
                ClientIp = clientIp,
                Details = safeDetails,
                IsSuccess = isSuccess
            };

            db.AuditLogs.Add(log);
            await db.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to write audit log for action: {Action}", action);
        }
    }

    public async Task<List<AuditLog>> GetRecentLogsAsync(int count = 50)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        return await db.AuditLogs
            .AsNoTracking()
            .OrderByDescending(l => l.Timestamp)
            .Take(count)
            .ToListAsync();
    }

    public async Task<List<AuditLog>> QueryLogsAsync(string? action = null, string? op = null, DateTime? from = null, DateTime? to = null)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var query = db.AuditLogs.AsNoTracking().AsQueryable();

        if (!string.IsNullOrWhiteSpace(action))
            query = query.Where(l => l.Action.Contains(action));

        if (!string.IsNullOrWhiteSpace(op))
            query = query.Where(l => l.Operator.Contains(op));

        if (from.HasValue)
            query = query.Where(l => l.Timestamp >= from.Value);

        if (to.HasValue)
            query = query.Where(l => l.Timestamp <= to.Value);

        return await query
            .OrderByDescending(l => l.Timestamp)
            .Take(200)
            .ToListAsync();
    }
}
