using OpensshUI.Models;

namespace OpensshUI.Services.OpenSsh;

public interface ISshEventLogService
{
    Task<OpenSshLogQueryResult> GetLogsAsync(SshLogFilter filter);
    OpenSshLogQueryResult GetMockLogs(SshLogFilter filter);
    byte[] ExportCsv(IEnumerable<OpenSshLogEntry> entries);
}
