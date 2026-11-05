using OpensshUI.Models;

namespace OpensshUI.Services.OpenSsh;

public interface IOpenSshLogService
{
    Task<OpenSshLogQueryResult> GetLogsAsync(SshLogFilter filter);
    OpenSshLogQueryResult GetMockLogs(SshLogFilter filter);
    byte[] ExportCsv(IEnumerable<OpenSshLogEntry> entries);
}
