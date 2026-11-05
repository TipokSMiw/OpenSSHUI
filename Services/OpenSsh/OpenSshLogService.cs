using System.Runtime.Versioning;

namespace OpensshUI.Services.OpenSsh;

/// <summary>
/// Backward-compatible adapter for IOpenSshLogService extending SshEventLogService.
/// </summary>
[SupportedOSPlatform("windows")]
public class OpenSshLogService : SshEventLogService
{
    public OpenSshLogService(ILogger<OpenSshLogService> logger) : base(logger)
    {
    }

    public static new string EscapeCsv(string? value) => SshEventLogService.EscapeCsv(value);
}
