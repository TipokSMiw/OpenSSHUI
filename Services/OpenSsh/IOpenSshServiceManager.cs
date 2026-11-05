namespace OpensshUI.Services.OpenSsh;

public interface IOpenSshServiceManager
{
    string ConfigPath { get; }
    string KeysPath { get; }
    string SftpRoot { get; }
    string FindSshdExecutable();
    ServiceStatusInfo GetStatus();
    ServiceStatusInfo GetAgentStatus();
    bool CheckHasZeroConfigBlock();
    string GetZeroConfigBlockTemplate(string sftpRoot, string keysPath);
    string GenerateManagedBlock(IEnumerable<DirectChrootRule>? customRules, string? sftpRoot = null, string? keysPath = null);
    ConfigValidationResult ValidateConfigSyntax();
    Task<(bool Success, string Message)> ApplyZeroConfigBlockAsync();
    Task<(bool Success, string Message)> SyncManagedConfigAsync(IEnumerable<DirectChrootRule> rules, bool autoRestart = true);
    Task<(bool Success, string Message)> RestartServiceAsync(string serviceName = "sshd");
    Task<(bool Success, string Message)> StartServiceAsync(string serviceName = "sshd");
    Task<(bool Success, string Message)> StopServiceAsync(string serviceName = "sshd");
}
