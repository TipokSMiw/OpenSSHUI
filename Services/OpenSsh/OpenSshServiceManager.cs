using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.ServiceProcess;
using System.Text;
using OpensshUI.Services.Security;

namespace OpensshUI.Services.OpenSsh;

public class DirectChrootRule
{
    public bool IsGroup { get; set; }
    public string Identifier { get; set; } = string.Empty;
    public string RootPath { get; set; } = string.Empty;
}

public class ConfigValidationResult
{
    public bool IsValid { get; set; }
    public string Output { get; set; } = string.Empty;
    public string? ErrorMessage { get; set; }
}

public class ServiceStatusInfo
{
    public bool IsInstalled { get; set; }
    public string Status { get; set; } = "Unknown";
    public bool CanStop { get; set; }
    public bool CanStart { get; set; }
    public bool HasZeroConfigBlock { get; set; }
    public string ConfigPath { get; set; } = string.Empty;
    public string SshdExecutablePath { get; set; } = string.Empty;
    public string ServiceName { get; set; } = "sshd";
}

[SupportedOSPlatform("windows")]
public class OpenSshServiceManager : IOpenSshServiceManager
{
    private const string DefaultSshdServiceName = "sshd";
    private const string DefaultAgentServiceName = "ssh-agent";

    private readonly IConfiguration? _configuration;
    private readonly string _defaultConfigPath;
    private readonly string _defaultKeysPath;
    private readonly string _defaultSftpRoot;
    private readonly ILogger<OpenSshServiceManager> _logger;
    private readonly ISshdConfigService _configService;
    private readonly SemaphoreSlim _serviceLock = new(1, 1);

    public const string BlockHeader = SshdConfigService.BlockHeader;
    public const string BlockFooter = SshdConfigService.BlockFooter;

    public OpenSshServiceManager(
        ILogger<OpenSshServiceManager> logger,
        IConfiguration? configuration = null,
        ISshdConfigService? configService = null)
    {
        _logger = logger;
        _configuration = configuration;
        _defaultSftpRoot = configuration?["SftpSettings:SftpRoot"] ?? @"C:\SFTPRoot";
        _defaultKeysPath = configuration?["SftpSettings:KeysPath"] ?? @"C:\ProgramData\ssh\keys";
        _defaultConfigPath = configuration?["SftpSettings:SshdConfigPath"] ?? @"C:\ProgramData\ssh\sshd_config";
        _configService = configService ?? new SshdConfigService(
            Microsoft.Extensions.Logging.Abstractions.NullLogger<SshdConfigService>.Instance,
            configuration);
    }

    public string ConfigPath => _configuration?["SftpSettings:SshdConfigPath"] ?? _defaultConfigPath;
    public string KeysPath => _configuration?["SftpSettings:KeysPath"] ?? _defaultKeysPath;
    public string SftpRoot => _configuration?["SftpSettings:SftpRoot"] ?? _defaultSftpRoot;

    public string FindSshdExecutable() => _configService.FindSshdExecutable();

    public ServiceStatusInfo GetStatus()
    {
        return QueryServiceStatus(DefaultSshdServiceName);
    }

    public ServiceStatusInfo GetAgentStatus()
    {
        return QueryServiceStatus(DefaultAgentServiceName);
    }

    private ServiceStatusInfo QueryServiceStatus(string serviceName)
    {
        var info = new ServiceStatusInfo
        {
            ServiceName = serviceName,
            ConfigPath = ConfigPath,
            SshdExecutablePath = FindSshdExecutable()
        };

        try
        {
            using var sc = new ServiceController(serviceName);
            info.IsInstalled = true;
            info.Status = sc.Status.ToString();
            info.CanStart = sc.Status == ServiceControllerStatus.Stopped;
            info.CanStop = sc.Status == ServiceControllerStatus.Running;
        }
        catch (Win32Exception ex)
        {
            _logger.LogWarning(ex, "Win32Exception querying service '{Service}': {Msg}", serviceName, ex.Message);
            info.IsInstalled = false;
            info.Status = "Access Denied";
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(ex, "Service '{Service}' not found or inaccessible.", serviceName);
            info.IsInstalled = false;
            info.Status = "Not Installed";
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Service '{Service}' query encountered unexpected error.", serviceName);
            info.IsInstalled = false;
            info.Status = "Unknown Error";
        }

        if (serviceName.Equals(DefaultSshdServiceName, StringComparison.OrdinalIgnoreCase))
        {
            info.HasZeroConfigBlock = CheckHasZeroConfigBlock();
        }

        return info;
    }

    public bool CheckHasZeroConfigBlock()
    {
        if (!File.Exists(ConfigPath)) return false;

        try
        {
            var content = File.ReadAllText(ConfigPath);
            return content.Contains("Match Group SFTP-Users", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public string GetZeroConfigBlockTemplate(string sftpRoot, string keysPath)
    {
        return GenerateManagedBlock(new List<DirectChrootRule>(), sftpRoot, keysPath);
    }

    public string GenerateManagedBlock(IEnumerable<DirectChrootRule>? customRules, string? sftpRoot = null, string? keysPath = null)
    {
        var root = sftpRoot ?? SftpRoot;
        var keys = keysPath ?? KeysPath;

        var normalizedKeys = FormatConfigPath(keys.Replace("\\", "/").TrimEnd('/') + "/%u");
        var defaultNormalizedRoot = FormatConfigPath(root.Replace("/", "\\").TrimEnd('\\') + "\\%u");

        var sb = new StringBuilder();
        sb.AppendLine();
        sb.AppendLine(BlockHeader);

        if (customRules != null)
        {
            var rules = customRules.ToList();

            foreach (var rule in rules.Where(r => !r.IsGroup && !string.IsNullOrWhiteSpace(r.RootPath)))
            {
                var cleanId = SecurityValidator.SanitizeSingleLine(rule.Identifier).Replace(" ", "").Replace("\"", "");
                var normPath = FormatConfigPath(rule.RootPath.Replace("/", "\\"));
                sb.AppendLine($"Match User {cleanId}");
                sb.AppendLine($"    ChrootDirectory {normPath}");
                sb.AppendLine("    ForceCommand internal-sftp");
                sb.AppendLine("    AllowTcpForwarding no");
                sb.AppendLine("    X11Forwarding no");
                sb.AppendLine($"    AuthorizedKeysFile {normalizedKeys}");
            }

            foreach (var rule in rules.Where(r => r.IsGroup && !string.IsNullOrWhiteSpace(r.RootPath)))
            {
                var cleanId = SecurityValidator.SanitizeSingleLine(rule.Identifier).Replace(" ", "").Replace("\"", "");
                var normPath = FormatConfigPath(rule.RootPath.Replace("/", "\\"));
                sb.AppendLine($"Match Group {cleanId}");
                sb.AppendLine($"    ChrootDirectory {normPath}");
                sb.AppendLine("    ForceCommand internal-sftp");
                sb.AppendLine("    AllowTcpForwarding no");
                sb.AppendLine("    X11Forwarding no");
                sb.AppendLine($"    AuthorizedKeysFile {normalizedKeys}");
            }
        }

        sb.AppendLine("Match Group SFTP-Users");
        sb.AppendLine($"    ChrootDirectory {defaultNormalizedRoot}");
        sb.AppendLine("    ForceCommand internal-sftp");
        sb.AppendLine("    AllowTcpForwarding no");
        sb.AppendLine("    X11Forwarding no");
        sb.AppendLine($"    AuthorizedKeysFile {normalizedKeys}");

        sb.AppendLine(BlockFooter);
        return sb.ToString();
    }

    public ConfigValidationResult ValidateConfigSyntax()
    {
        return _configService.ValidateSyntax(ConfigPath);
    }

    public async Task<(bool Success, string Message)> ApplyZeroConfigBlockAsync()
    {
        return await SyncManagedConfigAsync(new List<DirectChrootRule>(), autoRestart: false);
    }

    public async Task<(bool Success, string Message)> SyncManagedConfigAsync(IEnumerable<DirectChrootRule> rules, bool autoRestart = true)
    {
        // 1. Atomically update config via SshdConfigService (Write to temp, test with sshd -t -f, File.Replace)
        var result = await _configService.SyncManagedBlocksAsync(rules, SftpRoot, KeysPath, ConfigPath);
        if (!result.Success)
        {
            return result;
        }

        // 2. Optional auto-restart
        if (autoRestart)
        {
            var (restartOk, restartMsg) = await RestartServiceAsync(DefaultSshdServiceName);
            if (!restartOk)
            {
                return (true, $"Config updated and validated, but service restart notice: {restartMsg}");
            }
        }

        return (true, "OpenSSH sshd_config updated, validated, and applied successfully.");
    }

    public async Task<(bool Success, string Message)> RestartServiceAsync(string serviceName = DefaultSshdServiceName)
    {
        await _serviceLock.WaitAsync();
        try
        {
            return await Task.Run(() =>
            {
                // Only validate sshd config when restarting sshd service
                if (serviceName.Equals(DefaultSshdServiceName, StringComparison.OrdinalIgnoreCase))
                {
                    var validation = ValidateConfigSyntax();
                    if (!validation.IsValid)
                    {
                        return (false, $"Cannot restart OpenSSH: sshd.exe -t syntax error: {validation.Output}");
                    }
                }

                try
                {
                    using var sc = new ServiceController(serviceName);

                    // Stop if running or start pending
                    if (sc.Status == ServiceControllerStatus.Running || sc.Status == ServiceControllerStatus.StartPending)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
                    }

                    // Start service
                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));

                    return (true, $"Service '{serviceName}' restarted successfully.");
                }
                catch (Win32Exception ex)
                {
                    _logger.LogError(ex, "Win32 permission error restarting service '{Service}'.", serviceName);
                    return (false, $"Access Denied restarting service '{serviceName}'. Requires Local Administrator privileges (Win32 Error: {ex.NativeErrorCode}).");
                }
                catch (System.ServiceProcess.TimeoutException ex)
                {
                    _logger.LogError(ex, "Timeout waiting for service '{Service}' to transition.", serviceName);
                    return (false, $"Timeout waiting for service '{serviceName}' to restart within 15 seconds.");
                }
                catch (InvalidOperationException ex)
                {
                    _logger.LogError(ex, "InvalidOperationException restarting service '{Service}'.", serviceName);
                    return (false, $"Cannot control service '{serviceName}': {ex.Message}");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Unexpected error restarting service '{Service}'.", serviceName);
                    return (false, $"Error restarting service '{serviceName}': {ex.Message}");
                }
            });
        }
        finally
        {
            _serviceLock.Release();
        }
    }

    public async Task<(bool Success, string Message)> StartServiceAsync(string serviceName = DefaultSshdServiceName)
    {
        await _serviceLock.WaitAsync();
        try
        {
            return await Task.Run(() =>
            {
                if (serviceName.Equals(DefaultSshdServiceName, StringComparison.OrdinalIgnoreCase))
                {
                    var validation = ValidateConfigSyntax();
                    if (!validation.IsValid)
                    {
                        return (false, $"Cannot start OpenSSH: sshd.exe -t syntax check failed: {validation.Output}");
                    }
                }

                try
                {
                    using var sc = new ServiceController(serviceName);
                    if (sc.Status == ServiceControllerStatus.Running)
                        return (true, $"Service '{serviceName}' is already running.");

                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));
                    return (true, $"Service '{serviceName}' started successfully.");
                }
                catch (Win32Exception ex)
                {
                    _logger.LogError(ex, "Win32 permission error starting service '{Service}'.", serviceName);
                    return (false, $"Access Denied starting service '{serviceName}'. Requires Local Administrator privileges (Win32 Error: {ex.NativeErrorCode}).");
                }
                catch (System.ServiceProcess.TimeoutException ex)
                {
                    _logger.LogError(ex, "Timeout waiting for service '{Service}' to start.", serviceName);
                    return (false, $"Timeout waiting for service '{serviceName}' to start within 15 seconds.");
                }
                catch (InvalidOperationException ex)
                {
                    _logger.LogError(ex, "Cannot start service '{Service}'.", serviceName);
                    return (false, $"Cannot start service '{serviceName}': {ex.Message}");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Unexpected error starting service '{Service}'.", serviceName);
                    return (false, $"Error starting service '{serviceName}': {ex.Message}");
                }
            });
        }
        finally
        {
            _serviceLock.Release();
        }
    }

    public async Task<(bool Success, string Message)> StopServiceAsync(string serviceName = DefaultSshdServiceName)
    {
        await _serviceLock.WaitAsync();
        try
        {
            return await Task.Run(() =>
            {
                try
                {
                    using var sc = new ServiceController(serviceName);
                    if (sc.Status == ServiceControllerStatus.Stopped)
                        return (true, $"Service '{serviceName}' is already stopped.");

                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
                    return (true, $"Service '{serviceName}' stopped successfully.");
                }
                catch (Win32Exception ex)
                {
                    _logger.LogError(ex, "Win32 permission error stopping service '{Service}'.", serviceName);
                    return (false, $"Access Denied stopping service '{serviceName}'. Requires Local Administrator privileges (Win32 Error: {ex.NativeErrorCode}).");
                }
                catch (System.ServiceProcess.TimeoutException ex)
                {
                    _logger.LogError(ex, "Timeout waiting for service '{Service}' to stop.", serviceName);
                    return (false, $"Timeout waiting for service '{serviceName}' to stop within 15 seconds.");
                }
                catch (InvalidOperationException ex)
                {
                    _logger.LogError(ex, "Cannot stop service '{Service}'.", serviceName);
                    return (false, $"Cannot stop service '{serviceName}': {ex.Message}");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Unexpected error stopping service '{Service}'.", serviceName);
                    return (false, $"Error stopping service '{serviceName}': {ex.Message}");
                }
            });
        }
        finally
        {
            _serviceLock.Release();
        }
    }

    private static string FormatConfigPath(string rawPath)
    {
        var clean = SecurityValidator.SanitizeSingleLine(rawPath).Replace("\"", "").Trim();
        return clean.Contains(' ') ? $"\"{clean}\"" : clean;
    }
}
