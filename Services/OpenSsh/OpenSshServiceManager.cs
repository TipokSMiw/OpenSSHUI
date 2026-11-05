using System.Diagnostics;
using System.Runtime.Versioning;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
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
}

[SupportedOSPlatform("windows")]
public class OpenSshServiceManager : IOpenSshServiceManager
{
    private const string ServiceName = "sshd";
    private readonly IConfiguration? _configuration;
    private readonly string _defaultConfigPath;
    private readonly string _defaultKeysPath;
    private readonly string _defaultSftpRoot;
    private readonly ILogger<OpenSshServiceManager> _logger;
    private readonly SemaphoreSlim _configLock = new(1, 1);
    private readonly SemaphoreSlim _serviceLock = new(1, 1);

    public const string BlockHeader = "# >>> SFTP Zero-Config Block (Managed by OpensshUI) >>>";
    public const string BlockFooter = "# <<< SFTP Zero-Config Block (Managed by OpensshUI) <<<";

    public OpenSshServiceManager(
        ILogger<OpenSshServiceManager> logger,
        IConfiguration? configuration = null)
    {
        _logger = logger;
        _configuration = configuration;
        _defaultSftpRoot = configuration?["SftpSettings:SftpRoot"] ?? @"C:\SFTPRoot";
        _defaultKeysPath = configuration?["SftpSettings:KeysPath"] ?? @"C:\ProgramData\ssh\keys";
        _defaultConfigPath = configuration?["SftpSettings:SshdConfigPath"] ?? @"C:\ProgramData\ssh\sshd_config";
    }

    public string ConfigPath => _configuration?["SftpSettings:SshdConfigPath"] ?? _defaultConfigPath;
    public string KeysPath => _configuration?["SftpSettings:KeysPath"] ?? _defaultKeysPath;
    public string SftpRoot => _configuration?["SftpSettings:SftpRoot"] ?? _defaultSftpRoot;

    public string FindSshdExecutable()
    {
        string[] candidates = {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "OpenSSH", "sshd.exe"),
            @"C:\Program Files\OpenSSH\sshd.exe",
            @"C:\Windows\System32\OpenSSH\sshd.exe"
        };

        foreach (var path in candidates)
        {
            if (File.Exists(path)) return path;
        }

        return "sshd.exe"; // Fallback to PATH
    }

    public ServiceStatusInfo GetStatus()
    {
        var info = new ServiceStatusInfo
        {
            ConfigPath = _defaultConfigPath,
            SshdExecutablePath = FindSshdExecutable()
        };

        try
        {
            using var sc = new ServiceController(ServiceName);
            info.IsInstalled = true;
            info.Status = sc.Status.ToString();
            info.CanStart = sc.Status == ServiceControllerStatus.Stopped;
            info.CanStop = sc.Status == ServiceControllerStatus.Running;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "OpenSSH service '{Service}' could not be queried directly.", ServiceName);
            info.IsInstalled = false;
            info.Status = "Not Installed / Access Denied";
        }

        info.HasZeroConfigBlock = CheckHasZeroConfigBlock();
        return info;
    }

    public bool CheckHasZeroConfigBlock()
    {
        if (!File.Exists(_defaultConfigPath)) return false;

        try
        {
            var content = File.ReadAllText(_defaultConfigPath);
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

    private static string FormatConfigPath(string rawPath)
    {
        var clean = SecurityValidator.SanitizeSingleLine(rawPath).Replace("\"", "").Trim();
        return clean.Contains(' ') ? $"\"{clean}\"" : clean;
    }

    public string GenerateManagedBlock(IEnumerable<DirectChrootRule>? customRules, string? sftpRoot = null, string? keysPath = null)
    {
        var root = sftpRoot ?? _defaultSftpRoot;
        var keys = keysPath ?? _defaultKeysPath;

        var normalizedKeys = FormatConfigPath(keys.Replace("\\", "/").TrimEnd('/') + "/%u");
        var defaultNormalizedRoot = FormatConfigPath(root.Replace("/", "\\").TrimEnd('\\') + "\\%u");

        var sb = new StringBuilder();
        sb.AppendLine();
        sb.AppendLine(BlockHeader);

        // 1. Specific custom DirectChroot rules (Users first, then specific Groups)
        if (customRules != null)
        {
            var rules = customRules.ToList();

            // Match User rules first
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

            // Match Group rules (specific groups before generic SFTP-Users)
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

        // 2. Generic default SFTP-Users rule
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
        var sshdPath = FindSshdExecutable();
        var result = new ConfigValidationResult();

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = sshdPath,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add("-t");

            using var proc = new Process { StartInfo = psi };
            proc.Start();

            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();

            bool completed = proc.WaitForExit(5000);
            if (!completed)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                result.IsValid = false;
                result.ErrorMessage = "sshd -t syntax validation timed out.";
                return result;
            }

            Task.WaitAll(new[] { stdoutTask, stderrTask }, TimeSpan.FromMilliseconds(1000));
            var stdout = stdoutTask.Result;
            var stderr = stderrTask.Result;

            result.Output = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
            result.IsValid = proc.ExitCode == 0;

            if (!result.IsValid && string.IsNullOrWhiteSpace(result.ErrorMessage))
            {
                result.ErrorMessage = result.Output;
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to run sshd -t syntax validation.");
            result.IsValid = false;
            result.ErrorMessage = ex.Message;
            return result;
        }
    }

    public async Task<(bool Success, string Message)> ApplyZeroConfigBlockAsync()
    {
        return await SyncManagedConfigAsync(new List<DirectChrootRule>(), autoRestart: false);
    }

    public async Task<(bool Success, string Message)> SyncManagedConfigAsync(IEnumerable<DirectChrootRule> rules, bool autoRestart = true)
    {
        await _configLock.WaitAsync();
        try
        {
            if (!File.Exists(_defaultConfigPath))
            {
                return (false, $"Configuration file not found at {_defaultConfigPath}. Ensure OpenSSH Server is installed.");
            }

            var currentContent = await File.ReadAllTextAsync(_defaultConfigPath);
            var newBlock = GenerateManagedBlock(rules);

            // Strip existing block if present
            var pattern = Regex.Escape(BlockHeader) + @"[\s\S]*?" + Regex.Escape(BlockFooter);
            string updatedContent;
            if (Regex.IsMatch(currentContent, pattern))
            {
                updatedContent = Regex.Replace(currentContent, pattern, newBlock.TrimStart());
            }
            else
            {
                updatedContent = currentContent.TrimEnd() + Environment.NewLine + newBlock;
            }

            // Backup existing config with millisecond precision to avoid collisions
            var backupPath = $"{_defaultConfigPath}.bak_{DateTime.UtcNow:yyyyMMdd_HHmmss_fff}";
            File.Copy(_defaultConfigPath, backupPath, true);
            CleanupOldConfigBackups(maxBackups: 5);

            await File.WriteAllTextAsync(_defaultConfigPath, updatedContent);

            // Validate syntax immediately off the UI thread
            var validation = await Task.Run(ValidateConfigSyntax);
            if (!validation.IsValid)
            {
                // Rollback on syntax error
                File.Copy(backupPath, _defaultConfigPath, true);
                return (false, $"Config syntax error detected by sshd -t: {validation.Output}. Restored from backup.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sync managed sshd_config.");
            return (false, ex.Message);
        }
        finally
        {
            _configLock.Release();
        }

        if (autoRestart)
        {
            var (restartOk, restartMsg) = await RestartServiceAsync();
            if (!restartOk)
            {
                return (true, $"Config updated and validated, but restart had warning: {restartMsg}");
            }
        }

        return (true, "OpenSSH sshd_config updated, validated, and applied successfully.");
    }

    private void CleanupOldConfigBackups(int maxBackups = 5)
    {
        try
        {
            var dir = Path.GetDirectoryName(_defaultConfigPath);
            var fileName = Path.GetFileName(_defaultConfigPath);
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;

            var backups = new DirectoryInfo(dir)
                .GetFiles($"{fileName}.bak_*")
                .OrderByDescending(f => f.CreationTimeUtc)
                .Skip(maxBackups)
                .ToList();

            foreach (var oldBackup in backups)
            {
                try { oldBackup.Delete(); } catch { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not clean up old sshd_config backup files.");
        }
    }

    public async Task<(bool Success, string Message)> RestartServiceAsync()
    {
        await _serviceLock.WaitAsync();
        try
        {
            return await Task.Run(() =>
            {
                // 1. ALWAYS validate config syntax first!
                var validation = ValidateConfigSyntax();
                if (!validation.IsValid)
                {
                    return (false, $"Cannot restart OpenSSH: sshd -t syntax error: {validation.Output}");
                }

                try
                {
                    using var sc = new ServiceController(ServiceName);
                    if (sc.Status == ServiceControllerStatus.Running)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
                    }

                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));

                    return (true, "OpenSSH (sshd) service restarted successfully.");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error restarting sshd service.");
                    return (false, $"Error restarting service: {ex.Message}");
                }
            });
        }
        finally
        {
            _serviceLock.Release();
        }
    }

    public async Task<(bool Success, string Message)> StartServiceAsync()
    {
        await _serviceLock.WaitAsync();
        try
        {
            return await Task.Run(() =>
            {
                var validation = ValidateConfigSyntax();
                if (!validation.IsValid)
                {
                    return (false, $"Cannot start OpenSSH: sshd -t syntax check failed: {validation.Output}");
                }

                try
                {
                    using var sc = new ServiceController(ServiceName);
                    if (sc.Status == ServiceControllerStatus.Running)
                        return (true, "Service is already running.");

                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));
                    return (true, "Service started successfully.");
                }
                catch (Exception ex)
                {
                    return (false, ex.Message);
                }
            });
        }
        finally
        {
            _serviceLock.Release();
        }
    }

    public async Task<(bool Success, string Message)> StopServiceAsync()
    {
        await _serviceLock.WaitAsync();
        try
        {
            return await Task.Run(() =>
            {
                try
                {
                    using var sc = new ServiceController(ServiceName);
                    if (sc.Status == ServiceControllerStatus.Stopped)
                        return (true, "Service is already stopped.");

                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
                    return (true, "Service stopped successfully.");
                }
                catch (Exception ex)
                {
                    return (false, ex.Message);
                }
            });
        }
        finally
        {
            _serviceLock.Release();
        }
    }
}
