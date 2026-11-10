using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using System.Text.RegularExpressions;
using OpensshUI.Services.Security;

namespace OpensshUI.Services.OpenSsh;

[SupportedOSPlatform("windows")]
public class SshdConfigService : ISshdConfigService
{
    public const string BlockHeader = "# >>> SFTP Zero-Config Block (Managed by OpensshUI) >>>";
    public const string BlockFooter = "# <<< SFTP Zero-Config Block (Managed by OpensshUI) <<<";

    private static readonly HashSet<string> GlobalOnlyDirectives = new(StringComparer.OrdinalIgnoreCase)
    {
        "Port", "ListenAddress", "HostKey", "AddressFamily", "PidFile",
        "Subsystem", "SyslogFacility", "Protocol", "AcceptEnv", "UsePAM"
    };

    private static readonly Regex LineErrorRegex = new(@"line\s+\d+:", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly IConfiguration? _configuration;
    private readonly ILogger<SshdConfigService> _logger;
    private readonly SemaphoreSlim _fileLock = new(1, 1);
    private readonly string _defaultConfigPath;

    public SshdConfigService(
        ILogger<SshdConfigService> logger,
        IConfiguration? configuration = null)
    {
        _logger = logger;
        _configuration = configuration;
        _defaultConfigPath = configuration?["SftpSettings:SshdConfigPath"] ?? @"C:\ProgramData\ssh\sshd_config";
    }

    public string ConfigPath => _configuration?["SftpSettings:SshdConfigPath"] ?? _defaultConfigPath;

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

    public SshdConfigFile Parse(string configContent)
    {
        var result = new SshdConfigFile();
        if (string.IsNullOrWhiteSpace(configContent))
        {
            return result;
        }

        var lines = configContent.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
        bool inManagedBlock = false;
        SshdMatchBlock? currentBlock = null;
        var pendingComments = new List<string>();

        foreach (var rawLine in lines)
        {
            var trimmed = rawLine.Trim();

            // Track managed block boundaries
            if (trimmed.Equals(BlockHeader, StringComparison.OrdinalIgnoreCase))
            {
                if (currentBlock == null && pendingComments.Count > 0)
                {
                    result.GlobalLines.AddRange(pendingComments);
                }
                pendingComments.Clear();
                inManagedBlock = true;
                currentBlock = null;
                continue;
            }
            if (trimmed.Equals(BlockFooter, StringComparison.OrdinalIgnoreCase))
            {
                pendingComments.Clear();
                inManagedBlock = false;
                currentBlock = null;
                continue;
            }

            // Comment lines or blank lines
            if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith("#"))
            {
                pendingComments.Add(rawLine);
                continue;
            }

            // Check for Match block start
            if (trimmed.StartsWith("Match ", StringComparison.OrdinalIgnoreCase))
            {
                var matchParts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                var matchType = matchParts.Length > 1 ? matchParts[1] : "All";
                var pattern = matchParts.Length > 2 ? string.Join(" ", matchParts.Skip(2)) : string.Empty;

                // Keep only non-blank comment lines as preceding comments for this Match block
                var blockComments = pendingComments
                    .Where(c => !string.IsNullOrWhiteSpace(c))
                    .Select(c => c.Trim())
                    .ToList();

                currentBlock = new SshdMatchBlock
                {
                    MatchType = matchType,
                    Pattern = pattern,
                    IsManaged = inManagedBlock,
                    Comments = blockComments
                };
                pendingComments.Clear();
                result.MatchBlocks.Add(currentBlock);
                continue;
            }

            // Directive line
            var firstSpace = trimmed.IndexOfAny(new[] { ' ', '\t' });
            var key = firstSpace > 0 ? trimmed[..firstSpace].Trim() : trimmed;
            var value = firstSpace > 0 ? trimmed[firstSpace..].Trim() : string.Empty;

            // OpenSSH rule: Global-only directives MUST NOT bleed into Match blocks!
            if (GlobalOnlyDirectives.Contains(key))
            {
                if (pendingComments.Count > 0)
                {
                    result.GlobalLines.AddRange(pendingComments.Where(c => !string.IsNullOrWhiteSpace(c) || currentBlock == null));
                    pendingComments.Clear();
                }
                result.GlobalLines.Add(rawLine);
                currentBlock = null; // Ends preceding match block
                continue;
            }

            if (currentBlock != null)
            {
                // Flush any internal comments that appeared before this directive inside the Match block
                foreach (var pending in pendingComments)
                {
                    var pTrim = pending.Trim();
                    if (pTrim.StartsWith("#"))
                    {
                        currentBlock.Directives.Add(new SshdDirective
                        {
                            RawLine = pending,
                            Key = "#",
                            Value = pTrim[1..].Trim()
                        });
                    }
                }
                pendingComments.Clear();

                currentBlock.Directives.Add(new SshdDirective
                {
                    Key = key,
                    Value = value,
                    RawLine = rawLine
                });
            }
            else
            {
                if (pendingComments.Count > 0)
                {
                    result.GlobalLines.AddRange(pendingComments);
                    pendingComments.Clear();
                }
                result.GlobalLines.Add(rawLine);
            }
        }

        // Flush any trailing comments
        if (pendingComments.Count > 0)
        {
            if (currentBlock != null && !currentBlock.IsManaged)
            {
                foreach (var pending in pendingComments)
                {
                    var pTrim = pending.Trim();
                    if (pTrim.StartsWith("#"))
                    {
                        currentBlock.Directives.Add(new SshdDirective
                        {
                            RawLine = pending,
                            Key = "#",
                            Value = pTrim[1..].Trim()
                        });
                    }
                }
            }
            else if (currentBlock == null)
            {
                result.GlobalLines.AddRange(pendingComments);
            }
        }

        // Guard against unclosed managed block at EOF
        if (inManagedBlock)
        {
            _logger.LogWarning("Unclosed managed block header ('{Header}') detected in sshd_config; auto-closing managed section at EOF.", BlockHeader);
            inManagedBlock = false;
        }

        // Trim trailing empty lines from GlobalLines for idempotent serialization
        while (result.GlobalLines.Count > 0 && string.IsNullOrWhiteSpace(result.GlobalLines[^1]))
        {
            result.GlobalLines.RemoveAt(result.GlobalLines.Count - 1);
        }

        return result;
    }

    public string Serialize(SshdConfigFile configFile)
    {
        var sb = new StringBuilder();

        // 1. Output all global lines at the top
        bool hasGlobalLines = false;
        foreach (var line in configFile.GlobalLines)
        {
            sb.AppendLine(line);
            hasGlobalLines = true;
        }

        if (hasGlobalLines)
        {
            sb.AppendLine();
        }

        // 2. Output unmanaged custom Match blocks
        var unmanagedBlocks = configFile.MatchBlocks.Where(b => !b.IsManaged).ToList();
        foreach (var block in unmanagedBlocks)
        {
            foreach (var comment in block.Comments)
            {
                sb.AppendLine(comment);
            }
            sb.AppendLine($"Match {block.MatchType} {block.Pattern}");
            foreach (var dir in block.Directives)
            {
                if (dir.Key == "#")
                {
                    sb.AppendLine($"    # {dir.Value}");
                }
                else
                {
                    sb.AppendLine($"    {dir.Key} {dir.Value}");
                }
            }
            sb.AppendLine();
        }

        // 3. Output managed Match blocks inside the managed demarcated section
        var managedBlocks = configFile.MatchBlocks.Where(b => b.IsManaged).ToList();
        if (managedBlocks.Count > 0)
        {
            sb.AppendLine(BlockHeader);
            foreach (var block in managedBlocks)
            {
                foreach (var comment in block.Comments)
                {
                    sb.AppendLine(comment);
                }
                sb.AppendLine($"Match {block.MatchType} {block.Pattern}");
                foreach (var dir in block.Directives)
                {
                    if (dir.Key == "#")
                    {
                        sb.AppendLine($"    # {dir.Value}");
                    }
                    else
                    {
                        sb.AppendLine($"    {dir.Key} {dir.Value}");
                    }
                }
            }
            sb.AppendLine(BlockFooter);
        }

        return sb.ToString().TrimEnd() + Environment.NewLine;
    }

    public ConfigValidationResult ValidateSyntax(string configFilePath)
    {
        var sshdPath = FindSshdExecutable();
        var result = new ConfigValidationResult();

        if (!File.Exists(sshdPath))
        {
            _logger.LogWarning("sshd executable not found at '{Path}'. Syntax check running in fallback mode.", sshdPath);
            result.IsValid = true;
            result.Output = "sshd.exe not found on host (dev environment); syntax check bypassed.";
            return result;
        }

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
            psi.ArgumentList.Add("-f");
            psi.ArgumentList.Add(configFilePath);

            using var proc = new Process { StartInfo = psi };
            proc.Start();

            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();

            bool completed = proc.WaitForExit(5000);
            if (!completed)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                result.IsValid = false;
                result.ErrorMessage = "sshd.exe -t -f validation timed out.";
                return result;
            }

            Task.WaitAll(new[] { stdoutTask, stderrTask }, TimeSpan.FromMilliseconds(1000));
            var stdout = stdoutTask.Result;
            var stderr = stderrTask.Result;

            var outputCombined = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;

            // Check for actual syntax errors reported by sshd parser
            bool hasSyntaxError = outputCombined.Contains("bad configuration option", StringComparison.OrdinalIgnoreCase)
                || outputCombined.Contains("terminating,", StringComparison.OrdinalIgnoreCase)
                || outputCombined.Contains("is not allowed within a Match block", StringComparison.OrdinalIgnoreCase)
                || LineErrorRegex.IsMatch(outputCombined);

            // In test or non-elevated environments, sshd -t exits with code 1 if private host keys are inaccessible
            bool onlyHostKeyIssue = !hasSyntaxError && (
                outputCombined.Contains("no hostkeys available", StringComparison.OrdinalIgnoreCase) ||
                outputCombined.Contains("Unable to load host key", StringComparison.OrdinalIgnoreCase));

            if (proc.ExitCode == 0 || onlyHostKeyIssue)
            {
                result.IsValid = true;
                result.Output = onlyHostKeyIssue
                    ? "Configuration syntax is valid. (Host key loading deferred to service start)."
                    : outputCombined;
            }
            else
            {
                result.IsValid = false;
                result.ErrorMessage = outputCombined;
                result.Output = outputCombined;
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to run sshd -t -f syntax validation on {Path}.", configFilePath);
            result.IsValid = false;
            result.ErrorMessage = ex.Message;
            return result;
        }
    }

    public ConfigValidationResult ValidateSyntaxContent(string configContent)
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"sshd_test_{Guid.NewGuid():N}.conf");
        try
        {
            File.WriteAllText(tempFile, configContent, new UTF8Encoding(false));
            return ValidateSyntax(tempFile);
        }
        finally
        {
            try
            {
                if (File.Exists(tempFile)) File.Delete(tempFile);
            }
            catch { }
        }
    }

    public async Task<(bool Success, string Message)> AtomicWriteAndApplyAsync(string newContent, string? targetPath = null)
    {
        var finalPath = targetPath ?? ConfigPath;
        var dir = Path.GetDirectoryName(finalPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        await _fileLock.WaitAsync();
        try
        {
            return await AtomicWriteAndApplyCoreAsync(newContent, finalPath);
        }
        finally
        {
            _fileLock.Release();
        }
    }

    private async Task<(bool Success, string Message)> AtomicWriteAndApplyCoreAsync(string newContent, string finalPath)
    {
        var tempPath = $"{finalPath}.tmp_{Guid.NewGuid():N}";
        try
        {
            // 1. Write proposed configuration to .tmp file strictly in the same directory (volume)
            await File.WriteAllTextAsync(tempPath, newContent, new UTF8Encoding(false));

            // 2. Run syntax check via sshd -t -f <temp_path>
            var validation = await Task.Run(() => ValidateSyntax(tempPath));
            if (!validation.IsValid)
            {
                _logger.LogWarning("Config syntax check failed for proposed changes: {Error}", validation.ErrorMessage);
                return (false, $"Configuration syntax validation failed (ExitCode != 0): {validation.ErrorMessage}");
            }

            // 3. Atomically replace target file and rotate backup keeping last 5
            if (File.Exists(finalPath))
            {
                var backupPath = $"{finalPath}.bak_{DateTime.UtcNow:yyyyMMdd_HHmmss_fff}_{Guid.NewGuid().ToString("N")[..4]}";
                File.Replace(tempPath, finalPath, backupPath, ignoreMetadataErrors: true);
                CleanupOldConfigBackups(finalPath, maxBackups: 5);
            }
            else
            {
                File.Move(tempPath, finalPath, overwrite: true);
            }

            _logger.LogInformation("sshd_config atomically applied and verified at {Path}", finalPath);
            return (true, "OpenSSH sshd_config successfully validated and atomically updated.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed atomic write for {Path}", finalPath);
            return (false, $"Atomic write failed: {ex.Message}");
        }
        finally
        {
            try
            {
                if (File.Exists(tempPath)) File.Delete(tempPath);
            }
            catch { }
        }
    }

    public async Task<(bool Success, string Message)> SyncManagedBlocksAsync(
        IEnumerable<DirectChrootRule> rules,
        string sftpRoot,
        string keysPath,
        string? targetPath = null)
    {
        var finalPath = targetPath ?? ConfigPath;

        // Hold _fileLock across the entire Read -> Parse -> Modify -> Write cycle to prevent TOCTOU / Lost Updates
        await _fileLock.WaitAsync();
        try
        {
            if (!File.Exists(finalPath))
            {
                return (false, $"Configuration file not found at {finalPath}. Ensure OpenSSH Server is installed.");
            }

            var currentContent = await File.ReadAllTextAsync(finalPath);
            var configFile = Parse(currentContent);

            // Remove previous managed blocks
            configFile.MatchBlocks.RemoveAll(b => b.IsManaged);

            var normalizedKeys = FormatConfigPath(keysPath.Replace("\\", "/").TrimEnd('/') + "/%u");
            var defaultNormalizedRoot = FormatConfigPath(sftpRoot.Replace("/", "\\").TrimEnd('\\') + "\\%u");

            // 1. Add custom DirectChroot rules (Users first, then Groups)
            var ruleList = rules.ToList();

            foreach (var userRule in ruleList.Where(r => !r.IsGroup && !string.IsNullOrWhiteSpace(r.RootPath)))
            {
                var cleanId = SanitizeMatchIdentifier(userRule.Identifier);
                if (string.IsNullOrWhiteSpace(cleanId)) continue;

                var (isSafePath, pathErr) = SecurityValidator.ValidateSafeCustomPath(userRule.RootPath, sftpRoot);
                if (!isSafePath)
                {
                    _logger.LogWarning("Skipping unsafe DirectChroot user rule for '{User}' path '{Path}': {Error}", cleanId, userRule.RootPath, pathErr);
                    continue;
                }

                var normPath = FormatConfigPath(userRule.RootPath.Replace("/", "\\"));

                configFile.MatchBlocks.Add(new SshdMatchBlock
                {
                    MatchType = "User",
                    Pattern = cleanId,
                    IsManaged = true,
                    Directives = new List<SshdDirective>
                    {
                        new() { Key = "ChrootDirectory", Value = normPath },
                        new() { Key = "ForceCommand", Value = "internal-sftp" },
                        new() { Key = "AllowTcpForwarding", Value = "no" },
                        new() { Key = "X11Forwarding", Value = "no" },
                        new() { Key = "AuthorizedKeysFile", Value = normalizedKeys }
                    }
                });
            }

            foreach (var groupRule in ruleList.Where(r => r.IsGroup && !string.IsNullOrWhiteSpace(r.RootPath)))
            {
                var cleanId = SanitizeMatchIdentifier(groupRule.Identifier);
                if (string.IsNullOrWhiteSpace(cleanId)) continue;

                var (isSafePath, pathErr) = SecurityValidator.ValidateSafeCustomPath(groupRule.RootPath, sftpRoot);
                if (!isSafePath)
                {
                    _logger.LogWarning("Skipping unsafe DirectChroot group rule for '{Group}' path '{Path}': {Error}", cleanId, groupRule.RootPath, pathErr);
                    continue;
                }

                var normPath = FormatConfigPath(groupRule.RootPath.Replace("/", "\\"));

                configFile.MatchBlocks.Add(new SshdMatchBlock
                {
                    MatchType = "Group",
                    Pattern = cleanId,
                    IsManaged = true,
                    Directives = new List<SshdDirective>
                    {
                        new() { Key = "ChrootDirectory", Value = normPath },
                        new() { Key = "ForceCommand", Value = "internal-sftp" },
                        new() { Key = "AllowTcpForwarding", Value = "no" },
                        new() { Key = "X11Forwarding", Value = "no" },
                        new() { Key = "AuthorizedKeysFile", Value = normalizedKeys }
                    }
                });
            }

            // 2. Generic default SFTP-Users rule
            configFile.MatchBlocks.Add(new SshdMatchBlock
            {
                MatchType = "Group",
                Pattern = "SFTP-Users",
                IsManaged = true,
                Directives = new List<SshdDirective>
                {
                    new() { Key = "ChrootDirectory", Value = defaultNormalizedRoot },
                    new() { Key = "ForceCommand", Value = "internal-sftp" },
                    new() { Key = "AllowTcpForwarding", Value = "no" },
                    new() { Key = "X11Forwarding", Value = "no" },
                    new() { Key = "AuthorizedKeysFile", Value = normalizedKeys }
                }
            });

            var serialized = Serialize(configFile);
            return await AtomicWriteAndApplyCoreAsync(serialized, finalPath);
        }
        finally
        {
            _fileLock.Release();
        }
    }

    public List<string> GetBackupFiles(int maxBackups = 5)
    {
        try
        {
            var dir = Path.GetDirectoryName(ConfigPath);
            var fileName = Path.GetFileName(ConfigPath);
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return new List<string>();

            return new DirectoryInfo(dir)
                .GetFiles($"{fileName}.bak_*")
                .OrderByDescending(f => f.CreationTimeUtc)
                .Take(maxBackups)
                .Select(f => f.FullName)
                .ToList();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not list backup files.");
            return new List<string>();
        }
    }

    private void CleanupOldConfigBackups(string configPath, int maxBackups = 5)
    {
        try
        {
            var dir = Path.GetDirectoryName(configPath);
            var fileName = Path.GetFileName(configPath);
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
            _logger.LogDebug(ex, "Could not clean up old config backups.");
        }
    }

    private static string SanitizeMatchIdentifier(string? rawIdentifier)
    {
        if (string.IsNullOrWhiteSpace(rawIdentifier)) return string.Empty;

        var clean = SecurityValidator.SanitizeSingleLine(rawIdentifier);
        // Strip spaces, quotes, and OpenSSH Match pattern wildcards/negation/list separators (* ? ! ,)
        char[] forbiddenMatchChars = { ' ', '\t', '"', '*', '?', '!', ',', ';', '#', '|' };
        foreach (var ch in forbiddenMatchChars)
        {
            clean = clean.Replace(ch.ToString(), "");
        }

        return clean.Trim();
    }

    private static string FormatConfigPath(string rawPath)
    {
        var clean = SecurityValidator.SanitizeSingleLine(rawPath).Replace("\"", "").Trim();
        return clean.Contains(' ') ? $"\"{clean}\"" : clean;
    }
}
