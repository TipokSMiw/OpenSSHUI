using System.Diagnostics;
using System.Runtime.Versioning;
using OpensshUI.Services.Security;

namespace OpensshUI.Services.OpenSsh;

[SupportedOSPlatform("windows")]
public class WindowsUserManager : IWindowsUserManager
{
    private readonly ILogger<WindowsUserManager> _logger;

    public WindowsUserManager(ILogger<WindowsUserManager> logger)
    {
        _logger = logger;
    }

    private record ProcessResult(int ExitCode, string StandardOutput, string StandardError, bool TimedOut);

    private static string FormatMaskedArguments(IEnumerable<string> arguments)
    {
        var argList = arguments.ToList();
        var masked = new List<string>(argList.Count);

        for (int i = 0; i < argList.Count; i++)
        {
            var arg = argList[i];

            // In "net user <username> <password>", argument at index 2 is password if index 0 is "user"
            if (i == 2 && argList.Count > 2 && string.Equals(argList[0], "user", StringComparison.OrdinalIgnoreCase) && !arg.StartsWith('/'))
            {
                masked.Add("******");
            }
            else if (arg.StartsWith("/password:", StringComparison.OrdinalIgnoreCase))
            {
                masked.Add("/password:******");
            }
            else
            {
                masked.Add(arg);
            }
        }

        return string.Join(" ", masked);
    }

    private ProcessResult RunProcess(string fileName, IEnumerable<string> arguments, int timeoutMs = 5000)
    {
        var argList = arguments.ToList();
        var safeArgsForLog = FormatMaskedArguments(argList);

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            foreach (var arg in argList)
            {
                psi.ArgumentList.Add(arg);
            }

            using var proc = new Process { StartInfo = psi };
            proc.Start();

            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();

            bool completed = proc.WaitForExit(timeoutMs);
            if (!completed)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                _logger.LogWarning("Process {FileName} {Args} timed out after {Timeout}ms and was killed.", fileName, safeArgsForLog, timeoutMs);
                return new ProcessResult(-1, "", "Process timed out.", true);
            }

            Task.WaitAll(new[] { stdoutTask, stderrTask }, TimeSpan.FromMilliseconds(1000));
            return new ProcessResult(proc.ExitCode, stdoutTask.Result, stderrTask.Result, false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to execute process {FileName} {Args}", fileName, safeArgsForLog);
            return new ProcessResult(-1, "", ex.Message, false);
        }
    }

    public static string ToOsGroupName(string name)
    {
        var clean = name.Trim().Replace(" ", "_");
        if (clean.StartsWith("SFTP-", StringComparison.OrdinalIgnoreCase))
        {
            return clean;
        }
        return $"SFTP-{clean}";
    }

    public bool EnsureSftpUsersGroup(string groupName = "SFTP-Users")
    {
        return EnsureLocalGroup(groupName, "Managed SFTP Users");
    }

    public bool EnsureLocalGroup(string groupName, string? comment = null)
    {
        var (okGrp, errGrp) = SecurityValidator.ValidateGroupName(groupName, allowDefaultSftpUsersGroup: true);
        if (!okGrp)
        {
            _logger.LogWarning("Invalid group name {Group}: {Error}", groupName, errGrp);
            return false;
        }

        try
        {
            var check = RunProcess("net.exe", new[] { "localgroup", groupName });
            if (check.ExitCode == 0)
            {
                return true; // Group already exists
            }

            var args = new List<string> { "localgroup", groupName, "/add" };
            if (!string.IsNullOrWhiteSpace(comment))
            {
                args.Add($"/comment:{SecurityValidator.SanitizeSingleLine(comment)}");
            }

            var create = RunProcess("net.exe", args);
            return create.ExitCode == 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to ensure local group {Group}", groupName);
            return false;
        }
    }

    public bool DeleteLocalGroup(string groupName)
    {
        var (okGrp, _) = SecurityValidator.ValidateGroupName(groupName);
        if (!okGrp) return false;

        try
        {
            // Do not delete the default SFTP-Users group
            if (string.Equals(groupName, "SFTP-Users", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            var res = RunProcess("net.exe", new[] { "localgroup", groupName, "/delete" });
            return res.ExitCode == 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete local group {Group}", groupName);
            return false;
        }
    }

    public bool AddUserToLocalGroup(string groupName, string username)
    {
        var (okGrp, _) = SecurityValidator.ValidateGroupName(groupName, allowDefaultSftpUsersGroup: true);
        var (okUser, _) = SecurityValidator.ValidateUsername(username);
        if (!okGrp || !okUser) return false;

        try
        {
            // Fast path: attempt adding directly first to avoid redundant net.exe process spawn when group already exists
            var res = RunProcess("net.exe", new[] { "localgroup", groupName, username, "/add" });
            if (res.ExitCode == 0 || (res.ExitCode == 2 && res.StandardError.Contains("1378", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            // Group might not exist yet: ensure group and retry
            if (!EnsureLocalGroup(groupName))
            {
                return false;
            }

            res = RunProcess("net.exe", new[] { "localgroup", groupName, username, "/add" });
            // Return true if exit code is 0 or member already exists (1378)
            return res.ExitCode == 0 || res.ExitCode == 2;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to add user {User} to local group {Group}", username, groupName);
            return false;
        }
    }

    public bool RemoveUserFromLocalGroup(string groupName, string username)
    {
        var (okGrp, _) = SecurityValidator.ValidateGroupName(groupName, allowDefaultSftpUsersGroup: true);
        var (okUser, _) = SecurityValidator.ValidateUsername(username);
        if (!okGrp || !okUser) return false;

        try
        {
            var res = RunProcess("net.exe", new[] { "localgroup", groupName, username, "/delete" });
            return res.ExitCode == 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to remove user {User} from local group {Group}", username, groupName);
            return false;
        }
    }

    public List<string> GetGroupMembers(string groupName)
    {
        var members = new List<string>();
        var (okGrp, _) = SecurityValidator.ValidateGroupName(groupName, allowDefaultSftpUsersGroup: true);
        if (!okGrp) return members;

        try
        {
            var res = RunProcess("net.exe", new[] { "localgroup", groupName });
            if (res.ExitCode != 0) return members;

            var lines = res.StandardOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            bool pastHeader = false;
            foreach (var line in lines)
            {
                if (line.StartsWith("---"))
                {
                    pastHeader = true;
                    continue;
                }
                if (pastHeader)
                {
                    if (line.StartsWith("The command completed", StringComparison.OrdinalIgnoreCase))
                        break;

                    var trimmed = line.Trim();
                    if (!string.IsNullOrEmpty(trimmed))
                    {
                        members.Add(trimmed);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not list members for group {Group}", groupName);
        }
        return members;
    }

    public bool CreateOrUpdateLocalUser(string username, string password, bool isActive = true)
    {
        var (okUser, errUser) = SecurityValidator.ValidateUsername(username);
        if (!okUser)
        {
            _logger.LogError("Invalid username {Username}: {Error}", username, errUser);
            return false;
        }

        try
        {
            // 1. Check if user exists
            var check = RunProcess("net.exe", new[] { "user", username });
            bool userExists = check.ExitCode == 0;

            if (!userExists)
            {
                var (okPass, errPass) = SecurityValidator.ValidateWindowsPassword(password);
                if (!okPass)
                {
                    _logger.LogError("Invalid password for new Windows user {Username}: {Error}", username, errPass);
                    return false;
                }

                var createArgs = new List<string>
                {
                    "user",
                    username,
                    password,
                    "/add",
                    $"/active:{(isActive ? "yes" : "no")}",
                    "/comment:SFTP User"
                };

                var create = RunProcess("net.exe", createArgs);
                if (create.ExitCode != 0)
                {
                    _logger.LogError("Error creating Windows user {Username}: {Error}", username, create.StandardError);
                    return false;
                }
            }
            else
            {
                var updateArgs = new List<string> { "user", username };
                if (!string.IsNullOrEmpty(password))
                {
                    var (okPass, errPass) = SecurityValidator.ValidateWindowsPassword(password);
                    if (!okPass)
                    {
                        _logger.LogError("Invalid password update for Windows user {Username}: {Error}", username, errPass);
                        return false;
                    }
                    updateArgs.Add(password);
                }
                updateArgs.Add($"/active:{(isActive ? "yes" : "no")}");

                var update = RunProcess("net.exe", updateArgs);
                if (update.ExitCode != 0)
                {
                    _logger.LogError("Error updating Windows user {Username}: {Error}", username, update.StandardError);
                    return false;
                }
            }

            // 2. Add user to SFTP-Users group (AddUserToLocalGroup already ensures the group)
            AddUserToLocalGroup("SFTP-Users", username);

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to manage local user {Username}", username);
            return false;
        }
    }

    public bool DeleteLocalUser(string username)
    {
        var (okUser, _) = SecurityValidator.ValidateUsername(username);
        if (!okUser) return false;

        try
        {
            var res = RunProcess("net.exe", new[] { "user", username, "/delete" });
            return res.ExitCode == 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete local user {Username}", username);
            return false;
        }
    }
}
