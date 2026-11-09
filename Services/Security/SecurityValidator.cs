using System.Text.RegularExpressions;

namespace OpensshUI.Services.Security;

public static class SecurityValidator
{
    private static readonly Regex SafeUsernameRegex = new(@"^[a-zA-Z0-9_\-\.]{1,32}$", RegexOptions.Compiled);
    private static readonly Regex SafeGroupNameRegex = new(@"^[a-zA-Z0-9_\-\. ]{1,32}$", RegexOptions.Compiled);
    private static readonly Regex LocalDrivePathRegex = new(@"^[a-zA-Z]:[\\/]", RegexOptions.Compiled);
    private static readonly Regex ControlCharsRegex = new(@"[\r\n\t\x00-\x1F\x7F]", RegexOptions.Compiled);
    private static readonly char[] DangerousPathChars = { ';', '&', '|', '`', '$', '>', '<', '^', '%', '"', '\r', '\n', '\0' };

    private static readonly HashSet<string> ReservedWindowsNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    private static readonly HashSet<string> ProtectedWindowsAccounts = new(StringComparer.OrdinalIgnoreCase)
    {
        "Administrator", "Admin", "Guest", "DefaultAccount", "WDAGUtilityAccount",
        "SYSTEM", "LocalService", "NetworkService", "krbtgt", "sshd", "SFTP-Users"
    };

    private static readonly HashSet<string> ProtectedWindowsGroups = new(StringComparer.OrdinalIgnoreCase)
    {
        "SFTP-Users", "SFTP-Administrators", "Administrators", "Users", "Guests",
        "Backup Operators", "Remote Desktop Users", "Power Users", "System",
        "Authenticated Users", "Network Configuration Operators", "Hyper-V Administrators"
    };

    /// <summary>
    /// Validates username according to Windows OS and OpenSSH rules.
    /// Rejects dangerous characters, switch prefixes ('/' or '-'), DOS device names, and built-in OS accounts.
    /// </summary>
    public static (bool IsValid, string? ErrorMessage) ValidateUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return (false, "Username is required.");
        }

        var trimmed = username.Trim();

        // Reject flag/switch prefixes that could trick CLI tools like net.exe
        if (trimmed.StartsWith('/') || trimmed.StartsWith('-') || trimmed.StartsWith('.'))
        {
            return (false, "Username cannot start with '/', '-', or '.'.");
        }

        if (trimmed.Length < 1 || trimmed.Length > 32)
        {
            return (false, "Username length must be between 1 and 32 characters.");
        }

        if (!SafeUsernameRegex.IsMatch(trimmed))
        {
            return (false, "Username contains invalid characters. Only alphanumeric, underscore, hyphen, and period are permitted.");
        }

        if (ReservedWindowsNames.Contains(trimmed))
        {
            return (false, $"'{trimmed}' is a reserved Windows system device name.");
        }

        if (ProtectedWindowsAccounts.Contains(trimmed))
        {
            return (false, $"'{trimmed}' is a protected Windows system account and cannot be managed as an SFTP user.");
        }

        // Prevent path traversal sequences
        if (trimmed.Contains("..") || trimmed.Contains('/') || trimmed.Contains('\\'))
        {
            return (false, "Username cannot contain directory navigation characters.");
        }

        return (true, null);
    }

    /// <summary>
    /// Validates group name. Rejects dangerous shell characters (; & | ` $ > < / \) and protected OS groups.
    /// </summary>
    public static (bool IsValid, string? ErrorMessage) ValidateGroupName(string? groupName, bool allowDefaultSftpUsersGroup = false)
    {
        if (string.IsNullOrWhiteSpace(groupName))
        {
            return (false, "Group name is required.");
        }

        var trimmed = groupName.Trim();

        if (trimmed.StartsWith('/') || trimmed.StartsWith('-') || trimmed.StartsWith('.'))
        {
            return (false, "Group name cannot start with '/', '-', or '.'.");
        }

        if (trimmed.Length < 1 || trimmed.Length > 32)
        {
            return (false, "Group name length must be between 1 and 32 characters.");
        }

        if (!SafeGroupNameRegex.IsMatch(trimmed))
        {
            return (false, "Group name contains invalid characters. Only letters, numbers, spaces, underscores, hyphens, and periods are permitted.");
        }

        if (ReservedWindowsNames.Contains(trimmed))
        {
            return (false, $"'{trimmed}' is a reserved Windows system name.");
        }

        if (trimmed.Contains(".."))
        {
            return (false, "Group name cannot contain '..'.");
        }

        if (!allowDefaultSftpUsersGroup)
        {
            var normalizedOsName = trimmed.Replace(" ", "_");
            if (!normalizedOsName.StartsWith("SFTP-", StringComparison.OrdinalIgnoreCase))
            {
                normalizedOsName = $"SFTP-{normalizedOsName}";
            }

            if (ProtectedWindowsGroups.Contains(trimmed) || ProtectedWindowsGroups.Contains(normalizedOsName))
            {
                return (false, $"'{trimmed}' is a reserved or protected Windows system group.");
            }
        }

        return (true, null);
    }

    /// <summary>
    /// Validates a Windows local user password to prevent net.exe CLI switch injection (e.g. '/delete' or '-flag')
    /// and control character injection.
    /// </summary>
    public static (bool IsValid, string? ErrorMessage) ValidateWindowsPassword(string? password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            return (false, "Password cannot be empty.");
        }

        if (password.StartsWith('/') || password.StartsWith('-'))
        {
            return (false, "Password cannot start with '/' or '-' (reserved CLI switch prefix).");
        }

        if (password.Length < 4)
        {
            return (false, "Password must be at least 4 characters long.");
        }

        if (password.Length > 127)
        {
            return (false, "Password exceeds maximum length of 127 characters.");
        }

        if (password.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0)
        {
            return (false, "Password contains invalid control characters.");
        }

        return (true, null);
    }

    /// <summary>
    /// Validates a single folder or file item name (no path separators, '..', or reserved device names).
    /// </summary>
    public static (bool IsValid, string? ErrorMessage) ValidateFolderItemName(string? itemName)
    {
        if (string.IsNullOrWhiteSpace(itemName))
        {
            return (false, "Item name cannot be empty.");
        }

        var trimmed = itemName.Trim();
        if (trimmed == "." || trimmed == ".." || trimmed.Contains(".."))
        {
            return (false, "Item name cannot contain directory traversal sequences ('..').");
        }

        if (trimmed.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            trimmed.Contains('/') || trimmed.Contains('\\') || trimmed.Contains(':'))
        {
            return (false, "Item name contains invalid characters or path separators.");
        }

        if (trimmed.IndexOfAny(DangerousPathChars) >= 0)
        {
            return (false, "Item name contains dangerous shell characters.");
        }

        var nameWithoutExt = Path.GetFileNameWithoutExtension(trimmed);
        if (ReservedWindowsNames.Contains(trimmed) || ReservedWindowsNames.Contains(nameWithoutExt))
        {
            return (false, $"'{trimmed}' is a reserved Windows device name.");
        }

        return (true, null);
    }

    /// <summary>
    /// Validates that a path is safe and does not target critical Windows system directories, UNC shares, or app data.
    /// </summary>
    public static (bool IsSafe, string? ErrorMessage) ValidateSafeCustomPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return (false, "Path cannot be empty.");
        }

        var rawTrimmed = path.Trim();

        // Block UNC paths (\\server\share) and Win32 device paths (\\?\, \\.\)
        if (rawTrimmed.StartsWith(@"\\") || rawTrimmed.StartsWith("//") || !LocalDrivePathRegex.IsMatch(rawTrimmed))
        {
            return (false, "Only local drive paths (e.g. C:\\Folder or D:\\Share) are permitted. UNC and device paths are forbidden.");
        }

        // Block shell metacharacters & config injection characters
        if (rawTrimmed.IndexOfAny(DangerousPathChars) >= 0)
        {
            return (false, "Path contains forbidden special characters (; & | ` $ > < ^ % \").");
        }

        try
        {
            var fullPath = Path.GetFullPath(rawTrimmed);

            // Prevent targeting root drive directory directly (e.g. C:\ or D:\)
            var root = Path.GetPathRoot(fullPath);
            if (string.Equals(fullPath.TrimEnd('\\', '/'), root?.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase))
            {
                return (false, "Targeting an entire drive root as a shared folder is not permitted.");
            }

            // Block sensitive system and application directories
            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var progFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            var sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System);

            string[] forbiddenPrefixes = {
                winDir,
                progFiles,
                progFilesX86,
                sys32,
                @"C:\ProgramData\ssh",
                @"C:\ProgramData\Microsoft",
                @"C:\Windows",
                @"C:\Recovery",
                @"C:\System Volume Information",
                AppContext.BaseDirectory,
                Path.Combine(AppContext.BaseDirectory, "app_data"),
                Path.Combine(Directory.GetCurrentDirectory(), "app_data")
            };

            foreach (var forbidden in forbiddenPrefixes)
            {
                if (!string.IsNullOrEmpty(forbidden))
                {
                    var fullForbidden = Path.GetFullPath(forbidden).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                    var normalizedFull = fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                    if (normalizedFull.Equals(fullForbidden, StringComparison.OrdinalIgnoreCase) ||
                        normalizedFull.StartsWith(fullForbidden + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    {
                        return (false, $"Access to system or application directory '{forbidden}' is strictly forbidden.");
                    }
                }
            }

            return (true, null);
        }
        catch (Exception ex)
        {
            return (false, $"Invalid path: {ex.Message}");
        }
    }

    /// <summary>
    /// Escapes an input string according to RFC 4515 LDAP search filter requirements.
    /// Escapes: \ -> \5c, * -> \2a, ( -> \28, ) -> \29, \0 -> \00.
    /// </summary>
    public static string EscapeLdapFilter(string? input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;

        var sb = new System.Text.StringBuilder(input.Length);
        foreach (char c in input)
        {
            switch (c)
            {
                case '\\':
                    sb.Append(@"\5c");
                    break;
                case '*':
                    sb.Append(@"\2a");
                    break;
                case '(':
                    sb.Append(@"\28");
                    break;
                case ')':
                    sb.Append(@"\29");
                    break;
                case '\0':
                    sb.Append(@"\00");
                    break;
                default:
                    sb.Append(c);
                    break;
            }
        }
        return sb.ToString();
    }

    /// <summary>
    /// Strips carriage returns, line feeds, and control characters to prevent CRLF injection in config files.
    /// </summary>
    public static string SanitizeSingleLine(string? input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        return ControlCharsRegex.Replace(input, " ").Trim();
    }

    /// <summary>
    /// Validates an optional SSH key passphrase to ensure it does not contain control characters, quotes, or exceed safe limits.
    /// </summary>
    public static (bool IsValid, string? ErrorMessage) ValidateSshPassphrase(string? passphrase)
    {
        if (string.IsNullOrEmpty(passphrase))
        {
            return (true, null);
        }

        if (passphrase.Length > 128)
        {
            return (false, "Passphrase exceeds maximum length of 128 characters.");
        }

        if (passphrase.IndexOfAny(new[] { '\r', '\n', '\0', '"' }) >= 0 || passphrase.Any(char.IsControl))
        {
            return (false, "Passphrase contains invalid control characters or quotes.");
        }

        return (true, null);
    }

    /// <summary>
    /// Replaces invalid file name characters and traversal sequences with underscores so UI components do not need to call System.IO.Path directly.
    /// </summary>
    public static string SanitizeSafeFileName(string? rawFileName, string fallback = "download.dat")
    {
        if (string.IsNullOrWhiteSpace(rawFileName))
        {
            return fallback;
        }

        var clean = SanitizeSingleLine(rawFileName);
        foreach (var c in Path.GetInvalidFileNameChars())
        {
            clean = clean.Replace(c, '_');
        }

        clean = clean.Replace('/', '_').Replace('\\', '_').Replace(':', '_');
        while (clean.Contains(".."))
        {
            clean = clean.Replace("..", "_");
        }

        clean = clean.Trim().Trim('.');
        if (string.IsNullOrWhiteSpace(clean))
        {
            return fallback;
        }

        var nameWithoutExt = Path.GetFileNameWithoutExtension(clean);
        if (ReservedWindowsNames.Contains(clean) || ReservedWindowsNames.Contains(nameWithoutExt))
        {
            clean = "_" + clean;
        }

        return clean;
    }

    /// <summary>
    /// Validates LDAP server host and port to prevent SSRF and injection attacks.
    /// </summary>
    public static (bool IsValid, string? ErrorMessage) ValidateLdapHost(string? host, int port)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return (false, "กรุณาระบุ LDAP Server / Host (LDAP Server/Host cannot be empty).");
        }

        var trimmed = host.Trim();
        if (trimmed.Contains("://") || trimmed.Contains('/') || trimmed.Contains('\\'))
        {
            return (false, "LDAP Server/Host must be a hostname or IP address without URL scheme or path.");
        }

        if (trimmed.IndexOfAny(new[] { ' ', '\t', '\r', '\n', '\0', '?', '#', '@' }) >= 0)
        {
            return (false, "LDAP Server/Host contains invalid characters.");
        }

        if (port < 1 || port > 65535)
        {
            return (false, "พอร์ตต้องอยู่ระหว่าง 1 ถึง 65535 (Port must be between 1 and 65535).");
        }

        return (true, null);
    }
}
