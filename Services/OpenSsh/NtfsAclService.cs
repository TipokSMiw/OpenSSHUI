using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using OpensshUI.Models;
using OpensshUI.Services.Security;

namespace OpensshUI.Services.OpenSsh;

[SupportedOSPlatform("windows")]
public class NtfsAclService : INtfsAclService, INativeAclProvisioner
{
    private const int MaxResolvedAccountCacheSize = 500;
    private readonly ILogger<NtfsAclService> _logger;
    private readonly ConcurrentDictionary<string, NTAccount> _resolvedAccountCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _keysFileLock = new();

    public NtfsAclService(ILogger<NtfsAclService> logger)
    {
        _logger = logger;
    }

    public int ResolvedAccountCacheCount => _resolvedAccountCache.Count;

    private NTAccount? TryResolveAccount(string accountName)
    {
        if (string.IsNullOrWhiteSpace(accountName)) return null;
        var key = accountName.Trim();

        if (_resolvedAccountCache.TryGetValue(key, out var cached))
        {
            return cached;
        }

        try
        {
            var acc = new NTAccount(key);
            _ = acc.Translate(typeof(SecurityIdentifier));
            CacheResolvedAccount(key, acc);
            return acc;
        }
        catch (IdentityNotMappedException)
        {
            var domain = Environment.UserDomainName;
            if (!string.IsNullOrWhiteSpace(domain) && !key.Contains('\\'))
            {
                try
                {
                    var acc = new NTAccount(domain, key);
                    _ = acc.Translate(typeof(SecurityIdentifier));
                    CacheResolvedAccount(key, acc);
                    return acc;
                }
                catch (IdentityNotMappedException) { }
            }
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Unexpected error translating NTAccount for {Account}", accountName);
            return null;
        }
    }

    private void CacheResolvedAccount(string key, NTAccount account)
    {
        if (_resolvedAccountCache.Count >= MaxResolvedAccountCacheSize)
        {
            _resolvedAccountCache.Clear();
        }
        _resolvedAccountCache[key] = account;
    }

    public (bool IsSafe, string? ErrorMessage) ValidateResolvedPathSafety(string path, string? sftpRootPath = null)
    {
        var (isSafe, err) = SecurityValidator.ValidateSafeCustomPath(path, sftpRootPath);
        if (!isSafe)
        {
            return (false, err);
        }

        try
        {
            var fullPath = Path.GetFullPath(path.Trim()).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var root = Path.GetPathRoot(fullPath)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var current = new DirectoryInfo(fullPath);

            while (current != null &&
                   !string.Equals(current.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), root, StringComparison.OrdinalIgnoreCase))
            {
                if (current.Exists && current.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    var resolved = current.ResolveLinkTarget(returnFinalTarget: true);
                    if (resolved == null)
                    {
                        return (false, $"Unresolvable symbolic link or junction detected at '{current.FullName}'.");
                    }

                    var (isTargetSafe, targetErr) = SecurityValidator.ValidateSafeCustomPath(resolved.FullName, sftpRootPath);
                    if (!isTargetSafe)
                    {
                        return (false, $"Symbolic link or junction at '{current.FullName}' resolves to restricted path: {targetErr}");
                    }
                }

                current = current.Parent;
            }

            return (true, null);
        }
        catch (Exception ex)
        {
            return (false, $"Invalid path resolution: {ex.Message}");
        }
    }

    public void SecureAppDataDirectory(string appDataPath)
    {
        if (string.IsNullOrWhiteSpace(appDataPath)) return;

        try
        {
            var fullAppData = Path.GetFullPath(appDataPath.Trim());
            Directory.CreateDirectory(fullAppData);

            var dirInfo = new DirectoryInfo(fullAppData);
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

            security.AddAccessRule(new FileSystemAccessRule(
                adminSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            security.AddAccessRule(new FileSystemAccessRule(
                systemSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            var currentIdentitySid = WindowsIdentity.GetCurrent().User;
            if (currentIdentitySid != null && currentIdentitySid != adminSid && currentIdentitySid != systemSid)
            {
                security.AddAccessRule(new FileSystemAccessRule(
                    currentIdentitySid,
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));
            }

            dirInfo.SetAccessControl(security);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not lock down NTFS ACL on application data directory {Path}. Ensure the process runs with Administrator privileges in production.", appDataPath);
        }
    }

    /// <summary>
    /// Configures the root of an OpenSSH Chroot jail with strict Windows OpenSSH security rules:
    /// 1. Ownership: Must be BUILTIN\Administrators or NT AUTHORITY\SYSTEM.
    /// 2. Inheritance: Must be protected (broken) to prevent inherited write ACEs from parent drives.
    /// 3. Permissions: SYSTEM and Administrators have Full Control.
    /// 4. SFTP User/Group has Read &amp; Execute only (NO write/modify permissions at root).
    /// </summary>
    public void ProvisionChrootRoot(string chrootRootPath, string? accountName = null)
    {
        if (string.IsNullOrWhiteSpace(chrootRootPath))
            throw new ArgumentException("Chroot root path cannot be empty.", nameof(chrootRootPath));

        var (isSafePath, pathErr) = ValidateResolvedPathSafety(chrootRootPath);
        if (!isSafePath)
        {
            throw new SecurityException($"Unsafe chroot root path: {pathErr}");
        }

        var canonicalRoot = Path.GetFullPath(chrootRootPath);
        if (!Directory.Exists(canonicalRoot))
        {
            Directory.CreateDirectory(canonicalRoot);
        }

        try
        {
            var dirInfo = new DirectoryInfo(canonicalRoot);
            var security = dirInfo.GetAccessControl();

            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

            // 1. Break inheritance from parent drives (e.g. D:\ or C:\) and strip all inherited ACEs
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            // Remove any prior explicit write/modify/ownership ACEs granted to non-Admin / non-SYSTEM principals
            const FileSystemRights writeRightsMask =
                FileSystemRights.Write | FileSystemRights.Modify | FileSystemRights.FullControl |
                FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership |
                FileSystemRights.WriteData | FileSystemRights.AppendData |
                FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes |
                FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles;

            var existingRules = security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier));
            foreach (AuthorizationRule rule in existingRules)
            {
                if (rule is FileSystemAccessRule fsRule &&
                    fsRule.AccessControlType == AccessControlType.Allow &&
                    fsRule.IdentityReference is SecurityIdentifier sid &&
                    sid != adminSid && sid != systemSid &&
                    (fsRule.FileSystemRights & writeRightsMask) != 0)
                {
                    security.RemoveAccessRuleSpecific(fsRule);
                }
            }

            // 2. Grant Full Control to Administrators and SYSTEM
            security.AddAccessRule(new FileSystemAccessRule(
                adminSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            security.AddAccessRule(new FileSystemAccessRule(
                systemSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            // 3. Ensure host process identity has Read & Execute (r-x, NO Write) to traverse into /files
            // OpenSSH permits 0755 (rwxr-xr-x) on ChrootDirectory root as long as non-admins have NO Write bit
            var currentIdentitySid = WindowsIdentity.GetCurrent().User;
            if (currentIdentitySid != null && currentIdentitySid != adminSid && currentIdentitySid != systemSid)
            {
                security.AddAccessRule(new FileSystemAccessRule(
                    currentIdentitySid,
                    FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory,
                    InheritanceFlags.None,
                    PropagationFlags.None,
                    AccessControlType.Allow));
            }

            // 4. Grant user/group Read-Only access (NO Write / Modify on chroot root)
            if (!string.IsNullOrWhiteSpace(accountName))
            {
                var userAccount = TryResolveAccount(accountName);
                if (userAccount != null)
                {
                    // Purge any prior explicit rules (e.g. if switched from VirtualFolder ReadWrite to DirectChroot)
                    security.PurgeAccessRules(userAccount);

                    security.AddAccessRule(new FileSystemAccessRule(
                        userAccount,
                        FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory,
                        InheritanceFlags.None, // Non-inheriting to root only
                        PropagationFlags.None,
                        AccessControlType.Allow));
                }
                else
                {
                    _logger.LogWarning("Account {Account} could not be resolved for chroot root {Path}", accountName, canonicalRoot);
                }
            }

            // Persist DACL rules
            dirInfo.SetAccessControl(security);

            // 4. Strict Ownership Assignment (BUILTIN\Administrators)
            // Note: Assigning owner different from caller requires SeRestorePrivilege / Administrator privileges
            try
            {
                var ownerSecurity = new DirectorySecurity();
                ownerSecurity.SetOwner(adminSid);
                dirInfo.SetAccessControl(ownerSecurity);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not explicitly set owner to BUILTIN\\Administrators on chroot root {Path}. Host environment may require elevated SeRestorePrivilege.", canonicalRoot);
            }

            _logger.LogInformation("Successfully applied strict chroot root ACLs on {Path}", canonicalRoot);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to apply strict chroot root ACLs on {Path}", canonicalRoot);
            throw;
        }
    }

    /// <summary>
    /// Configures an accessible subdirectory inside the chroot (e.g. /files, /data, /uploads)
    /// where the SFTP user is granted Modify or FullControl rights.
    /// </summary>
    public void ProvisionSubdirectory(string subDirPath, string accountName, SftpPermissionType permission)
    {
        if (string.IsNullOrWhiteSpace(subDirPath))
            throw new ArgumentException("Subdirectory path cannot be empty.", nameof(subDirPath));

        var canonicalSubDir = Path.GetFullPath(subDirPath);
        if (!Directory.Exists(canonicalSubDir))
        {
            Directory.CreateDirectory(canonicalSubDir);
        }

        try
        {
            var dirInfo = new DirectoryInfo(canonicalSubDir);
            var security = dirInfo.GetAccessControl();

            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

            security.AddAccessRule(new FileSystemAccessRule(
                adminSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            security.AddAccessRule(new FileSystemAccessRule(
                systemSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            var userAccount = TryResolveAccount(accountName);
            if (userAccount != null)
            {
                // Purge previous rules for this account to apply fresh permissions cleanly
                security.PurgeAccessRules(userAccount);

                FileSystemRights rights = permission == SftpPermissionType.ReadWrite
                    ? FileSystemRights.Modify | FileSystemRights.DeleteSubdirectoriesAndFiles
                    : FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory;

                security.AddAccessRule(new FileSystemAccessRule(
                    userAccount,
                    rights,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                dirInfo.SetAccessControl(security);
                _logger.LogInformation("Successfully provisioned subdirectory ACLs ({Rights}) for {Account} at {Path}", rights, accountName, canonicalSubDir);
            }
            else
            {
                dirInfo.SetAccessControl(security);
                _logger.LogWarning("Account {Account} could not be resolved to a Windows SID. User-specific ACL skipped on subdirectory {Path}; secured for SYSTEM/Administrators.", accountName, canonicalSubDir);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to provision subdirectory ACLs at {Path} for {Account}", canonicalSubDir, accountName);
            throw;
        }
    }

    /// <summary>
    /// Full Chroot provisioning for a standard user:
    /// 1. Root ({baseRoot}\{username}) - Owned by Administrators, Protected Inheritance, Read-Only for user.
    /// 2. Subfolder ({baseRoot}\{username}\files) - Writable (Modify) by user.
    /// </summary>
    public void ProvisionUserChroot(string baseRootPath, string username)
    {
        var (okUser, errUser) = SecurityValidator.ValidateUsername(username);
        if (!okUser)
        {
            throw new SecurityException($"Invalid username for chroot provisioning: {errUser}");
        }

        var normalizedBase = Path.GetFullPath(baseRootPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var userRoot = Path.GetFullPath(Path.Combine(normalizedBase, username.Trim()));
        if (!userRoot.StartsWith(normalizedBase + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityException("Path traversal detected in ProvisionUserChroot.");
        }

        var userFilesDir = Path.Combine(userRoot, "files");

        Directory.CreateDirectory(userRoot);
        Directory.CreateDirectory(userFilesDir);

        // 1. Provision Writable /files subdirectory FIRST before locking down parent chroot root
        ProvisionSubdirectory(userFilesDir, username, SftpPermissionType.ReadWrite);

        // 2. Provision Root with strict OpenSSH Ownership & Protected Inheritance
        ProvisionChrootRoot(userRoot, username);

        _logger.LogInformation("Fully provisioned strict user chroot jail for {Username} at {Path}", username, userRoot);
    }

    /// <summary>
    /// Provisions NTFS ACLs for custom paths or group shares.
    /// If isDirectChroot is true, applies OpenSSH ownership rules and protected inheritance.
    /// </summary>
    public void ProvisionPathAcl(string folderPath, string accountName, SftpPermissionType permission, bool isDirectChroot = false)
    {
        var (isSafePath, pathErr) = ValidateResolvedPathSafety(folderPath);
        if (!isSafePath)
        {
            throw new SecurityException($"Unsafe target path '{folderPath}': {pathErr}");
        }

        var canonicalPath = Path.GetFullPath(folderPath);
        if (!Directory.Exists(canonicalPath))
        {
            Directory.CreateDirectory(canonicalPath);
        }

        try
        {
            if (isDirectChroot)
            {
                // Ensure and configure subfolder 'files' FIRST before locking down parent chroot root
                var subFiles = Path.Combine(canonicalPath, "files");
                Directory.CreateDirectory(subFiles);
                ProvisionSubdirectory(subFiles, accountName, permission);

                // Root must strictly follow OpenSSH Chroot rules
                ProvisionChrootRoot(canonicalPath, accountName);
            }
            else
            {
                var dirInfo = new DirectoryInfo(canonicalPath);
                var security = dirInfo.GetAccessControl();

                var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                var targetAccount = TryResolveAccount(accountName);

                security.AddAccessRule(new FileSystemAccessRule(
                    adminSid,
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                security.AddAccessRule(new FileSystemAccessRule(
                    systemSid,
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                if (targetAccount != null)
                {
                    security.PurgeAccessRules(targetAccount);

                    FileSystemRights rights = permission == SftpPermissionType.ReadWrite
                        ? FileSystemRights.Modify | FileSystemRights.DeleteSubdirectoriesAndFiles
                        : FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory;

                    security.AddAccessRule(new FileSystemAccessRule(
                        targetAccount,
                        rights,
                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                        PropagationFlags.None,
                        AccessControlType.Allow));

                    dirInfo.SetAccessControl(security);
                    _logger.LogInformation("Applied shared folder NTFS ACL ({Rights}) on {Path} for {Account}", rights, canonicalPath, accountName);
                }
                else
                {
                    dirInfo.SetAccessControl(security);
                    _logger.LogWarning("Account {Account} could not be resolved on {Path}; folder secured for SYSTEM/Administrators.", accountName, canonicalPath);
                }
            }
        }
        catch (SecurityException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not set ACL on {Path} for {Account}", folderPath, accountName);
        }
    }

    public void RemovePathAcl(string folderPath, string accountName)
    {
        if (!Directory.Exists(folderPath)) return;

        try
        {
            var targetAccount = TryResolveAccount(accountName);
            if (targetAccount == null) return;

            var dirInfo = new DirectoryInfo(folderPath);
            var security = dirInfo.GetAccessControl();

            security.PurgeAccessRules(targetAccount);
            dirInfo.SetAccessControl(security);
            _logger.LogInformation("Purged ACLs on {Path} for {Account}", folderPath, accountName);

            var subFilesPath = Path.Combine(folderPath, "files");
            if (Directory.Exists(subFilesPath))
            {
                var subInfo = new DirectoryInfo(subFilesPath);
                if (!subInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    var subSecurity = subInfo.GetAccessControl();
                    subSecurity.PurgeAccessRules(targetAccount);
                    subInfo.SetAccessControl(subSecurity);
                    _logger.LogInformation("Purged ACLs on DirectChroot subdirectory {Path} for {Account}", subFilesPath, accountName);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not remove ACL on {Path} for {Account}", folderPath, accountName);
        }
    }

    /// <summary>
    /// Validates that a requested path strictly resides within the base path and does not escape via '..' or junction.
    /// </summary>
    public bool ValidatePathSafety(string basePath, string relativeOrSubPath)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(basePath) || string.IsNullOrWhiteSpace(relativeOrSubPath))
                return false;

            var trimmedSub = relativeOrSubPath.Trim();
            if (trimmedSub.Contains('~'))
                return false;

            if (Path.IsPathRooted(trimmedSub) ? trimmedSub.IndexOf(':', 2) >= 0 : trimmedSub.Contains(':'))
                return false;

            var fullBase = Path.GetFullPath(basePath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string fullTarget;

            if (Path.IsPathRooted(trimmedSub))
            {
                // Absolute path: must directly reside inside fullBase
                fullTarget = Path.GetFullPath(trimmedSub).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            }
            else
            {
                fullTarget = Path.GetFullPath(Path.Combine(fullBase, trimmedSub)).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            }

            bool withinBase = fullTarget.Equals(fullBase, StringComparison.OrdinalIgnoreCase) ||
                              fullTarget.StartsWith(fullBase + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
            if (!withinBase)
            {
                return false;
            }

            // ReparsePoint / Junction escape check across segments inside fullBase
            var checkDir = new DirectoryInfo(fullTarget);
            while (checkDir != null &&
                   !checkDir.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Equals(fullBase, StringComparison.OrdinalIgnoreCase) &&
                   checkDir.FullName.StartsWith(fullBase + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                if (checkDir.Exists && checkDir.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    var resolved = checkDir.ResolveLinkTarget(returnFinalTarget: true);
                    if (resolved == null) return false;

                    var resolvedFull = Path.GetFullPath(resolved.FullName).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                    if (!resolvedFull.Equals(fullBase, StringComparison.OrdinalIgnoreCase) &&
                        !resolvedFull.StartsWith(fullBase + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }
                }
                checkDir = checkDir.Parent;
            }

            var targetFile = new FileInfo(fullTarget);
            if (targetFile.Exists && targetFile.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                var resolvedFile = targetFile.ResolveLinkTarget(returnFinalTarget: true);
                if (resolvedFile == null) return false;

                var resolvedFull = Path.GetFullPath(resolvedFile.FullName).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                if (!resolvedFull.Equals(fullBase, StringComparison.OrdinalIgnoreCase) &&
                    !resolvedFull.StartsWith(fullBase + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Creates an NTFS Directory Junction from linkPath to targetPath with strict traversal guards.
    /// </summary>
    public bool CreateDirectoryJunction(string linkPath, string targetPath)
    {
        var (okLink, errLink) = ValidateResolvedPathSafety(linkPath);
        var (okTarget, errTarget) = ValidateResolvedPathSafety(targetPath);
        if (!okLink || !okTarget)
        {
            _logger.LogWarning("Rejected unsafe directory junction from {Link} ({ErrLink}) to {Target} ({ErrTarget})", linkPath, errLink, targetPath, errTarget);
            return false;
        }

        try
        {
            var canonicalTarget = Path.GetFullPath(targetPath);
            var canonicalLink = Path.GetFullPath(linkPath);

            if (!Directory.Exists(canonicalTarget))
            {
                Directory.CreateDirectory(canonicalTarget);
            }

            if (Directory.Exists(canonicalLink))
            {
                var dirInfo = new DirectoryInfo(canonicalLink);
                if (dirInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    // Idempotent check: if the junction already points to the exact target directory, skip deleting & re-spawning mklink
                    try
                    {
                        var existingTarget = dirInfo.ResolveLinkTarget(returnFinalTarget: false);
                        if (existingTarget != null)
                        {
                            var normalizedExisting = Path.GetFullPath(existingTarget.FullName).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                            var normalizedDesired = canonicalTarget.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                            if (string.Equals(normalizedExisting, normalizedDesired, StringComparison.OrdinalIgnoreCase))
                            {
                                return true;
                            }
                        }
                    }
                    catch { }

                    Directory.Delete(canonicalLink);
                }
                else
                {
                    _logger.LogWarning("Target link path already exists as regular directory; junction aborted: {Path}", canonicalLink);
                    return false;
                }
            }

            var parent = Path.GetDirectoryName(canonicalLink);
            if (!string.IsNullOrEmpty(parent) && !Directory.Exists(parent))
            {
                Directory.CreateDirectory(parent);
            }

            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            psi.ArgumentList.Add("/c");
            psi.ArgumentList.Add("mklink");
            psi.ArgumentList.Add("/J");
            psi.ArgumentList.Add(canonicalLink);
            psi.ArgumentList.Add(canonicalTarget);

            using var proc = new Process { StartInfo = psi };
            proc.Start();
            var outTask = proc.StandardOutput.ReadToEndAsync();
            var errTask = proc.StandardError.ReadToEndAsync();
            bool finished = proc.WaitForExit(5000);
            if (!finished)
            {
                try { proc.Kill(true); } catch { }
                _logger.LogWarning("mklink timed out creating junction from {Link} to {Target}", canonicalLink, canonicalTarget);
                return false;
            }
            Task.WaitAll(new[] { outTask, errTask }, TimeSpan.FromMilliseconds(500));
            if (proc.ExitCode != 0)
            {
                _logger.LogError("mklink failed ({Code}): {Error}", proc.ExitCode, errTask.Result);
            }
            return proc.ExitCode == 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create directory junction from {Link} to {Target}", linkPath, targetPath);
            return false;
        }
    }

    public bool RemoveDirectoryJunction(string linkPath)
    {
        try
        {
            if (!Directory.Exists(linkPath)) return true;

            var dirInfo = new DirectoryInfo(linkPath);
            if (dirInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                Directory.Delete(linkPath);
                _logger.LogInformation("Removed directory junction {LinkPath}", linkPath);
                return true;
            }
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to remove directory junction {LinkPath}", linkPath);
            return false;
        }
    }

    public List<DriveFolderItem> ListAvailableDrives()
    {
        var items = new List<DriveFolderItem>();
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                try
                {
                    if (drive.IsReady && (drive.DriveType == DriveType.Fixed || drive.DriveType == DriveType.Removable))
                    {
                        var label = string.IsNullOrWhiteSpace(drive.VolumeLabel) ? "Local Disk" : drive.VolumeLabel;
                        items.Add(new DriveFolderItem
                        {
                            Name = $"{drive.Name.TrimEnd('\\')} ({label})",
                            FullPath = drive.RootDirectory.FullName,
                            IsDrive = true,
                            TotalSize = drive.TotalSize,
                            FreeSpace = drive.AvailableFreeSpace
                        });
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error enumerating system drives.");
        }
        return items;
    }

    public List<DriveFolderItem> ListDirectories(string parentPath)
    {
        var items = new List<DriveFolderItem>();
        try
        {
            if (string.IsNullOrWhiteSpace(parentPath) || !Directory.Exists(parentPath))
            {
                return items;
            }

            var fullParent = Path.GetFullPath(parentPath.Trim());
            var root = Path.GetPathRoot(fullParent);
            bool isDriveRoot = string.Equals(fullParent.TrimEnd('\\', '/'), root?.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase);

            if (!isDriveRoot)
            {
                var (isSafeParent, _) = ValidateResolvedPathSafety(fullParent);
                if (!isSafeParent)
                {
                    return items;
                }
            }

            var dir = new DirectoryInfo(fullParent);
            var enumOptions = new EnumerationOptions
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = false,
                AttributesToSkip = FileAttributes.Hidden | FileAttributes.System
            };

            foreach (var sub in dir.EnumerateDirectories("*", enumOptions))
            {
                var (isSafeSub, _) = ValidateResolvedPathSafety(sub.FullName);
                if (!isSafeSub)
                {
                    continue;
                }

                items.Add(new DriveFolderItem
                {
                    Name = sub.Name,
                    FullPath = sub.FullName,
                    IsDrive = false
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error listing directories in {Path}", parentPath);
        }
        return items.OrderBy(x => x.Name).ToList();
    }

    public bool DirectoryExists(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;

        var trimmed = path.Trim();
        // Block UNC and Win32 device paths before OS probe to prevent outbound NTLM credential leaks
        if (trimmed.StartsWith(@"\\") || trimmed.StartsWith("//"))
        {
            return false;
        }

        try { return Directory.Exists(trimmed); } catch { return false; }
    }

    public bool CreateDirectory(string fullPath)
    {
        var (isSafe, err) = ValidateResolvedPathSafety(fullPath);
        if (!isSafe)
        {
            _logger.LogWarning("Rejected directory creation at unsafe path {Path}: {Error}", fullPath, err);
            return false;
        }

        try
        {
            if (!Directory.Exists(fullPath))
            {
                Directory.CreateDirectory(fullPath);
            }
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating directory {Path}", fullPath);
            return false;
        }
    }

    public string? GetParentDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        try
        {
            var parent = Directory.GetParent(path);
            return parent?.FullName;
        }
        catch { return null; }
    }

    public List<BreadcrumbItem> GetDirectoryBreadcrumbs(string path)
    {
        var breadcrumbs = new List<BreadcrumbItem>();
        if (string.IsNullOrWhiteSpace(path)) return breadcrumbs;

        try
        {
            var dir = new DirectoryInfo(path);
            var stack = new Stack<DirectoryInfo>();

            var curr = dir;
            while (curr != null)
            {
                stack.Push(curr);
                curr = curr.Parent;
            }

            while (stack.Count > 0)
            {
                var item = stack.Pop();
                breadcrumbs.Add(new BreadcrumbItem
                {
                    Name = string.IsNullOrEmpty(item.Parent?.FullName) ? item.FullName : item.Name,
                    Path = item.FullName,
                    IsLast = stack.Count == 0
                });
            }
        }
        catch { }

        return breadcrumbs;
    }

    public void EnsureKeysDirectory(string keysPath)
    {
        Directory.CreateDirectory(keysPath);
        try
        {
            var dirInfo = new DirectoryInfo(keysPath);
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

            try
            {
                security.SetOwner(adminSid);
            }
            catch { }

            security.AddAccessRule(new FileSystemAccessRule(
                adminSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            security.AddAccessRule(new FileSystemAccessRule(
                systemSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            dirInfo.SetAccessControl(security);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not set ACL on keys directory {Path}. May require Administrator rights.", keysPath);
        }
    }

    public void WriteUserKeysFile(string keysPath, string username, IEnumerable<string> openSshPublicKeys)
    {
        var (okUser, errUser) = SecurityValidator.ValidateUsername(username);
        if (!okUser)
        {
            throw new SecurityException($"Invalid username for SSH key file: {errUser}");
        }

        lock (_keysFileLock)
        {
            EnsureKeysDirectory(keysPath);
            var normalizedKeysDir = Path.GetFullPath(keysPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var keyFilePath = Path.GetFullPath(Path.Combine(normalizedKeysDir, username.Trim()));
            if (!keyFilePath.StartsWith(normalizedKeysDir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                throw new SecurityException("Path traversal detected in WriteUserKeysFile.");
            }

            var keysList = openSshPublicKeys.Select(SecurityValidator.SanitizeSingleLine).Where(k => !string.IsNullOrWhiteSpace(k)).ToList();
            if (keysList.Count == 0)
            {
                if (File.Exists(keyFilePath))
                {
                    File.Delete(keyFilePath);
                }
                return;
            }

            var content = string.Join("\n", keysList) + "\n";
            var tempKeyFile = $"{keyFilePath}.tmp_{Guid.NewGuid():N}";
            try
            {
                File.WriteAllText(tempKeyFile, content);

                try
                {
                    var fileInfo = new FileInfo(tempKeyFile);
                    var security = new FileSecurity();
                    security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

                    var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                    var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

                    try { security.SetOwner(adminSid); } catch { }

                    security.AddAccessRule(new FileSystemAccessRule(adminSid, FileSystemRights.FullControl, AccessControlType.Allow));
                    security.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, AccessControlType.Allow));

                    fileInfo.SetAccessControl(security);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not set ACL on key file {Path}", keyFilePath);
                }

                File.Move(tempKeyFile, keyFilePath, overwrite: true);
            }
            finally
            {
                try
                {
                    if (File.Exists(tempKeyFile)) File.Delete(tempKeyFile);
                }
                catch { }
            }
        }
    }
}
