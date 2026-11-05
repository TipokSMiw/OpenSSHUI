using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using OpensshUI.Models;
using OpensshUI.Services.Security;

namespace OpensshUI.Services.OpenSsh;

public class DriveFolderItem
{
    public string Name { get; set; } = string.Empty;
    public string FullPath { get; set; } = string.Empty;
    public bool IsDrive { get; set; }
    public long? TotalSize { get; set; }
    public long? FreeSpace { get; set; }
}

public class BreadcrumbItem
{
    public string Name { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public bool IsLast { get; set; }
}

[SupportedOSPlatform("windows")]
public class NativeAclProvisioner : INativeAclProvisioner
{
    private readonly ILogger<NativeAclProvisioner> _logger;

    public NativeAclProvisioner(ILogger<NativeAclProvisioner> logger)
    {
        _logger = logger;
    }

    private NTAccount? TryResolveAccount(string accountName)
    {
        try
        {
            var acc = new NTAccount(accountName);
            var sid = acc.Translate(typeof(SecurityIdentifier));
            return acc;
        }
        catch (IdentityNotMappedException)
        {
            var domain = Environment.UserDomainName;
            if (!string.IsNullOrWhiteSpace(domain) && !accountName.Contains('\\'))
            {
                try
                {
                    var acc = new NTAccount(domain, accountName);
                    var sid = acc.Translate(typeof(SecurityIdentifier));
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

    /// <summary>
    /// Provisions user directory structure:
    /// 1. C:\SFTPRoot\{username} - Owned by Administrators/SYSTEM, Read-Only for user (Required for OpenSSH Chroot)
    /// 2. C:\SFTPRoot\{username}\files - Writable by user (Modify/Write/Read)
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

        try
        {
            // 1. Configure userRoot (C:\SFTPRoot\{username})
            var rootDirInfo = new DirectoryInfo(userRoot);
            var rootSecurity = new DirectorySecurity();

            // Disable inheritance and remove existing inherited rules
            rootSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var userAccount = TryResolveAccount(username);

            // Grant Full Control to Administrators and SYSTEM
            rootSecurity.AddAccessRule(new FileSystemAccessRule(
                adminSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            rootSecurity.AddAccessRule(new FileSystemAccessRule(
                systemSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            if (userAccount != null)
            {
                // Grant Read & Execute ONLY to the user (NO Write access to prevent OpenSSH Chroot failure)
                rootSecurity.AddAccessRule(new FileSystemAccessRule(
                    userAccount,
                    FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory,
                    InheritanceFlags.None,
                    PropagationFlags.None,
                    AccessControlType.Allow));
            }
            else
            {
                _logger.LogWarning("Account {Username} could not be resolved to a Windows SID. User-specific Read ACL skipped on chroot root; folder secured for SYSTEM/Administrators.", username);
            }

            rootDirInfo.SetAccessControl(rootSecurity);

            // 2. Configure userFilesDir (C:\SFTPRoot\{username}\files)
            var filesDirInfo = new DirectoryInfo(userFilesDir);
            var filesSecurity = filesDirInfo.GetAccessControl();

            if (userAccount != null)
            {
                // Grant Modify rights to the user inside their 'files' folder
                filesSecurity.AddAccessRule(new FileSystemAccessRule(
                    userAccount,
                    FileSystemRights.Modify | FileSystemRights.DeleteSubdirectoriesAndFiles,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                filesDirInfo.SetAccessControl(filesSecurity);
            }
            else
            {
                _logger.LogWarning("Account {Username} could not be resolved to a Windows SID. User-specific Modify ACL skipped on user files folder.", username);
            }

            _logger.LogInformation("Successfully provisioned NTFS ACLs for user {Username} at {Path}", username, userRoot);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to apply native NTFS ACLs for user {Username} at {Path}", username, userRoot);
            throw;
        }
    }

    /// <summary>
    /// Provisions NTFS ACLs for a custom or shared path (e.g. D:\A) for a user or local group.
    /// </summary>
    public void ProvisionPathAcl(string folderPath, string accountName, SftpPermissionType permission, bool isDirectChroot = false)
    {
        if (!Directory.Exists(folderPath))
        {
            Directory.CreateDirectory(folderPath);
        }

        try
        {
            var dirInfo = new DirectoryInfo(folderPath);
            var security = dirInfo.GetAccessControl();

            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var targetAccount = new NTAccount(accountName);

            // Ensure Administrators and SYSTEM have FullControl
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

            // Purge any previous rules for this account so permission changes (e.g. ReadWrite -> ReadOnly) take effect cleanly
            security.PurgeAccessRules(targetAccount);

            // For DirectChroot, the root folder itself must NOT be writable by the user/group to satisfy OpenSSH strict chroot rules
            FileSystemRights rootRights = (!isDirectChroot && permission == SftpPermissionType.ReadWrite)
                ? FileSystemRights.Modify | FileSystemRights.DeleteSubdirectoriesAndFiles
                : FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory;

            security.AddAccessRule(new FileSystemAccessRule(
                targetAccount,
                rootRights,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            dirInfo.SetAccessControl(security);
            _logger.LogInformation("Applied NTFS ACL ({Permission}, DirectChroot={IsDirectChroot}) on {Path} for {Account}", permission, isDirectChroot, folderPath, accountName);

            // If DirectChroot, configure 'files' subfolder with the requested permission (ReadWrite or ReadOnly)
            if (isDirectChroot)
            {
                var subFiles = Path.Combine(folderPath, "files");
                if (!Directory.Exists(subFiles))
                {
                    Directory.CreateDirectory(subFiles);
                }

                var subInfo = new DirectoryInfo(subFiles);
                var subSecurity = subInfo.GetAccessControl();
                subSecurity.PurgeAccessRules(targetAccount);

                FileSystemRights subRights = permission == SftpPermissionType.ReadWrite
                    ? FileSystemRights.Modify | FileSystemRights.DeleteSubdirectoriesAndFiles
                    : FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory;

                subSecurity.AddAccessRule(new FileSystemAccessRule(
                    targetAccount,
                    subRights,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));
                subInfo.SetAccessControl(subSecurity);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not set ACL on {Path} for {Account}", folderPath, accountName);
        }
    }

    /// <summary>
    /// Removes an access rule for a specific user or group from a directory.
    /// </summary>
    public void RemovePathAcl(string folderPath, string accountName)
    {
        if (!Directory.Exists(folderPath)) return;

        try
        {
            var dirInfo = new DirectoryInfo(folderPath);
            var security = dirInfo.GetAccessControl();
            var targetAccount = new NTAccount(accountName);

            security.PurgeAccessRules(targetAccount);
            dirInfo.SetAccessControl(security);
            _logger.LogInformation("Purged ACLs on {Path} for {Account}", folderPath, accountName);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not remove ACL on {Path} for {Account}", folderPath, accountName);
        }
    }

    /// <summary>
    /// Creates an NTFS Directory Junction from linkPath to targetPath using mklink /J.
    /// </summary>
    public bool CreateDirectoryJunction(string linkPath, string targetPath)
    {
        var (okLink, errLink) = SecurityValidator.ValidateSafeCustomPath(linkPath);
        var (okTarget, errTarget) = SecurityValidator.ValidateSafeCustomPath(targetPath);
        if (!okLink || !okTarget)
        {
            _logger.LogWarning("Rejected unsafe directory junction from {Link} ({ErrLink}) to {Target} ({ErrTarget})", linkPath, errLink, targetPath, errTarget);
            return false;
        }

        try
        {
            if (!Directory.Exists(targetPath))
            {
                Directory.CreateDirectory(targetPath);
            }

            // If link already exists, remove it first
            if (Directory.Exists(linkPath))
            {
                var dirInfo = new DirectoryInfo(linkPath);
                if (dirInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    Directory.Delete(linkPath);
                }
                else
                {
                    // Existing regular directory: don't overwrite blindly
                    return false;
                }
            }

            var parent = Path.GetDirectoryName(linkPath);
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
            psi.ArgumentList.Add(linkPath);
            psi.ArgumentList.Add(targetPath);

            using var proc = new Process { StartInfo = psi };
            proc.Start();
            var outTask = proc.StandardOutput.ReadToEndAsync();
            var errTask = proc.StandardError.ReadToEndAsync();
            bool finished = proc.WaitForExit(5000);
            if (!finished)
            {
                try { proc.Kill(true); } catch { }
                _logger.LogWarning("mklink timed out creating junction from {Link} to {Target}", linkPath, targetPath);
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

    /// <summary>
    /// Removes a directory junction point safely without deleting the files in the target directory.
    /// </summary>
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

    /// <summary>
    /// Lists all ready local fixed and removable drives.
    /// </summary>
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
                catch
                {
                    // Drive offline or restricted, skip
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error enumerating system drives.");
        }
        return items;
    }

    /// <summary>
    /// Lists subdirectories of a given path safely.
    /// </summary>
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
                var (isSafeParent, _) = SecurityValidator.ValidateSafeCustomPath(fullParent);
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
                var (isSafeSub, _) = SecurityValidator.ValidateSafeCustomPath(sub.FullName);
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
        try
        {
            return Directory.Exists(path);
        }
        catch
        {
            return false;
        }
    }

    public bool CreateDirectory(string fullPath)
    {
        var (isSafe, err) = SecurityValidator.ValidateSafeCustomPath(fullPath);
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
        catch
        {
            return null;
        }
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
        catch
        {
            // fallback
        }

        return breadcrumbs;
    }

    /// <summary>
    /// Ensures C:\ProgramData\ssh\keys directory exists with strict SYSTEM/Administrators ACL.
    /// </summary>
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

    /// <summary>
    /// Updates the user's public key file in C:\ProgramData\ssh\keys\{username}
    /// </summary>
    public void WriteUserKeysFile(string keysPath, string username, IEnumerable<string> openSshPublicKeys)
    {
        var (okUser, errUser) = SecurityValidator.ValidateUsername(username);
        if (!okUser)
        {
            throw new SecurityException($"Invalid username for SSH key file: {errUser}");
        }

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
        File.WriteAllText(keyFilePath, content);

        try
        {
            var fileInfo = new FileInfo(keyFilePath);
            var security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

            security.AddAccessRule(new FileSystemAccessRule(adminSid, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, AccessControlType.Allow));

            fileInfo.SetAccessControl(security);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not set ACL on key file {Path}", keyFilePath);
        }
    }
}
