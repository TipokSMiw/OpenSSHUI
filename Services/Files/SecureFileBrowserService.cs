using System.Security;
using Microsoft.EntityFrameworkCore;
using OpensshUI.Data;
using OpensshUI.Models;
using OpensshUI.Services.OpenSsh;
using OpensshUI.Services.Security;

namespace OpensshUI.Services.Files;

public class SecureFileBrowserService : ISecureFileBrowserService
{
    private readonly string _baseRoot;
    private readonly ILogger<SecureFileBrowserService> _logger;
    private readonly IDbContextFactory<AppDbContext>? _dbFactory;
    private readonly IOpenSshServiceManager? _sshServiceManager;

    public SecureFileBrowserService(
        ILogger<SecureFileBrowserService> logger,
        string baseRoot = @"C:\SFTPRoot",
        IDbContextFactory<AppDbContext>? dbFactory = null,
        IOpenSshServiceManager? sshServiceManager = null)
    {
        _logger = logger;
        _baseRoot = baseRoot;
        _dbFactory = dbFactory;
        _sshServiceManager = sshServiceManager;
    }

    private string GetEffectiveSftpRoot()
    {
        return _sshServiceManager?.SftpRoot ?? _baseRoot;
    }

    private (string BasePath, bool IsDirectChroot) ResolveUserDirectoryInfo(string username)
    {
        var cleanUsername = username.Trim();
        if (_dbFactory != null)
        {
            try
            {
                using var db = _dbFactory.CreateDbContext();
                var user = db.SftpUsers.AsNoTracking().FirstOrDefault(u => u.Username == cleanUsername);
                if (user != null)
                {
                    if (user.AccessMode == SftpAccessMode.DirectChroot && !string.IsNullOrWhiteSpace(user.CustomRootPath))
                    {
                        return (Path.GetFullPath(user.CustomRootPath.Trim()), true);
                    }
                    if (!string.IsNullOrWhiteSpace(user.HomeDirectory))
                    {
                        return (Path.GetFullPath(Path.Combine(user.HomeDirectory.Trim(), "files")), false);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not resolve user custom path from DB for {User}, falling back to effective SftpRoot", username);
            }
        }

        return (Path.GetFullPath(Path.Combine(GetEffectiveSftpRoot(), cleanUsername, "files")), false);
    }

    private string ResolveUserBaseDirectory(string username) => ResolveUserDirectoryInfo(username).BasePath;

    private (string BasePath, bool IsDirectChroot) ResolveGroupDirectoryInfo(string groupName)
    {
        var cleanGroup = groupName.Trim();
        if (_dbFactory != null)
        {
            try
            {
                using var db = _dbFactory.CreateDbContext();
                var group = db.SftpGroups.AsNoTracking().FirstOrDefault(g => g.Name == cleanGroup);
                if (group != null && !string.IsNullOrWhiteSpace(group.RootPath))
                {
                    return (Path.GetFullPath(group.RootPath.Trim()), group.AccessMode == SftpAccessMode.DirectChroot);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not resolve group path from DB for {Group}", groupName);
            }
        }

        return (Path.GetFullPath(Path.Combine(GetEffectiveSftpRoot(), "groups", cleanGroup)), false);
    }

    private string ResolveGroupBaseDirectory(string groupName) => ResolveGroupDirectoryInfo(groupName).BasePath;

    private (string SafeBase, string Target, bool IsDirectChroot) GetSafeUserDirectory(string username, string subPath = "")
    {
        // 1. Strict Username Validation
        var (isUsernameValid, usernameError) = SecurityValidator.ValidateUsername(username);
        if (!isUsernameValid)
        {
            _logger.LogWarning("Invalid username detected in file browser: {User} ({Error})", username, usernameError);
            throw new SecurityException($"Access Denied: {usernameError}");
        }

        // 2. Resolve safeBase for this user and normalize trailing separators
        var (rawBase, isDirectChroot) = ResolveUserDirectoryInfo(username);
        var safeBase = Path.GetFullPath(rawBase).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var (isSafeBase, baseErr) = SecurityValidator.ValidateSafeCustomPath(safeBase, GetEffectiveSftpRoot());
        if (!isSafeBase)
        {
            _logger.LogWarning("User directory safety check failed! User: {User}, Path: {Path} ({Error})", username, safeBase, baseErr);
            throw new SecurityException($"Access Denied: {baseErr}");
        }

        // 3. Clean subPath and ensure target stays inside safeBase
        var cleanSubPath = (subPath ?? "").TrimStart('/', '\\').Replace('/', Path.DirectorySeparatorChar);
        var target = Path.GetFullPath(Path.Combine(safeBase, cleanSubPath))
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        if (!target.Equals(safeBase, StringComparison.OrdinalIgnoreCase) &&
            !target.StartsWith(safeBase + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Path traversal attempt detected! User: {User}, Path: {Path}", username, subPath);
            throw new SecurityException("Access Denied: Path Traversal detected.");
        }

        // 4. ReparsePoint (Junction / Symlink) Escape Guard
        ValidateReparsePointEscapes(safeBase, target, username.Trim(), isGroupMode: false);

        return (safeBase, target, isDirectChroot);
    }

    private (string SafeBase, string Target, bool IsDirectChroot) GetSafeGroupDirectory(string groupName, string subPath = "")
    {
        // 1. Strict Group Name Validation
        var (isGroupValid, groupError) = SecurityValidator.ValidateGroupName(groupName, allowDefaultSftpUsersGroup: true);
        if (!isGroupValid)
        {
            _logger.LogWarning("Invalid group name detected in file browser: {Group} ({Error})", groupName, groupError);
            throw new SecurityException($"Access Denied: {groupError}");
        }

        // 2. Resolve safeBase for this group and normalize trailing separators
        var (rawBase, isDirectChroot) = ResolveGroupDirectoryInfo(groupName);
        var safeBase = Path.GetFullPath(rawBase).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var (isSafeBase, baseErr) = SecurityValidator.ValidateSafeCustomPath(safeBase, GetEffectiveSftpRoot());
        if (!isSafeBase)
        {
            _logger.LogWarning("Group directory safety check failed! Group: {Group}, Path: {Path} ({Error})", groupName, safeBase, baseErr);
            throw new SecurityException($"Access Denied: {baseErr}");
        }

        // 3. Clean subPath and ensure target stays inside safeBase
        var cleanSubPath = (subPath ?? "").TrimStart('/', '\\').Replace('/', Path.DirectorySeparatorChar);
        var target = Path.GetFullPath(Path.Combine(safeBase, cleanSubPath))
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        if (!target.Equals(safeBase, StringComparison.OrdinalIgnoreCase) &&
            !target.StartsWith(safeBase + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Path traversal attempt detected! Group: {Group}, Path: {Path}", groupName, subPath);
            throw new SecurityException("Access Denied: Path Traversal detected.");
        }

        // 4. ReparsePoint Escape Guard (groups must never jump outside safeBase)
        ValidateReparsePointEscapes(safeBase, target, groupName.Trim(), isGroupMode: true);

        return (safeBase, target, isDirectChroot);
    }

    private void ValidateReparsePointEscapes(string safeBase, string target, string identifier, bool isGroupMode)
    {
        var normalizedBase = Path.GetFullPath(safeBase).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var checkDir = new DirectoryInfo(target);
        while (checkDir != null)
        {
            var currentFull = Path.GetFullPath(checkDir.FullName).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            bool isBase = currentFull.Equals(normalizedBase, StringComparison.OrdinalIgnoreCase);
            bool isInsideBase = currentFull.StartsWith(normalizedBase + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
            if (!isBase && !isInsideBase)
            {
                break;
            }

            if (checkDir.Exists && checkDir.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                var resolved = checkDir.ResolveLinkTarget(returnFinalTarget: true);
                if (resolved == null || !IsAuthorizedLinkDestination(normalizedBase, resolved.FullName, identifier, isGroupMode))
                {
                    _logger.LogWarning("ReparsePoint escape or unauthorized link blocked! Identifier: {Id}, Link: {Link} -> {Target}",
                        identifier, checkDir.FullName, resolved?.FullName ?? "<unresolvable>");
                    throw new SecurityException("Access Denied: Symbolic link or junction targets a restricted or unauthorized directory.");
                }
            }

            if (isBase)
            {
                break;
            }
            checkDir = checkDir.Parent;
        }

        var fileInfo = new FileInfo(target);
        if (fileInfo.Exists && fileInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            var resolvedFile = fileInfo.ResolveLinkTarget(returnFinalTarget: true);
            var parentDir = resolvedFile != null ? Path.GetDirectoryName(resolvedFile.FullName) : null;
            if (resolvedFile == null || string.IsNullOrEmpty(parentDir) ||
                !IsAuthorizedLinkDestination(normalizedBase, resolvedFile.FullName, identifier, isGroupMode) ||
                !IsAuthorizedLinkDestination(normalizedBase, parentDir, identifier, isGroupMode))
            {
                throw new SecurityException("Access Denied: File symbolic link targets a restricted or unauthorized directory.");
            }
        }
    }

    private bool IsAuthorizedLinkDestination(string normalizedBase, string destinationFullPath, string identifier, bool isGroupMode)
    {
        var normalizedDest = Path.GetFullPath(destinationFullPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var (isSafeLink, _) = SecurityValidator.ValidateSafeCustomPath(normalizedDest, GetEffectiveSftpRoot());
        if (!isSafeLink)
        {
            return false;
        }

        if (normalizedDest.Equals(normalizedBase, StringComparison.OrdinalIgnoreCase) ||
            normalizedDest.StartsWith(normalizedBase + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (isGroupMode || _dbFactory == null)
        {
            return false;
        }

        try
        {
            using var db = _dbFactory.CreateDbContext();
            var user = db.SftpUsers.AsNoTracking()
                .Include(u => u.UserGroups)
                .ThenInclude(ug => ug.Group)
                .FirstOrDefault(u => u.Username == identifier);

            if (user == null)
            {
                return false;
            }

            var authorizedRoots = new List<string>();
            if (!string.IsNullOrWhiteSpace(user.CustomRootPath))
            {
                authorizedRoots.Add(Path.GetFullPath(user.CustomRootPath.Trim())
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            }

            foreach (var ug in user.UserGroups)
            {
                if (ug.Group == null || ug.Group.AccessMode != SftpAccessMode.VirtualFolder)
                {
                    continue;
                }

                var grpPath = !string.IsNullOrWhiteSpace(ug.Group.RootPath)
                    ? ug.Group.RootPath.Trim()
                    : Path.Combine(GetEffectiveSftpRoot(), "groups", ug.Group.Name);
                authorizedRoots.Add(Path.GetFullPath(grpPath)
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            }

            return authorizedRoots.Any(root =>
                normalizedDest.Equals(root, StringComparison.OrdinalIgnoreCase) ||
                normalizedDest.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed resolving DB-authorized link targets for {User}", identifier);
            return false;
        }
    }

    private static List<FileItemInfo> ListItemsInternal(string safeBase, string targetDir, bool isDirectChroot = false)
    {
        if (isDirectChroot && !Directory.Exists(safeBase))
        {
            throw new DirectoryNotFoundException($"DirectChroot root directory '{safeBase}' does not exist. Refuse to create unprovisioned Chroot root without Administrator ACL ownership.");
        }

        if (!Directory.Exists(targetDir))
        {
            return new List<FileItemInfo>();
        }

        var list = new List<FileItemInfo>();
        var dirInfo = new DirectoryInfo(targetDir);

        foreach (var dir in dirInfo.GetDirectories())
        {
            var rel = Path.GetRelativePath(safeBase, dir.FullName).Replace('\\', '/');
            list.Add(new FileItemInfo
            {
                Name = dir.Name,
                RelativePath = rel,
                IsDirectory = true,
                SizeBytes = 0,
                LastModified = dir.LastWriteTimeUtc,
                Extension = ""
            });
        }

        foreach (var file in dirInfo.GetFiles())
        {
            var rel = Path.GetRelativePath(safeBase, file.FullName).Replace('\\', '/');
            list.Add(new FileItemInfo
            {
                Name = file.Name,
                RelativePath = rel,
                IsDirectory = false,
                SizeBytes = file.Length,
                LastModified = file.LastWriteTimeUtc,
                Extension = file.Extension
            });
        }

        return list;
    }

    private static async Task UploadFileInternalAsync(string safeBase, string targetDir, string fileName, Stream sourceStream, long maxSizeBytes)
    {
        var (isValidName, nameErr) = SecurityValidator.ValidateFolderItemName(fileName);
        if (!isValidName)
        {
            throw new SecurityException($"Access Denied: {nameErr}");
        }

        var normalizedBase = Path.GetFullPath(safeBase).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var safeFileName = Path.GetFileName(fileName.Trim());
        var targetFile = Path.GetFullPath(Path.Combine(targetDir, safeFileName));

        if (!targetFile.StartsWith(normalizedBase + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityException("Access Denied: Path Traversal detected in filename.");
        }

        if (Directory.Exists(targetFile) ||
            (File.Exists(targetFile) && File.GetAttributes(targetFile).HasFlag(FileAttributes.ReparsePoint)))
        {
            throw new SecurityException("Access Denied: Cannot overwrite a directory or reparse point target.");
        }

        using var destination = new FileStream(targetFile, FileMode.Create, FileAccess.Write, FileShare.None);
        var buffer = new byte[81920];
        long totalBytesRead = 0;
        int bytesRead;

        while ((bytesRead = await sourceStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
        {
            totalBytesRead += bytesRead;
            if (totalBytesRead > maxSizeBytes)
            {
                destination.Close();
                File.Delete(targetFile);
                throw new InvalidOperationException($"File exceeds maximum allowed upload size of {maxSizeBytes / (1024 * 1024)} MB.");
            }
            await destination.WriteAsync(buffer, 0, bytesRead);
        }
    }

    private static void DeleteItemInternal(string safeBase, string target, bool isDirectChroot = false)
    {
        var normalizedBase = Path.GetFullPath(safeBase).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var normalizedTarget = Path.GetFullPath(target).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        if (normalizedTarget.Equals(normalizedBase, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Cannot delete the root files folder.");
        }

        if (isDirectChroot)
        {
            var protectedFilesDir = Path.Combine(normalizedBase, "files");
            if (normalizedTarget.Equals(protectedFilesDir, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Cannot delete the protected 'files' subdirectory inside a DirectChroot root folder.");
            }
        }

        if (File.Exists(normalizedTarget))
        {
            if (File.GetAttributes(normalizedTarget).HasFlag(FileAttributes.ReparsePoint))
            {
                throw new InvalidOperationException("Cannot delete a symbolic link file from the file browser.");
            }
            File.Delete(normalizedTarget);
        }
        else if (Directory.Exists(normalizedTarget))
        {
            var dirInfo = new DirectoryInfo(normalizedTarget);
            if (dirInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw new InvalidOperationException("Cannot delete a shared group or custom root junction folder from the file browser.");
            }

            // Refuse deleting a directory that contains nested junctions or symbolic links (non-descending walk)
            var dirStack = new Stack<DirectoryInfo>();
            dirStack.Push(dirInfo);
            var enumOpts = new EnumerationOptions
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = false,
                AttributesToSkip = 0
            };
            while (dirStack.Count > 0)
            {
                var current = dirStack.Pop();
                foreach (var sub in current.EnumerateDirectories("*", enumOpts))
                {
                    if (sub.Attributes.HasFlag(FileAttributes.ReparsePoint))
                    {
                        throw new InvalidOperationException("Cannot delete a directory that contains a shared group or custom root junction folder.");
                    }
                    dirStack.Push(sub);
                }
            }

            Directory.Delete(normalizedTarget, true);
        }
    }

    private static void CreateDirectoryInternal(string safeBase, string targetParent, string directoryName)
    {
        var (isValidName, nameErr) = SecurityValidator.ValidateFolderItemName(directoryName);
        if (!isValidName)
        {
            throw new SecurityException($"Access Denied: {nameErr}");
        }

        var normalizedBase = Path.GetFullPath(safeBase).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var safeDirName = Path.GetFileName(directoryName.Trim());
        var targetPath = Path.GetFullPath(Path.Combine(targetParent, safeDirName))
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        if (!targetPath.StartsWith(normalizedBase + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityException("Access Denied: Path Traversal detected in folder name.");
        }

        if (!Directory.Exists(normalizedBase))
        {
            throw new DirectoryNotFoundException($"Base directory '{normalizedBase}' does not exist.");
        }

        if (Directory.Exists(targetPath) && new DirectoryInfo(targetPath).Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new SecurityException("Access Denied: Target path is an existing symbolic link or junction.");
        }

        Directory.CreateDirectory(targetPath);
    }

    // ==========================================
    // User Operations Implementation
    // ==========================================

    public Task<List<FileItemInfo>> ListItemsAsync(string username, string subPath = "")
    {
        return Task.Run(() =>
        {
            var (safeBase, targetDir, isDirectChroot) = GetSafeUserDirectory(username, subPath);
            return ListItemsInternal(safeBase, targetDir, isDirectChroot);
        });
    }

    public Task<Stream> OpenReadStreamAsync(string username, string subPath)
    {
        var (_, targetFile, _) = GetSafeUserDirectory(username, subPath);
        if (!File.Exists(targetFile))
        {
            throw new FileNotFoundException("File not found.", subPath);
        }

        var stream = new FileStream(targetFile, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Task.FromResult<Stream>(stream);
    }

    public async Task UploadFileAsync(string username, string subPath, string fileName, Stream sourceStream, long maxSizeBytes = 500 * 1024 * 1024)
    {
        var (safeBase, targetDir, _) = GetSafeUserDirectory(username, subPath);
        await UploadFileInternalAsync(safeBase, targetDir, fileName, sourceStream, maxSizeBytes);
    }

    public Task DeleteItemAsync(string username, string subPath)
    {
        return Task.Run(() =>
        {
            var (safeBase, target, isDirectChroot) = GetSafeUserDirectory(username, subPath);
            DeleteItemInternal(safeBase, target, isDirectChroot);
        });
    }

    public Task CreateDirectoryAsync(string username, string subPath, string directoryName)
    {
        return Task.Run(() =>
        {
            var (safeBase, targetParent, _) = GetSafeUserDirectory(username, subPath);
            CreateDirectoryInternal(safeBase, targetParent, directoryName);
        });
    }

    public long GetTotalUserStorageBytes(string username)
        => GetTotalUserStorageBytes(username, CancellationToken.None);

    public long GetTotalUserStorageBytes(string username, CancellationToken cancellationToken)
    {
        try
        {
            var (isValid, _) = SecurityValidator.ValidateUsername(username);
            if (!isValid) return 0;

            var userDir = ResolveUserBaseDirectory(username);
            var (isSafe, _) = SecurityValidator.ValidateSafeCustomPath(userDir, GetEffectiveSftpRoot());
            if (!isSafe || !Directory.Exists(userDir)) return 0;

            return CalculateDirectorySizeExcludingReparsePoints(new DirectoryInfo(userDir), cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error calculating storage for user {User}", username);
            return 0;
        }
    }

    public Task<long> GetTotalUserStorageBytesAsync(string username, CancellationToken cancellationToken = default)
    {
        return Task.Run(() => GetTotalUserStorageBytes(username, cancellationToken), cancellationToken);
    }

    public Task<string?> ResolveUserPhysicalPathAsync(string username)
    {
        try
        {
            var (isValid, _) = SecurityValidator.ValidateUsername(username);
            if (!isValid) return Task.FromResult<string?>(null);

            var path = ResolveUserBaseDirectory(username);
            return Task.FromResult<string?>(path);
        }
        catch
        {
            return Task.FromResult<string?>(null);
        }
    }

    // ==========================================
    // Group Operations Implementation
    // ==========================================

    public Task<List<FileItemInfo>> ListGroupItemsAsync(string groupName, string subPath = "")
    {
        return Task.Run(() =>
        {
            var (safeBase, targetDir, isDirectChroot) = GetSafeGroupDirectory(groupName, subPath);
            return ListItemsInternal(safeBase, targetDir, isDirectChroot);
        });
    }

    public Task<Stream> OpenGroupReadStreamAsync(string groupName, string subPath)
    {
        var (_, targetFile, _) = GetSafeGroupDirectory(groupName, subPath);
        if (!File.Exists(targetFile))
        {
            throw new FileNotFoundException("File not found in group share.", subPath);
        }

        var stream = new FileStream(targetFile, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Task.FromResult<Stream>(stream);
    }

    public async Task UploadGroupFileAsync(string groupName, string subPath, string fileName, Stream sourceStream, long maxSizeBytes = 500 * 1024 * 1024)
    {
        var (safeBase, targetDir, _) = GetSafeGroupDirectory(groupName, subPath);
        await UploadFileInternalAsync(safeBase, targetDir, fileName, sourceStream, maxSizeBytes);
    }

    public Task DeleteGroupItemAsync(string groupName, string subPath)
    {
        return Task.Run(() =>
        {
            var (safeBase, target, isDirectChroot) = GetSafeGroupDirectory(groupName, subPath);
            DeleteItemInternal(safeBase, target, isDirectChroot);
        });
    }

    public Task CreateGroupDirectoryAsync(string groupName, string subPath, string directoryName)
    {
        return Task.Run(() =>
        {
            var (safeBase, targetParent, _) = GetSafeGroupDirectory(groupName, subPath);
            CreateDirectoryInternal(safeBase, targetParent, directoryName);
        });
    }

    public long GetTotalGroupStorageBytes(string groupName)
        => GetTotalGroupStorageBytes(groupName, CancellationToken.None);

    public long GetTotalGroupStorageBytes(string groupName, CancellationToken cancellationToken)
    {
        try
        {
            var (isValid, _) = SecurityValidator.ValidateGroupName(groupName, allowDefaultSftpUsersGroup: true);
            if (!isValid) return 0;

            var groupDir = ResolveGroupBaseDirectory(groupName);
            var (isSafe, _) = SecurityValidator.ValidateSafeCustomPath(groupDir, GetEffectiveSftpRoot());
            if (!isSafe || !Directory.Exists(groupDir)) return 0;

            return CalculateDirectorySizeExcludingReparsePoints(new DirectoryInfo(groupDir), cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error calculating storage for group {Group}", groupName);
            return 0;
        }
    }

    public Task<long> GetTotalGroupStorageBytesAsync(string groupName, CancellationToken cancellationToken = default)
    {
        return Task.Run(() => GetTotalGroupStorageBytes(groupName, cancellationToken), cancellationToken);
    }

    public Task<string?> ResolveGroupPhysicalPathAsync(string groupName)
    {
        try
        {
            var (isValid, _) = SecurityValidator.ValidateGroupName(groupName, allowDefaultSftpUsersGroup: true);
            if (!isValid) return Task.FromResult<string?>(null);

            var path = ResolveGroupBaseDirectory(groupName);
            return Task.FromResult<string?>(path);
        }
        catch
        {
            return Task.FromResult<string?>(null);
        }
    }

    // ==========================================
    // Common Storage Calculation
    // ==========================================

    private static long CalculateDirectorySizeExcludingReparsePoints(DirectoryInfo rootDir, CancellationToken cancellationToken = default)
    {
        long totalBytes = 0;
        var stack = new Stack<DirectoryInfo>();
        stack.Push(rootDir);

        var fileEnumOptions = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = false,
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        var dirEnumOptions = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = false,
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        while (stack.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var currentDir = stack.Pop();

            try
            {
                foreach (var file in currentDir.EnumerateFiles("*", fileEnumOptions))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    totalBytes += file.Length;
                }

                foreach (var subDir in currentDir.EnumerateDirectories("*", dirEnumOptions))
                {
                    stack.Push(subDir);
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                // Inaccessible folder, continue with remaining items
            }
        }

        return totalBytes;
    }
}
