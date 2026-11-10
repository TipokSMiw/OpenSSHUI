using System.Runtime.Versioning;
using Microsoft.EntityFrameworkCore;
using OpensshUI.Data;
using OpensshUI.Models;
using OpensshUI.Services.Audit;
using OpensshUI.Services.Groups;
using OpensshUI.Services.OpenSsh;
using OpensshUI.Services.Security;

namespace OpensshUI.Services.Users;

[SupportedOSPlatform("windows")]
public class SftpUserService : ISftpUserService
{
    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly INativeAclProvisioner _aclProvisioner;
    private readonly IWindowsUserManager _windowsUserManager;
    private readonly IOpenSshServiceManager _sshServiceManager;
    private readonly ISftpGroupService _groupService;
    private readonly IAuditService _auditService;
    private readonly ISshKeyGenerator _sshKeyGenerator;
    private readonly ILogger<SftpUserService> _logger;

    public SftpUserService(
        IDbContextFactory<AppDbContext> dbFactory,
        INativeAclProvisioner aclProvisioner,
        IWindowsUserManager windowsUserManager,
        IOpenSshServiceManager sshServiceManager,
        ISftpGroupService groupService,
        IAuditService auditService,
        ISshKeyGenerator sshKeyGenerator,
        ILogger<SftpUserService> logger)
    {
        _dbFactory = dbFactory;
        _aclProvisioner = aclProvisioner;
        _windowsUserManager = windowsUserManager;
        _sshServiceManager = sshServiceManager;
        _groupService = groupService;
        _auditService = auditService;
        _sshKeyGenerator = sshKeyGenerator;
        _logger = logger;
    }

    public async Task<List<SftpUser>> GetAllUsersAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        return await db.SftpUsers
            .AsNoTracking()
            .Include(u => u.PublicKeys)
            .Include(u => u.UserGroups)
                .ThenInclude(ug => ug.Group)
            .OrderBy(u => u.Username)
            .ToListAsync();
    }

    public async Task<SftpUser?> GetUserAsync(string username)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        return await db.SftpUsers
            .AsNoTracking()
            .Include(u => u.PublicKeys)
            .Include(u => u.UserGroups)
                .ThenInclude(ug => ug.Group)
            .FirstOrDefaultAsync(u => u.Username == username);
    }

    public async Task<(bool Success, string Message)> CreateUserAsync(CreateUserRequest request, string op = "admin")
    {
        var (okUser, userErr) = SecurityValidator.ValidateUsername(request.Username);
        if (!okUser)
        {
            return (false, userErr!);
        }

        var cleanUsername = request.Username.Trim();

        if (!string.IsNullOrWhiteSpace(request.CustomRootPath))
        {
            var (okPath, pathErr) = SecurityValidator.ValidateSafeCustomPath(request.CustomRootPath, _sshServiceManager.SftpRoot);
            if (!okPath)
            {
                return (false, pathErr!);
            }
        }

        await using var db = await _dbFactory.CreateDbContextAsync();
        if (await db.SftpUsers.AnyAsync(u => u.Username == cleanUsername))
        {
            return (false, $"User '{cleanUsername}' already exists.");
        }

        try
        {
            // 1. If LocalWindows user, create local Windows user and add to SFTP-Users group
            if (request.AccountType == SftpAccountType.LocalWindows)
            {
                var (okPass, passErr) = SecurityValidator.ValidateWindowsPassword(request.Password);
                if (!okPass)
                {
                    return (false, passErr!);
                }

                bool userCreated = _windowsUserManager.CreateOrUpdateLocalUser(cleanUsername, request.Password!, true);
                if (!userCreated)
                {
                    await _auditService.LogAsync("USER_CREATE_FAIL", $"Failed to create OS user '{cleanUsername}'", false, op);
                    return (false, "Failed to create local Windows account. Ensure the application is running as Administrator.");
                }
            }
            else if (request.AccountType == SftpAccountType.ActiveDirectory)
            {
                // Ensure Active Directory user is a member of the SFTP-Users local group for OpenSSH chroot rules
                _windowsUserManager.AddUserToLocalGroup("SFTP-Users", cleanUsername);
            }

            // 2. Provision Directory & Native NTFS ACLs
            _aclProvisioner.ProvisionUserChroot(_sshServiceManager.SftpRoot, cleanUsername);

            string? cleanCustomRoot = null;
            if (!string.IsNullOrWhiteSpace(request.CustomRootPath))
            {
                cleanCustomRoot = Path.GetFullPath(request.CustomRootPath.Trim());
                _aclProvisioner.ProvisionPathAcl(
                    cleanCustomRoot, 
                    cleanUsername, 
                    request.CustomPermissionType, 
                    isDirectChroot: request.AccessMode == SftpAccessMode.DirectChroot);
            }

            // 3. Database Entity
            var user = new SftpUser
            {
                Username = cleanUsername,
                DisplayName = string.IsNullOrWhiteSpace(request.DisplayName) ? cleanUsername : request.DisplayName,
                AccountType = request.AccountType,
                IsActive = true,
                HomeDirectory = Path.Combine(_sshServiceManager.SftpRoot, cleanUsername),
                CustomRootPath = cleanCustomRoot,
                CustomPermissionType = request.CustomPermissionType,
                AccessMode = request.AccessMode,
                CreatedAt = DateTime.UtcNow,
                Notes = request.Notes
            };

            // 4. Group memberships
            if (request.GroupIds.Any())
            {
                var availableGroups = await db.SftpGroups.Where(g => request.GroupIds.Contains(g.Id)).ToListAsync();
                foreach (var grp in availableGroups)
                {
                    user.UserGroups.Add(new SftpUserGroup
                    {
                        Username = cleanUsername,
                        GroupId = grp.Id,
                        JoinedAt = DateTime.UtcNow
                    });

                    // Add to OS Local Group
                    var osGrp = WindowsUserManager.ToOsGroupName(grp.Name);
                    _windowsUserManager.AddUserToLocalGroup(osGrp, cleanUsername);
                }
            }

            // 5. Optional Initial Public Key
            if (!string.IsNullOrWhiteSpace(request.SshPublicKey))
            {
                var parse = SshKeyConverter.ParseAndNormalizeKey(request.SshPublicKey);
                if (parse.IsSuccess)
                {
                    var key = new SshPublicKey
                    {
                        Username = cleanUsername,
                        KeyType = parse.KeyType,
                        FingerprintSha256 = parse.FingerprintSha256,
                        RawPublicKey = parse.RawPublicKey,
                        Comment = parse.Comment,
                        AddedAt = DateTime.UtcNow
                    };
                    user.PublicKeys.Add(key);

                    // Write key file
                    _aclProvisioner.WriteUserKeysFile(_sshServiceManager.KeysPath, cleanUsername, new[] { parse.RawPublicKey });
                }
            }

            db.SftpUsers.Add(user);
            await db.SaveChangesAsync();

            // 6. Sync Directory Junctions for virtual folder groups
            await _groupService.SyncUserJunctionsAsync(cleanUsername);

            // 7. Sync DirectChroot config if needed
            if (user.AccessMode == SftpAccessMode.DirectChroot && !string.IsNullOrEmpty(user.CustomRootPath))
            {
                await _groupService.SyncAllDirectChrootConfigsAsync();
            }

            await _auditService.LogAsync("USER_CREATE", $"Created SFTP user '{cleanUsername}' ({request.AccountType})", true, op);
            return (true, $"User '{cleanUsername}' created successfully.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create user {User}", cleanUsername);
            await _auditService.LogAsync("USER_CREATE_ERROR", $"Exception creating user '{cleanUsername}': {ex.Message}", false, op);
            return (false, $"Error creating user: {ex.Message}");
        }
    }

    public async Task<(bool Success, string Message)> UpdateUserAsync(UpdateUserRequest request, string op = "admin")
    {
        var (okUser, userErr) = SecurityValidator.ValidateUsername(request.Username);
        if (!okUser)
        {
            return (false, userErr!);
        }

        await using var db = await _dbFactory.CreateDbContextAsync();
        var user = await db.SftpUsers
            .Include(u => u.UserGroups)
                .ThenInclude(ug => ug.Group)
            .FirstOrDefaultAsync(u => u.Username == request.Username);

        if (user == null) return (false, "User not found.");

        try
        {
            var oldCustomRootPath = user.CustomRootPath;
            var oldAccessMode = user.AccessMode;

            user.DisplayName = string.IsNullOrWhiteSpace(request.DisplayName) ? user.Username : request.DisplayName.Trim();
            user.Notes = request.Notes;
            user.CustomPermissionType = request.CustomPermissionType;
            user.AccessMode = request.AccessMode;

            string? cleanCustomRoot = null;
            if (!string.IsNullOrWhiteSpace(request.CustomRootPath))
            {
                var (okPath, pathErr) = SecurityValidator.ValidateSafeCustomPath(request.CustomRootPath, _sshServiceManager.SftpRoot);
                if (!okPath)
                {
                    return (false, pathErr!);
                }

                cleanCustomRoot = Path.GetFullPath(request.CustomRootPath.Trim());
                _aclProvisioner.ProvisionPathAcl(
                    cleanCustomRoot, 
                    user.Username, 
                    request.CustomPermissionType, 
                    isDirectChroot: request.AccessMode == SftpAccessMode.DirectChroot);
            }

            // If CustomRootPath was changed or cleared, remove ACL from the previous path
            if (!string.IsNullOrWhiteSpace(oldCustomRootPath) &&
                !string.Equals(oldCustomRootPath, cleanCustomRoot, StringComparison.OrdinalIgnoreCase))
            {
                _aclProvisioner.RemovePathAcl(oldCustomRootPath, user.Username);
            }

            user.CustomRootPath = cleanCustomRoot;

            // Sync Group memberships
            var currentGroupIds = user.UserGroups.Select(ug => ug.GroupId).ToList();
            var targetGroupIds = request.GroupIds.Distinct().ToList();

            // Groups to remove
            var toRemove = user.UserGroups.Where(ug => !targetGroupIds.Contains(ug.GroupId)).ToList();
            foreach (var ug in toRemove)
            {
                if (ug.Group != null)
                {
                    var osGrp = WindowsUserManager.ToOsGroupName(ug.Group.Name);
                    _windowsUserManager.RemoveUserFromLocalGroup(osGrp, user.Username);
                }
                user.UserGroups.Remove(ug);
            }

            // Groups to add
            var toAddIds = targetGroupIds.Where(gid => !currentGroupIds.Contains(gid)).ToList();
            var groupsToAdd = await db.SftpGroups.Where(g => toAddIds.Contains(g.Id)).ToListAsync();
            foreach (var grp in groupsToAdd)
            {
                user.UserGroups.Add(new SftpUserGroup
                {
                    Username = user.Username,
                    GroupId = grp.Id,
                    JoinedAt = DateTime.UtcNow
                });
                var osGrp = WindowsUserManager.ToOsGroupName(grp.Name);
                _windowsUserManager.AddUserToLocalGroup(osGrp, user.Username);
            }

            await db.SaveChangesAsync();

            // Sync junctions
            await _groupService.SyncUserJunctionsAsync(user.Username);

            // Sync DirectChroot rules only when DirectChroot mode was or is active (Zero-Config Reload Discipline)
            if (oldAccessMode == SftpAccessMode.DirectChroot || user.AccessMode == SftpAccessMode.DirectChroot)
            {
                await _groupService.SyncAllDirectChrootConfigsAsync();
            }

            await _auditService.LogAsync("USER_UPDATE", $"Updated user '{user.Username}'", true, op);
            return (true, $"User '{user.Username}' updated successfully.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update user {User}", user.Username);
            return (false, $"Error updating user: {ex.Message}");
        }
    }

    public async Task<(bool Success, string Message)> UpdateUserStatusAsync(string username, bool isActive, string op = "admin")
    {
        var (okUser, userErr) = SecurityValidator.ValidateUsername(username);
        if (!okUser) return (false, userErr!);

        await using var db = await _dbFactory.CreateDbContextAsync();
        var user = await db.SftpUsers.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null) return (false, "User not found.");

        user.IsActive = isActive;
        await db.SaveChangesAsync();

        if (user.AccountType == SftpAccountType.LocalWindows)
        {
            bool osUpdated = _windowsUserManager.CreateOrUpdateLocalUser(username, "", isActive);
            if (!osUpdated)
            {
                _logger.LogWarning("OS user status update returned false for {Username} (IsActive={IsActive})", username, isActive);
            }
        }

        await _auditService.LogAsync("USER_STATUS_CHANGE", $"User '{username}' status changed to {(isActive ? "Active" : "Disabled")}", true, op);
        return (true, $"User '{username}' updated.");
    }

    public async Task<(bool Success, string Message)> ResetPasswordAsync(string username, string newPassword, string op = "admin")
    {
        var (okUser, userErr) = SecurityValidator.ValidateUsername(username);
        if (!okUser) return (false, userErr!);

        var (okPass, passErr) = SecurityValidator.ValidateWindowsPassword(newPassword);
        if (!okPass) return (false, passErr!);

        await using var db = await _dbFactory.CreateDbContextAsync();
        var user = await db.SftpUsers.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null) return (false, "User not found.");

        if (user.AccountType != SftpAccountType.LocalWindows)
        {
            return (false, "Cannot change password of Active Directory account directly from here.");
        }

        bool ok = _windowsUserManager.CreateOrUpdateLocalUser(username, newPassword, user.IsActive);
        if (!ok)
        {
            await _auditService.LogAsync("USER_PASSWORD_RESET_FAIL", $"Failed to reset password for '{username}'", false, op);
            return (false, "Failed to reset Windows password.");
        }

        await _auditService.LogAsync("USER_PASSWORD_RESET", $"Password reset for '{username}'", true, op);
        return (true, "Password updated successfully.");
    }

    public async Task<(bool Success, string Message)> DeleteUserAsync(string username, bool deleteFiles = false, string op = "admin")
    {
        var (okUser, userErr) = SecurityValidator.ValidateUsername(username);
        if (!okUser) return (false, userErr!);

        var cleanUsername = username.Trim();
        await using var db = await _dbFactory.CreateDbContextAsync();
        var user = await db.SftpUsers
            .Include(u => u.PublicKeys)
            .Include(u => u.UserGroups)
                .ThenInclude(ug => ug.Group)
            .FirstOrDefaultAsync(u => u.Username == cleanUsername);

        if (user == null) return (false, "User not found.");

        var userDir = !string.IsNullOrWhiteSpace(user.HomeDirectory)
            ? Path.GetFullPath(user.HomeDirectory.Trim())
            : Path.Combine(_sshServiceManager.SftpRoot, cleanUsername);
        var userFilesDir = Path.Combine(userDir, "files");

        // Remove from all OS local groups and detach group junctions first
        bool allJunctionsDetachedSafely = true;
        foreach (var ug in user.UserGroups)
        {
            if (ug.Group != null)
            {
                var osGrp = WindowsUserManager.ToOsGroupName(ug.Group.Name);
                _windowsUserManager.RemoveUserFromLocalGroup(osGrp, cleanUsername);

                var grpJunction = Path.Combine(userFilesDir, ug.Group.Name);
                bool detached = _aclProvisioner.RemoveDirectoryJunction(grpJunction);
                if (!detached && Directory.Exists(grpJunction))
                {
                    allJunctionsDetachedSafely = false;
                    _logger.LogWarning("Failed to detach group junction {Junction} before deleting user {User}; aborting recursive file deletion to protect shared data.", grpJunction, cleanUsername);
                }
            }
        }

        // Detach any remaining reparse points (junctions) inside user's directory tree before recursive delete
        if (Directory.Exists(userDir))
        {
            try
            {
                var enumOptions = new EnumerationOptions
                {
                    IgnoreInaccessible = true,
                    RecurseSubdirectories = true,
                    AttributesToSkip = 0 // Do NOT skip reparse points when searching for junctions to detach
                };

                foreach (var sub in new DirectoryInfo(userDir).EnumerateDirectories("*", enumOptions))
                {
                    if (sub.Attributes.HasFlag(FileAttributes.ReparsePoint))
                    {
                        bool detached = _aclProvisioner.RemoveDirectoryJunction(sub.FullName);
                        if (!detached && Directory.Exists(sub.FullName))
                        {
                            allJunctionsDetachedSafely = false;
                            _logger.LogWarning("Failed to detach reparse point {Junction} before deleting user {User}; aborting recursive file deletion.", sub.FullName, cleanUsername);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                allJunctionsDetachedSafely = false;
                _logger.LogWarning(ex, "Could not enumerate/remove junctions in {Dir} before user deletion", userDir);
            }
        }

        if (!string.IsNullOrWhiteSpace(user.CustomRootPath))
        {
            _aclProvisioner.RemovePathAcl(user.CustomRootPath, cleanUsername);
        }

        if (user.AccountType == SftpAccountType.LocalWindows)
        {
            _windowsUserManager.DeleteLocalUser(cleanUsername);
        }
        else if (user.AccountType == SftpAccountType.ActiveDirectory)
        {
            _windowsUserManager.RemoveUserFromLocalGroup("SFTP-Users", cleanUsername);
        }

        // Delete keys file
        var keyFile = Path.Combine(_sshServiceManager.KeysPath, cleanUsername);
        if (File.Exists(keyFile)) File.Delete(keyFile);

        // Delete files folder if requested and all junctions were safely detached
        if (deleteFiles && allJunctionsDetachedSafely)
        {
            if (Directory.Exists(userDir))
            {
                try { Directory.Delete(userDir, true); } catch (Exception ex) { _logger.LogWarning(ex, "Could not delete user dir {Dir}", userDir); }
            }
        }

        db.SftpUsers.Remove(user);
        await db.SaveChangesAsync();

        if (user.AccessMode == SftpAccessMode.DirectChroot)
        {
            await _groupService.SyncAllDirectChrootConfigsAsync();
        }

        await _auditService.LogAsync("USER_DELETE", $"Deleted user '{cleanUsername}' (DeleteFiles: {deleteFiles})", true, op);
        return (true, $"User '{cleanUsername}' deleted.");
    }

    public async Task<(bool Success, string Message, SshPublicKey? Key)> AddPublicKeyAsync(string username, string rawKey, string? comment = null, string op = "admin")
    {
        var (okUser, userErr) = SecurityValidator.ValidateUsername(username);
        if (!okUser)
        {
            return (false, userErr!, null);
        }
        var parse = SshKeyConverter.ParseAndNormalizeKey(rawKey);
        if (!parse.IsSuccess)
        {
            return (false, parse.ErrorMessage ?? "Invalid SSH Key format.", null);
        }

        await using var db = await _dbFactory.CreateDbContextAsync();
        var user = await db.SftpUsers.Include(u => u.PublicKeys).FirstOrDefaultAsync(u => u.Username == username);
        if (user == null) return (false, "User not found.", null);

        if (user.PublicKeys.Any(k => string.Equals(k.FingerprintSha256, parse.FingerprintSha256, StringComparison.OrdinalIgnoreCase)))
        {
            return (false, $"SSH Key with fingerprint '{parse.FingerprintSha256}' already exists for this user.", null);
        }

        var safeCustomComment = string.IsNullOrWhiteSpace(comment)
            ? null
            : SecurityValidator.SanitizeSingleLine(comment);

        var key = new SshPublicKey
        {
            Username = username,
            KeyType = parse.KeyType,
            FingerprintSha256 = parse.FingerprintSha256,
            RawPublicKey = parse.RawPublicKey,
            Comment = safeCustomComment ?? parse.Comment,
            AddedAt = DateTime.UtcNow
        };

        user.PublicKeys.Add(key);
        await db.SaveChangesAsync();

        // Refresh user's key file
        var allKeys = user.PublicKeys.Select(k => k.RawPublicKey).ToList();
        _aclProvisioner.WriteUserKeysFile(_sshServiceManager.KeysPath, username, allKeys);

        await _auditService.LogAsync("KEY_ADD", $"Added SSH Key ({parse.KeyType}, {parse.FingerprintSha256}) for user '{username}'", true, op);
        return (true, "SSH Key added successfully.", key);
    }

    public async Task<(bool Success, string Message)> DeletePublicKeyAsync(int keyId, string op = "admin")
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var key = await db.SshPublicKeys.FirstOrDefaultAsync(k => k.Id == keyId);
        if (key == null) return (false, "Key not found.");

        var username = key.Username;
        db.SshPublicKeys.Remove(key);
        await db.SaveChangesAsync();

        // Refresh user's key file
        var remainingKeys = await db.SshPublicKeys.Where(k => k.Username == username).Select(k => k.RawPublicKey).ToListAsync();
        _aclProvisioner.WriteUserKeysFile(_sshServiceManager.KeysPath, username, remainingKeys);

        await _auditService.LogAsync("KEY_DELETE", $"Deleted SSH Key #{keyId} for user '{username}'", true, op);
        return (true, "SSH Key removed.");
    }

    public async Task<(bool Success, string Message, SshKeyGenerateResult? Result)> GenerateAutomationKeyAsync(
        GenerateAutomationKeyRequest request, 
        string op = "admin")
    {
        var (okUser, userErr) = SecurityValidator.ValidateUsername(request.Username);
        if (!okUser)
        {
            return (false, userErr!, null);
        }

        var cleanUsername = request.Username.Trim();
        await using var db = await _dbFactory.CreateDbContextAsync();
        var user = await db.SftpUsers
            .Include(u => u.PublicKeys)
            .FirstOrDefaultAsync(u => u.Username == cleanUsername);

        if (user == null)
        {
            return (false, $"User '{cleanUsername}' not found.", null);
        }

        var defaultComment = $"automation-{cleanUsername}-{DateTime.UtcNow:yyyyMMdd}";
        var comment = string.IsNullOrWhiteSpace(request.Comment) ? defaultComment : request.Comment.Trim();

        var genResult = await _sshKeyGenerator.GenerateKeyPairAsync(request.KeyType, comment, request.Passphrase);
        if (!genResult.Success)
        {
            await _auditService.LogAsync("KEY_GENERATE_FAIL", $"Failed to generate SSH key for '{cleanUsername}': {genResult.ErrorMessage}", false, op);
            return (false, genResult.ErrorMessage ?? "Failed to generate SSH key.", null);
        }

        if (user.PublicKeys.Any(k => string.Equals(k.FingerprintSha256, genResult.FingerprintSha256, StringComparison.OrdinalIgnoreCase)))
        {
            return (false, $"SSH Key with fingerprint '{genResult.FingerprintSha256}' already exists for this user.", null);
        }

        var key = new SshPublicKey
        {
            Username = cleanUsername,
            KeyType = genResult.KeyType,
            FingerprintSha256 = genResult.FingerprintSha256,
            RawPublicKey = genResult.PublicKeyOpenSsh,
            Comment = genResult.Comment,
            AddedAt = DateTime.UtcNow
        };

        user.PublicKeys.Add(key);
        await db.SaveChangesAsync();

        // Refresh user's key file on disk
        var allKeys = user.PublicKeys.Select(k => k.RawPublicKey).ToList();
        _aclProvisioner.WriteUserKeysFile(_sshServiceManager.KeysPath, cleanUsername, allKeys);

        await _auditService.LogAsync("KEY_GENERATE", $"Generated SSH Key ({genResult.KeyType}, {genResult.FingerprintSha256}, Comment: {genResult.Comment}) for user '{cleanUsername}'", true, op);

        return (true, "SSH Key generated successfully.", genResult);
    }
}
