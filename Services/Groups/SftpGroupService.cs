using System.Runtime.Versioning;
using Microsoft.EntityFrameworkCore;
using OpensshUI.Data;
using OpensshUI.Models;
using OpensshUI.Services.Audit;
using OpensshUI.Services.OpenSsh;
using OpensshUI.Services.Security;

namespace OpensshUI.Services.Groups;

[SupportedOSPlatform("windows")]
public class SftpGroupService : ISftpGroupService
{
    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly IWindowsUserManager _windowsUserManager;
    private readonly INativeAclProvisioner _aclProvisioner;
    private readonly IOpenSshServiceManager _sshServiceManager;
    private readonly IAuditService _auditService;
    private readonly ILogger<SftpGroupService> _logger;

    public SftpGroupService(
        IDbContextFactory<AppDbContext> dbFactory,
        IWindowsUserManager windowsUserManager,
        INativeAclProvisioner aclProvisioner,
        IOpenSshServiceManager sshServiceManager,
        IAuditService auditService,
        ILogger<SftpGroupService> logger)
    {
        _dbFactory = dbFactory;
        _windowsUserManager = windowsUserManager;
        _aclProvisioner = aclProvisioner;
        _sshServiceManager = sshServiceManager;
        _auditService = auditService;
        _logger = logger;
    }

    public async Task<List<SftpGroup>> GetAllGroupsAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        return await db.SftpGroups
            .AsNoTracking()
            .Include(g => g.Members)
            .OrderBy(g => g.Name)
            .ToListAsync();
    }

    public async Task<SftpGroup?> GetGroupAsync(string id)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        return await db.SftpGroups
            .AsNoTracking()
            .Include(g => g.Members)
            .FirstOrDefaultAsync(g => g.Id == id);
    }

    public async Task<(bool Success, string Message, SftpGroup? Group)> CreateGroupAsync(CreateGroupRequest request, string op = "admin")
    {
        var (okGrp, grpErr) = SecurityValidator.ValidateGroupName(request.Name);
        if (!okGrp)
        {
            return (false, grpErr!, null);
        }

        var (okPath, pathErr) = SecurityValidator.ValidateSafeCustomPath(request.RootPath, _sshServiceManager.SftpRoot);
        if (!okPath)
        {
            return (false, pathErr!, null);
        }

        var cleanName = request.Name.Trim();
        var cleanPath = Path.GetFullPath(request.RootPath.Trim());

        await using var db = await _dbFactory.CreateDbContextAsync();
        if (await db.SftpGroups.AnyAsync(g => g.Name == cleanName))
        {
            return (false, $"Group '{cleanName}' already exists.", null);
        }

        try
        {
            // 1. Create or ensure OS Local Group
            var osGroupName = WindowsUserManager.ToOsGroupName(cleanName);
            _windowsUserManager.EnsureLocalGroup(osGroupName, $"OpensshUI SFTP Group: {cleanName}");

            // 2. Ensure target folder exists and provision NTFS ACLs
            if (!Directory.Exists(cleanPath))
            {
                Directory.CreateDirectory(cleanPath);
            }
            _aclProvisioner.ProvisionPathAcl(
                cleanPath, 
                osGroupName, 
                request.PermissionType, 
                isDirectChroot: request.AccessMode == SftpAccessMode.DirectChroot);

            // 3. Database record
            var group = new SftpGroup
            {
                Name = cleanName,
                Description = request.Description?.Trim(),
                RootPath = cleanPath,
                PermissionType = request.PermissionType,
                AccessMode = request.AccessMode,
                CreatedAt = DateTime.UtcNow
            };

            var distinctInitial = request.InitialMembers.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (distinctInitial.Count > 0)
            {
                var existingUsernames = (await db.SftpUsers
                    .Where(u => distinctInitial.Contains(u.Username))
                    .Select(u => u.Username)
                    .ToListAsync())
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                foreach (var username in distinctInitial)
                {
                    if (existingUsernames.Contains(username))
                    {
                        group.Members.Add(new SftpUserGroup
                        {
                            Username = username,
                            GroupId = group.Id,
                            JoinedAt = DateTime.UtcNow
                        });

                        // Add to OS Local Group
                        _windowsUserManager.AddUserToLocalGroup(osGroupName, username);
                    }
                }
            }

            db.SftpGroups.Add(group);
            await db.SaveChangesAsync();

            // 4. Create Directory Junctions for members if VirtualFolder mode
            if (group.AccessMode == SftpAccessMode.VirtualFolder)
            {
                foreach (var member in group.Members)
                {
                    await SyncUserJunctionsAsync(member.Username);
                }
            }
            else
            {
                // DirectChroot: update sshd_config and restart sshd
                await SyncAllDirectChrootConfigsAsync();
            }

            await _auditService.LogAsync("GROUP_CREATE", $"Created SFTP group '{cleanName}' ({group.AccessMode}, {group.PermissionType}) path: {cleanPath}", true, op);
            return (true, $"Group '{cleanName}' created successfully.", group);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create group {Group}", cleanName);
            await _auditService.LogAsync("GROUP_CREATE_ERROR", $"Failed to create group '{cleanName}': {ex.Message}", false, op);
            return (false, $"Error creating group: {ex.Message}", null);
        }
    }

    public async Task<(bool Success, string Message)> UpdateGroupAsync(UpdateGroupRequest request, string op = "admin")
    {
        var (okPath, pathErr) = SecurityValidator.ValidateSafeCustomPath(request.RootPath, _sshServiceManager.SftpRoot);
        if (!okPath)
        {
            return (false, pathErr!);
        }

        await using var db = await _dbFactory.CreateDbContextAsync();
        var group = await db.SftpGroups.Include(g => g.Members).FirstOrDefaultAsync(g => g.Id == request.Id);
        if (group == null) return (false, "Group not found.");

        var oldPath = group.RootPath;
        var cleanPath = Path.GetFullPath(request.RootPath.Trim());
        bool pathChanged = !string.Equals(oldPath, cleanPath, StringComparison.OrdinalIgnoreCase);
        bool permChanged = group.PermissionType != request.PermissionType;
        bool modeChanged = group.AccessMode != request.AccessMode;

        var osGroupName = WindowsUserManager.ToOsGroupName(group.Name);

        try
        {
            // Update metadata
            group.Description = request.Description?.Trim();
            group.RootPath = cleanPath;
            group.PermissionType = request.PermissionType;
            group.AccessMode = request.AccessMode;

            // Remove ACL from old path if path changed
            if (pathChanged && !string.IsNullOrWhiteSpace(oldPath))
            {
                _aclProvisioner.RemovePathAcl(oldPath, osGroupName);
            }

            // Re-apply NTFS ACLs if path or permission changed
            if (pathChanged || permChanged || modeChanged)
            {
                if (!Directory.Exists(cleanPath))
                {
                    Directory.CreateDirectory(cleanPath);
                }
                _aclProvisioner.ProvisionPathAcl(
                    cleanPath, 
                    osGroupName, 
                    group.PermissionType, 
                    isDirectChroot: group.AccessMode == SftpAccessMode.DirectChroot);
            }

            // Sync members
            var requestedMembers = request.Members.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var currentMemberNames = group.Members.Select(m => m.Username).ToList();

            // Members to remove
            var toRemove = group.Members.Where(m => !requestedMembers.Contains(m.Username, StringComparer.OrdinalIgnoreCase)).ToList();
            foreach (var rem in toRemove)
            {
                group.Members.Remove(rem);
                _windowsUserManager.RemoveUserFromLocalGroup(osGroupName, rem.Username);
            }

            // Members to add (single batch query instead of N+1)
            var toAdd = requestedMembers.Where(m => !currentMemberNames.Contains(m, StringComparer.OrdinalIgnoreCase)).ToList();
            if (toAdd.Count > 0)
            {
                var existingToAdd = (await db.SftpUsers
                    .Where(u => toAdd.Contains(u.Username))
                    .Select(u => u.Username)
                    .ToListAsync())
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                foreach (var username in toAdd)
                {
                    if (existingToAdd.Contains(username))
                    {
                        group.Members.Add(new SftpUserGroup
                        {
                            Username = username,
                            GroupId = group.Id,
                            JoinedAt = DateTime.UtcNow
                        });
                        _windowsUserManager.AddUserToLocalGroup(osGroupName, username);
                    }
                }
            }

            await db.SaveChangesAsync();

            // Refresh junctions for all affected members
            var allAffectedMembers = currentMemberNames.Union(requestedMembers);
            foreach (var username in allAffectedMembers)
            {
                await SyncUserJunctionsAsync(username);
            }

            // If DirectChroot or mode changed, sync sshd_config
            if (modeChanged || group.AccessMode == SftpAccessMode.DirectChroot)
            {
                await SyncAllDirectChrootConfigsAsync();
            }

            await _auditService.LogAsync("GROUP_UPDATE", $"Updated SFTP group '{group.Name}'", true, op);
            return (true, $"Group '{group.Name}' updated successfully.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update group {Group}", group.Name);
            return (false, $"Error updating group: {ex.Message}");
        }
    }

    public async Task<(bool Success, string Message)> DeleteGroupAsync(string id, string op = "admin")
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var group = await db.SftpGroups.Include(g => g.Members).FirstOrDefaultAsync(g => g.Id == id);
        if (group == null) return (false, "Group not found.");

        var groupName = group.Name;
        var osGroupName = WindowsUserManager.ToOsGroupName(groupName);
        var memberUsernames = group.Members.Select(m => m.Username).ToList();
        bool wasDirectChroot = group.AccessMode == SftpAccessMode.DirectChroot;

        try
        {
            // 1. Remove junction links inside each member's home directory (files & folders remain safe!)
            foreach (var username in memberUsernames)
            {
                var userJunction = Path.Combine(_sshServiceManager.SftpRoot, username, "files", groupName);
                _aclProvisioner.RemoveDirectoryJunction(userJunction);
            }

            // 2. Remove ACL on shared folder and delete OS Local Group
            if (!string.IsNullOrWhiteSpace(group.RootPath))
            {
                _aclProvisioner.RemovePathAcl(group.RootPath, osGroupName);
            }
            _windowsUserManager.DeleteLocalGroup(osGroupName);

            // 3. Remove from Database
            db.SftpGroups.Remove(group);
            await db.SaveChangesAsync();

            // 4. Update sshd_config if it was DirectChroot
            if (wasDirectChroot)
            {
                await SyncAllDirectChrootConfigsAsync();
            }

            await _auditService.LogAsync("GROUP_DELETE", $"Deleted SFTP group '{groupName}' (data files preserved at {group.RootPath})", true, op);
            return (true, $"Group '{groupName}' deleted successfully.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete group {Group}", groupName);
            return (false, $"Error deleting group: {ex.Message}");
        }
    }

    public async Task<(bool Success, string Message)> AddUserToGroupAsync(string groupId, string username, string op = "admin")
    {
        var (okUser, userErr) = SecurityValidator.ValidateUsername(username);
        if (!okUser) return (false, userErr!);

        await using var db = await _dbFactory.CreateDbContextAsync();
        var group = await db.SftpGroups.Include(g => g.Members).FirstOrDefaultAsync(g => g.Id == groupId);
        if (group == null) return (false, "Group not found.");

        var user = await db.SftpUsers.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null) return (false, "User not found.");

        if (group.Members.Any(m => m.Username == username))
            return (true, $"User '{username}' is already in group '{group.Name}'.");

        try
        {
            var osGroupName = WindowsUserManager.ToOsGroupName(group.Name);
            _windowsUserManager.AddUserToLocalGroup(osGroupName, username);

            group.Members.Add(new SftpUserGroup
            {
                Username = username,
                GroupId = group.Id,
                JoinedAt = DateTime.UtcNow
            });
            await db.SaveChangesAsync();

            if (group.AccessMode == SftpAccessMode.VirtualFolder)
            {
                await SyncUserJunctionsAsync(username);
            }

            await _auditService.LogAsync("GROUP_ADD_MEMBER", $"Added user '{username}' to group '{group.Name}'", true, op);
            return (true, $"Added '{username}' to group '{group.Name}'.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to add member {User} to group {Group}", username, group.Name);
            return (false, ex.Message);
        }
    }

    public async Task<(bool Success, string Message)> RemoveUserFromGroupAsync(string groupId, string username, string op = "admin")
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var group = await db.SftpGroups.Include(g => g.Members).FirstOrDefaultAsync(g => g.Id == groupId);
        if (group == null) return (false, "Group not found.");

        var member = group.Members.FirstOrDefault(m => m.Username == username);
        if (member == null) return (true, "User is not in this group.");

        try
        {
            var osGroupName = WindowsUserManager.ToOsGroupName(group.Name);
            _windowsUserManager.RemoveUserFromLocalGroup(osGroupName, username);

            group.Members.Remove(member);
            await db.SaveChangesAsync();

            // Remove junction in user directory
            var junctionPath = Path.Combine(_sshServiceManager.SftpRoot, username, "files", group.Name);
            _aclProvisioner.RemoveDirectoryJunction(junctionPath);

            await _auditService.LogAsync("GROUP_REMOVE_MEMBER", $"Removed user '{username}' from group '{group.Name}'", true, op);
            return (true, $"Removed '{username}' from group '{group.Name}'.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to remove member {User} from group {Group}", username, group.Name);
            return (false, ex.Message);
        }
    }

    public async Task SyncUserJunctionsAsync(string username)
    {
        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync();
            var user = await db.SftpUsers
                .Include(u => u.UserGroups)
                .ThenInclude(ug => ug.Group)
                .FirstOrDefaultAsync(u => u.Username == username);

            if (user == null) return;

            var userFilesDir = Path.Combine(_sshServiceManager.SftpRoot, username, "files");
            if (!Directory.Exists(userFilesDir))
            {
                Directory.CreateDirectory(userFilesDir);
            }

            // Active virtual folder groups for this user
            var activeVirtualGroups = user.UserGroups
                .Where(ug => ug.Group != null && ug.Group.AccessMode == SftpAccessMode.VirtualFolder)
                .Select(ug => ug.Group!)
                .ToList();

            var activeJunctionNames = activeVirtualGroups.Select(g => g.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);

            // 1. Create or verify junctions for active groups
            foreach (var grp in activeVirtualGroups)
            {
                var linkPath = Path.Combine(userFilesDir, grp.Name);
                _aclProvisioner.CreateDirectoryJunction(linkPath, grp.RootPath);
            }

            // 2. Create or verify junction for user's own CustomRootPath when in VirtualFolder mode
            if (user.AccessMode == SftpAccessMode.VirtualFolder && !string.IsNullOrWhiteSpace(user.CustomRootPath))
            {
                var customFolderName = Path.GetFileName(user.CustomRootPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                if (string.IsNullOrWhiteSpace(customFolderName))
                {
                    customFolderName = "CustomRoot";
                }
                else if (activeJunctionNames.Contains(customFolderName))
                {
                    customFolderName = $"Custom_{customFolderName}";
                }

                activeJunctionNames.Add(customFolderName);
                var customLinkPath = Path.Combine(userFilesDir, customFolderName);
                _aclProvisioner.CreateDirectoryJunction(customLinkPath, user.CustomRootPath);
            }

            // 3. Remove any existing junctions in user's folder that are no longer part of active groups or custom root
            var dirInfo = new DirectoryInfo(userFilesDir);
            foreach (var sub in dirInfo.EnumerateDirectories())
            {
                if (sub.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    if (!activeJunctionNames.Contains(sub.Name))
                    {
                        _aclProvisioner.RemoveDirectoryJunction(sub.FullName);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error syncing junctions for user {User}", username);
        }
    }

    public async Task SyncAllDirectChrootConfigsAsync()
    {
        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync();
            var rules = new List<DirectChrootRule>();

            // DirectChroot Users
            var directUsers = await db.SftpUsers
                .Where(u => u.AccessMode == SftpAccessMode.DirectChroot && !string.IsNullOrWhiteSpace(u.CustomRootPath))
                .ToListAsync();

            foreach (var u in directUsers)
            {
                rules.Add(new DirectChrootRule
                {
                    IsGroup = false,
                    Identifier = u.Username,
                    RootPath = u.CustomRootPath!
                });
            }

            // DirectChroot Groups
            var directGroups = await db.SftpGroups
                .Where(g => g.AccessMode == SftpAccessMode.DirectChroot && !string.IsNullOrWhiteSpace(g.RootPath))
                .ToListAsync();

            foreach (var g in directGroups)
            {
                rules.Add(new DirectChrootRule
                {
                    IsGroup = true,
                    Identifier = WindowsUserManager.ToOsGroupName(g.Name),
                    RootPath = g.RootPath
                });
            }

            await _sshServiceManager.SyncManagedConfigAsync(rules, autoRestart: true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error syncing DirectChroot sshd_config rules");
        }
    }
}
