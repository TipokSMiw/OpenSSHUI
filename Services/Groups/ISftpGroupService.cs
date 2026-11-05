using OpensshUI.Models;

namespace OpensshUI.Services.Groups;

public class CreateGroupRequest
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string RootPath { get; set; } = string.Empty;
    public SftpPermissionType PermissionType { get; set; } = SftpPermissionType.ReadWrite;
    public SftpAccessMode AccessMode { get; set; } = SftpAccessMode.VirtualFolder;
    public List<string> InitialMembers { get; set; } = new();
}

public class UpdateGroupRequest
{
    public string Id { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string RootPath { get; set; } = string.Empty;
    public SftpPermissionType PermissionType { get; set; } = SftpPermissionType.ReadWrite;
    public SftpAccessMode AccessMode { get; set; } = SftpAccessMode.VirtualFolder;
    public List<string> Members { get; set; } = new();
}

public interface ISftpGroupService
{
    Task<List<SftpGroup>> GetAllGroupsAsync();
    Task<SftpGroup?> GetGroupAsync(string id);
    Task<(bool Success, string Message, SftpGroup? Group)> CreateGroupAsync(CreateGroupRequest request, string op = "admin");
    Task<(bool Success, string Message)> UpdateGroupAsync(UpdateGroupRequest request, string op = "admin");
    Task<(bool Success, string Message)> DeleteGroupAsync(string id, string op = "admin");
    Task<(bool Success, string Message)> AddUserToGroupAsync(string groupId, string username, string op = "admin");
    Task<(bool Success, string Message)> RemoveUserFromGroupAsync(string groupId, string username, string op = "admin");
    Task SyncUserJunctionsAsync(string username);
    Task SyncAllDirectChrootConfigsAsync();
}
