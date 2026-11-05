namespace OpensshUI.Services.OpenSsh;

public interface IWindowsUserManager
{
    bool EnsureSftpUsersGroup(string groupName = "SFTP-Users");
    bool EnsureLocalGroup(string groupName, string? comment = null);
    bool DeleteLocalGroup(string groupName);
    bool AddUserToLocalGroup(string groupName, string username);
    bool RemoveUserFromLocalGroup(string groupName, string username);
    List<string> GetGroupMembers(string groupName);
    bool CreateOrUpdateLocalUser(string username, string password, bool isActive = true);
    bool DeleteLocalUser(string username);
}
