using OpensshUI.Models;

namespace OpensshUI.Services.OpenSsh;

public interface INativeAclProvisioner
{
    void ProvisionUserChroot(string baseRootPath, string username);
    void ProvisionPathAcl(string folderPath, string accountName, SftpPermissionType permission, bool isDirectChroot = false);
    void RemovePathAcl(string folderPath, string accountName);
    bool CreateDirectoryJunction(string linkPath, string targetPath);
    bool RemoveDirectoryJunction(string linkPath);
    List<DriveFolderItem> ListAvailableDrives();
    List<DriveFolderItem> ListDirectories(string parentPath);
    bool DirectoryExists(string path);
    bool CreateDirectory(string fullPath);
    string? GetParentDirectory(string path);
    List<BreadcrumbItem> GetDirectoryBreadcrumbs(string path);
    void EnsureKeysDirectory(string keysPath);
    void WriteUserKeysFile(string keysPath, string username, IEnumerable<string> openSshPublicKeys);
}
