using OpensshUI.Models;

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

public interface INtfsAclService
{
    void ProvisionChrootRoot(string chrootRootPath, string? accountName = null);
    void ProvisionSubdirectory(string subDirPath, string accountName, SftpPermissionType permission);
    void ProvisionUserChroot(string baseRootPath, string username);
    void ProvisionPathAcl(string folderPath, string accountName, SftpPermissionType permission, bool isDirectChroot = false);
    void RemovePathAcl(string folderPath, string accountName);
    bool CreateDirectoryJunction(string linkPath, string targetPath);
    bool RemoveDirectoryJunction(string linkPath);
    bool ValidatePathSafety(string basePath, string relativeOrSubPath);
    List<DriveFolderItem> ListAvailableDrives();
    List<DriveFolderItem> ListDirectories(string parentPath);
    bool DirectoryExists(string path);
    bool CreateDirectory(string fullPath);
    string? GetParentDirectory(string path);
    List<BreadcrumbItem> GetDirectoryBreadcrumbs(string path);
    void EnsureKeysDirectory(string keysPath);
    void WriteUserKeysFile(string keysPath, string username, IEnumerable<string> openSshPublicKeys);
}
