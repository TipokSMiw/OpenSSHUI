namespace OpensshUI.Services.Files;

public class FileItemInfo
{
    public string Name { get; set; } = string.Empty;
    public string RelativePath { get; set; } = string.Empty;
    public bool IsDirectory { get; set; }
    public long SizeBytes { get; set; }
    public DateTime LastModified { get; set; }
    public string Extension { get; set; } = string.Empty;
}

public interface ISecureFileBrowserService
{
    // User File Operations
    Task<List<FileItemInfo>> ListItemsAsync(string username, string subPath = "");
    Task<Stream> OpenReadStreamAsync(string username, string subPath);
    Task UploadFileAsync(string username, string subPath, string fileName, Stream sourceStream, long maxSizeBytes = 500 * 1024 * 1024);
    Task DeleteItemAsync(string username, string subPath);
    Task CreateDirectoryAsync(string username, string subPath, string directoryName);
    long GetTotalUserStorageBytes(string username);
    Task<long> GetTotalUserStorageBytesAsync(string username, CancellationToken cancellationToken = default);
    Task<string?> ResolveUserPhysicalPathAsync(string username);

    // Group File Operations
    Task<List<FileItemInfo>> ListGroupItemsAsync(string groupName, string subPath = "");
    Task<Stream> OpenGroupReadStreamAsync(string groupName, string subPath);
    Task UploadGroupFileAsync(string groupName, string subPath, string fileName, Stream sourceStream, long maxSizeBytes = 500 * 1024 * 1024);
    Task DeleteGroupItemAsync(string groupName, string subPath);
    Task CreateGroupDirectoryAsync(string groupName, string subPath, string directoryName);
    long GetTotalGroupStorageBytes(string groupName);
    Task<long> GetTotalGroupStorageBytesAsync(string groupName, CancellationToken cancellationToken = default);
    Task<string?> ResolveGroupPhysicalPathAsync(string groupName);
}
