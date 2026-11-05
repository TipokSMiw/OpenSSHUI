namespace OpensshUI.Models;

public enum SftpPermissionType
{
    ReadWrite = 0,
    ReadOnly = 1
}

public enum SftpAccessMode
{
    VirtualFolder = 0, // Appears as junction link inside user's Home/files/ folder
    DirectChroot = 1   // Overrides root to land directly in this folder
}

public class SftpGroup
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string RootPath { get; set; } = string.Empty;
    public SftpPermissionType PermissionType { get; set; } = SftpPermissionType.ReadWrite;
    public SftpAccessMode AccessMode { get; set; } = SftpAccessMode.VirtualFolder;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public List<SftpUserGroup> Members { get; set; } = new();
}
