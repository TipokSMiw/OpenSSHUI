namespace OpensshUI.Models;

public enum SftpAccountType
{
    LocalWindows = 0,
    ActiveDirectory = 1
}

public class SftpUser
{
    public string Username { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public SftpAccountType AccountType { get; set; } = SftpAccountType.LocalWindows;
    public bool IsActive { get; set; } = true;
    public string HomeDirectory { get; set; } = string.Empty;
    
    // Per-User Custom Path & Permissions
    public string? CustomRootPath { get; set; }
    public SftpPermissionType CustomPermissionType { get; set; } = SftpPermissionType.ReadWrite;
    public SftpAccessMode AccessMode { get; set; } = SftpAccessMode.VirtualFolder;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }
    public string? Notes { get; set; }

    public List<SshPublicKey> PublicKeys { get; set; } = new();
    public List<SftpUserGroup> UserGroups { get; set; } = new();
}
